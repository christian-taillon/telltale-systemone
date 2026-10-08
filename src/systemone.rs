//! TypeSafe System One wire format (`POST /v1/systemone`) and strict answer
//! validation. See <https://docs.typesafe.ai/api.md>.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct Request {
    pub state: Value,
    pub model: String,
    pub questions: BTreeMap<String, Value>,
}

/// What the analyzer expects back for one question key.
#[derive(Debug, Clone, PartialEq)]
pub enum Expect {
    Noul,
    Choice(Vec<String>),
    /// Number of levels.
    Score(usize),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    Noul(f64),
    Choice {
        choice: String,
        probabilities: BTreeMap<String, f64>,
        confidence: f64,
    },
    Score {
        score: f64,
        probabilities: BTreeMap<String, f64>,
        confidence: f64,
    },
}

#[derive(Debug, Clone, Default)]
pub struct Response {
    pub model: String,
    pub answers: BTreeMap<String, Value>,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Closed reasons an answer could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerError {
    Missing,
    WrongType,
    Invalid,
}

impl AnswerError {
    pub fn code(self) -> &'static str {
        match self {
            AnswerError::Missing => "provider_missing_answer",
            AnswerError::WrongType => "provider_wrong_answer_type",
            AnswerError::Invalid => "provider_invalid_answer",
        }
    }
}

/// Parse the top-level response envelope. Returns `None` when it is unusable.
pub fn parse_response(payload: &Value) -> Option<Response> {
    let object = payload.as_object()?;
    let model = object.get("model")?.as_str()?.to_owned();
    if model.is_empty() || model.len() > 96 {
        return None;
    }
    let answers = object
        .get("answers")?
        .as_object()?
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let usage = object.get("usage").and_then(Value::as_object);
    let count = |key: &str| {
        usage
            .and_then(|u| u.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    Some(Response {
        model,
        answers,
        input_tokens: count("input_tokens"),
        output_tokens: count("output_tokens"),
    })
}

const SUM_TOLERANCE: f64 = 0.02;

pub fn parse_answer(
    response: &Response,
    key: &str,
    expect: &Expect,
) -> Result<Answer, AnswerError> {
    let answer = response.answers.get(key).ok_or(AnswerError::Missing)?;
    let object = answer.as_object().ok_or(AnswerError::Invalid)?;
    let kind = object.get("type").and_then(Value::as_str);
    match expect {
        Expect::Noul => {
            if kind != Some("noul") {
                return Err(AnswerError::WrongType);
            }
            let p = unit(object.get("noul"))?;
            Ok(Answer::Noul(p))
        }
        Expect::Choice(options) => {
            if kind != Some("choice") {
                return Err(AnswerError::WrongType);
            }
            let probabilities = distribution(object.get("probabilities"), options)?;
            let choice = object
                .get("choice")
                .and_then(Value::as_str)
                .ok_or(AnswerError::Invalid)?
                .to_owned();
            let top = probabilities.values().cloned().fold(0.0, f64::max);
            match probabilities.get(&choice) {
                // The reported choice must be a highest-probability option.
                Some(p) if (top - p).abs() <= 1e-9 => {}
                _ => return Err(AnswerError::Invalid),
            }
            let confidence = unit(object.get("confidence"))?;
            Ok(Answer::Choice {
                choice,
                probabilities,
                confidence,
            })
        }
        Expect::Score(levels) => {
            if kind != Some("score") {
                return Err(AnswerError::WrongType);
            }
            let keys: Vec<String> = (0..*levels).map(|i| i.to_string()).collect();
            let probabilities = distribution(object.get("probabilities"), &keys)?;
            let score = object
                .get("score")
                .and_then(Value::as_f64)
                .filter(|s| s.is_finite() && *s >= 0.0 && *s <= (*levels as f64 - 1.0) + 1e-9)
                .ok_or(AnswerError::Invalid)?;
            let confidence = unit(object.get("confidence"))?;
            Ok(Answer::Score {
                score,
                probabilities,
                confidence,
            })
        }
    }
}

fn unit(value: Option<&Value>) -> Result<f64, AnswerError> {
    value
        .and_then(Value::as_f64)
        .filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
        .ok_or(AnswerError::Invalid)
}

/// Every expected key present, no extras, each in [0, 1], summing to ~1.
fn distribution(
    value: Option<&Value>,
    keys: &[String],
) -> Result<BTreeMap<String, f64>, AnswerError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or(AnswerError::Invalid)?;
    if object.len() != keys.len() {
        return Err(AnswerError::Invalid);
    }
    let mut out = BTreeMap::new();
    for key in keys {
        out.insert(key.clone(), unit(object.get(key))?);
    }
    let sum: f64 = out.values().sum();
    if (sum - 1.0).abs() > SUM_TOLERANCE {
        return Err(AnswerError::Invalid);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn response(answers: Value) -> Response {
        parse_response(&json!({"model": "jev-1.13.0", "answers": answers})).unwrap()
    }

    #[test]
    fn parses_documented_answer_shapes() {
        let r = response(json!({
            "n": {"type": "noul", "noul": 0.95},
            "c": {"type": "choice", "choice": "a", "probabilities": {"a": 0.88, "b": 0.12}, "confidence": 0.76},
            "s": {"type": "score", "score": 1.05, "legend": {"0": "x", "1": "y", "2": "z"},
                  "probabilities": {"0": 0.0, "1": 0.95, "2": 0.05}, "confidence": 0.92}
        }));
        assert_eq!(parse_answer(&r, "n", &Expect::Noul), Ok(Answer::Noul(0.95)));
        let options = vec!["a".to_string(), "b".to_string()];
        assert!(matches!(
            parse_answer(&r, "c", &Expect::Choice(options)),
            Ok(Answer::Choice { .. })
        ));
        assert!(matches!(
            parse_answer(&r, "s", &Expect::Score(3)),
            Ok(Answer::Score { .. })
        ));
    }

    #[test]
    fn rejects_malformed_answers() {
        let options = vec!["a".to_string(), "b".to_string()];
        let r = response(json!({
            "missing_option": {"type": "choice", "choice": "a", "probabilities": {"a": 1.0}, "confidence": 1.0},
            "not_argmax": {"type": "choice", "choice": "b", "probabilities": {"a": 0.9, "b": 0.1}, "confidence": 0.8},
            "bad_sum": {"type": "choice", "choice": "a", "probabilities": {"a": 0.9, "b": 0.9}, "confidence": 0.8},
            "out_of_range": {"type": "noul", "noul": 1.5},
            "wrong": {"type": "noul", "noul": 0.5}
        }));
        let choice = Expect::Choice(options);
        assert_eq!(
            parse_answer(&r, "missing_option", &choice),
            Err(AnswerError::Invalid)
        );
        assert_eq!(
            parse_answer(&r, "not_argmax", &choice),
            Err(AnswerError::Invalid)
        );
        assert_eq!(
            parse_answer(&r, "bad_sum", &choice),
            Err(AnswerError::Invalid)
        );
        assert_eq!(
            parse_answer(&r, "out_of_range", &Expect::Noul),
            Err(AnswerError::Invalid)
        );
        assert_eq!(
            parse_answer(&r, "wrong", &choice),
            Err(AnswerError::WrongType)
        );
        assert_eq!(
            parse_answer(&r, "absent", &Expect::Noul),
            Err(AnswerError::Missing)
        );
    }
}
