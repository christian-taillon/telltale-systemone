//! Deterministic decisions: model answers in, Telltale status and metadata
//! out. The model supplies probabilities; the pack supplies every threshold,
//! severity, and risk value.

use crate::pack::{Check, ChoiceOutcome, Question, UncertainPolicy};
use crate::protocol::{Assessment, Confidence, NonEvaluationReason, OrderCheck, Severity};
use crate::systemone::Answer;

pub const HIGH_CONFIDENCE: f64 = 0.8;
pub const MEDIUM_CONFIDENCE: f64 = 0.5;

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Match { severity: Severity, risk_points: u8 },
    Review,
    NoMatch,
    NotEvaluated(NonEvaluationReason),
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub outcome: Outcome,
    pub confidence_score: f64,
    /// `classification:` evidence token.
    pub evidence: String,
    pub assessment: Assessment,
}

/// Why an answer could not be decided; becomes `detector_error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecideError(pub &'static str);

pub fn confidence_label(score: f64) -> Confidence {
    if score >= HIGH_CONFIDENCE {
        Confidence::High
    } else if score >= MEDIUM_CONFIDENCE {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

pub fn decide(
    check: &Check,
    primary: &Answer,
    reordered: Option<&Answer>,
) -> Result<Decision, DecideError> {
    let uncertain = |primitive: &str| match check.uncertain {
        UncertainPolicy::Review => (
            Outcome::Review,
            format!("classification:{primitive}.uncertain"),
        ),
        UncertainPolicy::NoMatch => (
            Outcome::NoMatch,
            format!("classification:{primitive}.uncertain"),
        ),
    };

    match (&check.question, primary) {
        (
            Question::Predicate {
                match_at,
                clear_below,
                severity,
                risk_points,
                ..
            },
            Answer::Noul(p),
        ) => {
            let p = *p;
            let (outcome, evidence) = if p >= *match_at {
                (
                    Outcome::Match {
                        severity: *severity,
                        risk_points: *risk_points,
                    },
                    "classification:predicate.yes".to_string(),
                )
            } else if p < *clear_below {
                (Outcome::NoMatch, "classification:predicate.no".to_string())
            } else {
                uncertain("predicate")
            };
            Ok(Decision {
                outcome,
                // TypeSafe's suggested Noul confidence: |2p - 1|.
                confidence_score: (2.0 * p - 1.0).abs(),
                evidence,
                assessment: Assessment::Predicate { probability: p },
            })
        }
        (
            Question::Choice {
                options,
                min_confidence,
                order_check,
                ..
            },
            Answer::Choice {
                choice,
                probabilities,
                confidence,
            },
        ) => {
            let order = match (order_check, reordered) {
                (false, _) => None,
                (true, Some(Answer::Choice { choice: second, .. })) => Some(if second == choice {
                    OrderCheck::Consistent
                } else {
                    OrderCheck::Inconsistent
                }),
                (true, _) => return Err(DecideError("order_check_answer_missing")),
            };
            let option = options
                .iter()
                .find(|o| &o.name == choice)
                .ok_or(DecideError("provider_invalid_answer"))?;
            let (outcome, evidence) =
                if order == Some(OrderCheck::Inconsistent) || *confidence < *min_confidence {
                    uncertain("choice")
                } else {
                    let evidence = format!("classification:choice.{}", option.name);
                    let outcome = match option.outcome {
                        ChoiceOutcome::Match => Outcome::Match {
                            severity: option.severity.expect("validated"),
                            risk_points: option.risk_points.expect("validated"),
                        },
                        ChoiceOutcome::NoMatch => Outcome::NoMatch,
                        ChoiceOutcome::Review => Outcome::Review,
                        ChoiceOutcome::InsufficientVisibility => {
                            Outcome::NotEvaluated(NonEvaluationReason::InsufficientVisibility)
                        }
                    };
                    (outcome, evidence)
                };
            Ok(Decision {
                outcome,
                confidence_score: *confidence,
                evidence,
                assessment: Assessment::Choice {
                    choice: choice.clone(),
                    probabilities: probabilities.clone(),
                    confidence: *confidence,
                    order_check: order,
                },
            })
        }
        (
            Question::Score {
                match_at,
                clear_below,
                min_confidence,
                bands,
                ..
            },
            Answer::Score {
                score,
                probabilities,
                confidence,
            },
        ) => {
            // Jev's expected score is only reliable against thresholds.
            let (outcome, evidence) = if *confidence < *min_confidence {
                uncertain("score")
            } else if *score >= *match_at {
                let band = bands
                    .iter()
                    .rev()
                    .find(|b| *score >= b.at)
                    .expect("first band equals match_at");
                (
                    Outcome::Match {
                        severity: band.severity,
                        risk_points: band.risk_points,
                    },
                    "classification:score.match".to_string(),
                )
            } else if *score < *clear_below {
                (Outcome::NoMatch, "classification:score.clear".to_string())
            } else {
                uncertain("score")
            };
            Ok(Decision {
                outcome,
                confidence_score: *confidence,
                evidence,
                assessment: Assessment::Score {
                    score: *score,
                    probabilities: probabilities.clone(),
                    confidence: *confidence,
                },
            })
        }
        _ => Err(DecideError("provider_wrong_answer_type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn check(question_yaml: &str, uncertain: &str) -> Check {
        let yaml = format!(
            "id: systemone.test.check\ntitle: t\nfinding_kind: security_detection\ncategory: execution\n\
             applies_to: {{families: [tool]}}\nstate: action\nuncertain: {uncertain}\nquestion:\n{question_yaml}"
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    fn predicate(uncertain: &str) -> Check {
        check(
            "  type: predicate\n  instructions: q\n  match_at: 0.8\n  clear_below: 0.3\n  severity: medium\n  risk_points: 30\n",
            uncertain,
        )
    }

    #[test]
    fn predicate_thresholds_are_inclusive_at_match_and_exclusive_at_clear() {
        let c = predicate("review");
        let at = |p| decide(&c, &Answer::Noul(p), None).unwrap().outcome;
        assert_eq!(
            at(0.8),
            Outcome::Match {
                severity: Severity::Medium,
                risk_points: 30
            }
        );
        assert_eq!(at(0.79), Outcome::Review);
        assert_eq!(at(0.3), Outcome::Review);
        assert_eq!(at(0.29), Outcome::NoMatch);
        let quiet = predicate("no_match");
        assert_eq!(
            decide(&quiet, &Answer::Noul(0.5), None).unwrap().outcome,
            Outcome::NoMatch
        );
    }

    #[test]
    fn predicate_confidence_is_distance_from_even() {
        let c = predicate("review");
        let d = decide(&c, &Answer::Noul(0.95), None).unwrap();
        assert!((d.confidence_score - 0.9).abs() < 1e-9);
        assert_eq!(confidence_label(d.confidence_score), Confidence::High);
        assert_eq!(confidence_label(0.5), Confidence::Medium);
        assert_eq!(confidence_label(0.49), Confidence::Low);
    }

    fn choice_check() -> Check {
        check(
            "  type: choice\n  instructions: q\n  min_confidence: 0.4\n  order_check: true\n  options:\n\
             \x20   - {name: benign, description: d, outcome: no_match}\n\
             \x20   - {name: bad, description: d, outcome: match, severity: high, risk_points: 50}\n\
             \x20   - {name: unknown, description: d, outcome: insufficient_visibility}\n",
            "review",
        )
    }

    fn choice(name: &str, confidence: f64) -> Answer {
        let mut probabilities = BTreeMap::new();
        for option in ["benign", "bad", "unknown"] {
            probabilities.insert(option.to_string(), if option == name { 0.9 } else { 0.05 });
        }
        Answer::Choice {
            choice: name.into(),
            probabilities,
            confidence,
        }
    }

    #[test]
    fn choice_maps_options_and_treats_order_disagreement_as_uncertain() {
        let c = choice_check();
        let d = decide(&c, &choice("bad", 0.85), Some(&choice("bad", 0.8))).unwrap();
        assert_eq!(
            d.outcome,
            Outcome::Match {
                severity: Severity::High,
                risk_points: 50
            }
        );
        assert_eq!(d.evidence, "classification:choice.bad");
        let flipped = decide(&c, &choice("bad", 0.85), Some(&choice("benign", 0.8))).unwrap();
        assert_eq!(flipped.outcome, Outcome::Review);
        let low = decide(&c, &choice("bad", 0.2), Some(&choice("bad", 0.2))).unwrap();
        assert_eq!(low.outcome, Outcome::Review);
        let blind = decide(&c, &choice("unknown", 0.9), Some(&choice("unknown", 0.9))).unwrap();
        assert_eq!(
            blind.outcome,
            Outcome::NotEvaluated(NonEvaluationReason::InsufficientVisibility)
        );
        assert_eq!(
            decide(&c, &choice("bad", 0.9), None).unwrap_err().0,
            "order_check_answer_missing"
        );
    }

    #[test]
    fn score_uses_bands_and_confidence_floor() {
        let c = check(
            "  type: score\n  instructions: q\n  levels: [calm, odd, hostile]\n  match_at: 1.0\n  clear_below: 0.5\n\
             \x20 min_confidence: 0.3\n  bands:\n    - {at: 1.0, severity: medium, risk_points: 20}\n\
             \x20   - {at: 1.6, severity: high, risk_points: 40}\n",
            "review",
        );
        let score = |s, confidence| Answer::Score {
            score: s,
            probabilities: BTreeMap::new(),
            confidence,
        };
        let at = |s| decide(&c, &score(s, 0.9), None).unwrap().outcome;
        assert_eq!(
            at(1.7),
            Outcome::Match {
                severity: Severity::High,
                risk_points: 40
            }
        );
        assert_eq!(
            at(1.2),
            Outcome::Match {
                severity: Severity::Medium,
                risk_points: 20
            }
        );
        assert_eq!(at(0.7), Outcome::Review);
        assert_eq!(at(0.2), Outcome::NoMatch);
        assert_eq!(
            decide(&c, &score(1.9, 0.1), None).unwrap().outcome,
            Outcome::Review
        );
    }
}
