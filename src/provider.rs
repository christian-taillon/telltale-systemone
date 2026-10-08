//! System One providers: the TypeSafe HTTP API (or a compatible endpoint) and
//! an offline fixture provider for tests and replayed evaluations.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::systemone::{Request, Response, parse_response};

const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
const BACKOFF_BASE: Duration = Duration::from_millis(250);

/// A closed, content-free failure code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderError(pub &'static str);

pub trait Provider: Send {
    fn evaluate(
        &self,
        request: &Request,
        subject: &str,
        deadline: Instant,
    ) -> Result<Response, ProviderError>;
    /// Destinations that receive request content.
    fn egress(&self) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

pub struct HttpProvider {
    endpoint: String,
    api_key: String,
    timeout: Duration,
    max_attempts: u32,
    agent: ureq::Agent,
}

impl std::fmt::Debug for HttpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpProvider")
            .field("endpoint", &self.endpoint)
            .field("api_key", &"[redacted]")
            .finish()
    }
}

impl HttpProvider {
    pub fn new(
        endpoint: &str,
        api_key: String,
        timeout: Duration,
        max_attempts: u32,
    ) -> Result<Self, &'static str> {
        let loopback = is_loopback_http(endpoint);
        if !endpoint.starts_with("https://") && !loopback {
            return Err("endpoint_requires_https");
        }
        if api_key.trim().is_empty() {
            return Err("credentials_missing");
        }
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .https_only(!loopback)
            .user_agent(concat!("telltale-systemone/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Self {
            endpoint: endpoint.to_owned(),
            api_key,
            timeout,
            max_attempts: max_attempts.clamp(1, 6),
            agent,
        })
    }

    fn attempt(&self, body: &[u8], timeout: Duration) -> Attempt {
        let result = self
            .agent
            .post(&self.endpoint)
            .config()
            .timeout_global(Some(timeout))
            .build()
            .header("Authorization", &format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .send(body);
        let mut response = match result {
            Ok(response) => response,
            Err(ureq::Error::Timeout(_)) => return Attempt::Retry("provider_timeout", None),
            Err(_) => return Attempt::Retry("provider_unavailable", None),
        };
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|s| s.is_finite() && *s >= 0.0)
            .map(Duration::from_secs_f64);
        match status {
            200..=299 => {}
            401 | 403 => return Attempt::Fail("provider_auth"),
            429 | 529 => return Attempt::Retry("provider_overloaded", retry_after),
            502..=504 => return Attempt::Retry("provider_unavailable", retry_after),
            400..=499 => return Attempt::Fail("provider_rejected_request"),
            _ => return Attempt::Fail("provider_unavailable"),
        }
        let mut text = String::new();
        let read = response
            .body_mut()
            .as_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_string(&mut text);
        if read.is_err() || text.len() as u64 > MAX_RESPONSE_BYTES {
            return Attempt::Fail("provider_invalid_response");
        }
        match serde_json::from_str::<Value>(&text)
            .ok()
            .as_ref()
            .and_then(parse_response)
        {
            Some(parsed) => Attempt::Done(parsed),
            None => Attempt::Fail("provider_invalid_response"),
        }
    }
}

enum Attempt {
    Done(Response),
    Retry(&'static str, Option<Duration>),
    Fail(&'static str),
}

impl Provider for HttpProvider {
    fn evaluate(
        &self,
        request: &Request,
        _subject: &str,
        deadline: Instant,
    ) -> Result<Response, ProviderError> {
        let body = serde_json::to_vec(request).map_err(|_| ProviderError("request_encoding"))?;
        let mut last = "provider_unavailable";
        for attempt in 1..=self.max_attempts {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining < Duration::from_millis(50) {
                return Err(ProviderError("deadline_exceeded"));
            }
            match self.attempt(&body, remaining.min(self.timeout)) {
                Attempt::Done(response) => return Ok(response),
                Attempt::Fail(code) => {
                    eprintln!("telltale-systemone: provider {code} attempt={attempt}");
                    return Err(ProviderError(code));
                }
                Attempt::Retry(code, retry_after) => {
                    eprintln!("telltale-systemone: provider {code} attempt={attempt}");
                    last = code;
                    if attempt == self.max_attempts {
                        break;
                    }
                    let wait = retry_after.unwrap_or(BACKOFF_BASE * 2u32.pow(attempt - 1));
                    if Instant::now() + wait >= deadline {
                        return Err(ProviderError("deadline_exceeded"));
                    }
                    std::thread::sleep(wait);
                }
            }
        }
        Err(ProviderError(last))
    }

    fn egress(&self) -> Vec<String> {
        vec![self.endpoint.clone()]
    }
}

fn is_loopback_http(endpoint: &str) -> bool {
    [
        "http://127.0.0.1:",
        "http://127.0.0.1/",
        "http://localhost:",
        "http://localhost/",
        "http://[::1]:",
    ]
    .iter()
    .any(|prefix| endpoint.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// Answers keyed by subject observation ID and question key:
///
/// ```json
/// {"model": "jev-1.13.0", "subjects": {"obs:v2:sha256:…": {"<question key>": {…}}}}
/// ```
#[derive(Debug)]
pub struct FixtureProvider {
    model: String,
    subjects: BTreeMap<String, serde_json::Map<String, Value>>,
}

impl FixtureProvider {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read fixture: {e}"))?;
        let value: Value =
            serde_json::from_str(&text).map_err(|e| format!("invalid fixture JSON: {e}"))?;
        let model = value
            .get("model")
            .and_then(Value::as_str)
            .ok_or("fixture needs a `model` string")?
            .to_owned();
        let subjects = value
            .get("subjects")
            .and_then(Value::as_object)
            .ok_or("fixture needs a `subjects` object")?
            .iter()
            .map(|(k, v)| {
                v.as_object()
                    .cloned()
                    .map(|o| (k.clone(), o))
                    .ok_or("subject entries must be objects")
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { model, subjects })
    }
}

impl Provider for FixtureProvider {
    fn evaluate(
        &self,
        request: &Request,
        subject: &str,
        _deadline: Instant,
    ) -> Result<Response, ProviderError> {
        let answers = self
            .subjects
            .get(subject)
            .ok_or(ProviderError("fixture_miss"))?;
        Ok(Response {
            model: self.model.clone(),
            answers: request
                .questions
                .keys()
                .filter_map(|k| answers.get(k).map(|a| (k.clone(), a.clone())))
                .collect(),
            input_tokens: 0,
            output_tokens: 0,
        })
    }

    fn egress(&self) -> Vec<String> {
        Vec::new()
    }
}
