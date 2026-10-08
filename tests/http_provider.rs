//! The TypeSafe client against a local mock server: retry on 529, no retry
//! on 401, bearer auth, and the documented request shape.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use telltale_systemone::provider::{HttpProvider, Provider};
use telltale_systemone::systemone::Request;

/// Serves the given (status, body) responses in order and reports each
/// request's headers and body.
fn mock(responses: Vec<(u16, String)>) -> (String, mpsc::Receiver<(String, Value)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/v1/systemone",
        listener.local_addr().unwrap().port()
    );
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for (status, body) in responses {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
                headers.push_str(&line);
            }
            let mut buf = vec![0; length];
            reader.read_exact(&mut buf).unwrap();
            tx.send((headers, serde_json::from_slice(&buf).unwrap()))
                .unwrap();
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    (url, rx)
}

fn request() -> Request {
    Request {
        state: json!({"action": {"tool": "Bash", "command": "npm test"}}),
        model: "jev-1.13.0".into(),
        questions: [(
            "q".to_string(),
            json!({"type": "noul", "instructions": "x"}),
        )]
        .into(),
    }
}

const OK: &str = r#"{"model":"jev-1.13.0","answers":{"q":{"type":"noul","noul":0.12}},"usage":{"input_tokens":40,"output_tokens":3}}"#;

#[test]
fn retries_overload_then_succeeds_with_bearer_auth() {
    let (url, rx) = mock(vec![(529, "{}".into()), (200, OK.into())]);
    let provider = HttpProvider::new(&url, "test-key".into(), Duration::from_secs(5), 3).unwrap();
    let response = provider
        .evaluate(
            &request(),
            "subject",
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
    assert_eq!(response.model, "jev-1.13.0");
    assert_eq!(response.input_tokens, 40);
    let (headers, body) = rx.recv().unwrap();
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("authorization: bearer test-key")
    );
    assert_eq!(body["model"], "jev-1.13.0");
    assert_eq!(body["questions"]["q"]["type"], "noul");
    assert!(rx.recv().is_ok(), "second attempt after 529");
}

#[test]
fn auth_failures_and_bad_bodies_are_not_retried() {
    let (url, rx) = mock(vec![(401, "{}".into())]);
    let provider = HttpProvider::new(&url, "k".into(), Duration::from_secs(5), 3).unwrap();
    let error = provider
        .evaluate(&request(), "s", Instant::now() + Duration::from_secs(10))
        .unwrap_err();
    assert_eq!(error.0, "provider_auth");
    assert_eq!(rx.iter().count(), 1);

    let (url, _rx) = mock(vec![(200, r#"{"answers":{}}"#.into())]);
    let provider = HttpProvider::new(&url, "k".into(), Duration::from_secs(5), 3).unwrap();
    let error = provider
        .evaluate(&request(), "s", Instant::now() + Duration::from_secs(10))
        .unwrap_err();
    assert_eq!(error.0, "provider_invalid_response");
}

#[test]
fn refuses_plain_http_off_loopback_and_missing_keys() {
    assert_eq!(
        HttpProvider::new(
            "http://api.example.invalid/v1/systemone",
            "k".into(),
            Duration::from_secs(1),
            1
        )
        .unwrap_err(),
        "endpoint_requires_https"
    );
    assert_eq!(
        HttpProvider::new(
            "https://api.typesafe.ai/v1/systemone",
            " ".into(),
            Duration::from_secs(1),
            1
        )
        .unwrap_err(),
        "credentials_missing"
    );
}
