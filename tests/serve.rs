//! Drives `serve` over JSONL exactly as a host would, then validates every
//! line against the JSON Schemas and the host-side semantic checks.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use telltale_systemone::host_check;
use telltale_systemone::protocol::{AnalysisInputV1, AnalysisResultV1, Ready, Status};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(root().join(path)).unwrap()).unwrap()
}

fn messages_validator() -> jsonschema::Validator {
    let resource = |path| jsonschema::Resource::from_contents(read_json(path)).unwrap();
    jsonschema::options()
        .with_resource(
            "urn:telltale-systemone:schema:analysis-input-v1",
            resource("schemas/analysis-input-v1.schema.json"),
        )
        .with_resource(
            "urn:telltale-systemone:schema:analysis-result-v1",
            resource("schemas/analysis-result-v1.schema.json"),
        )
        .build(&read_json("schemas/extension-v1-messages.schema.json"))
        .unwrap()
}

fn example_inputs() -> Vec<Value> {
    ["examples/inputs.jsonl", "examples/mode-b-inputs.jsonl"]
        .iter()
        .flat_map(|p| {
            std::fs::read_to_string(root().join(p))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str::<Value>(l).unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Sends `lines` to a fresh `serve` process and returns its stdout lines.
fn session(lines: &[Value]) -> (Vec<Value>, std::process::ExitStatus) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_telltale-systemone"))
        .args(["serve", "--config"])
        .arg(root().join("examples/config.fixture.yaml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for line in lines {
            writeln!(stdin, "{line}").unwrap();
        }
        stdin.write_all(b"this is not json\n").unwrap();
        writeln!(stdin, "{}", json!({"type": "shutdown"})).unwrap();
    }
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let out = stdout
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
        .collect();
    (out, child.wait().unwrap())
}

fn hello() -> Value {
    json!({"type": "hello", "protocol": "telltale-extension-v1", "capabilities": ["analyzer.v1"],
           "host": {"name": "test-host", "version": "0"}, "limits": {"deadline_ms": 5000}})
}

#[test]
fn full_session_conforms_to_schemas_and_host_rules() {
    let inputs = example_inputs();
    let mut lines = vec![hello()];
    for (i, input) in inputs.iter().enumerate() {
        lines.push(json!({"type": "analyze", "id": format!("req-{i}"), "input": input}));
    }
    let (out, status) = session(&lines);
    assert!(status.success());
    // ready + one result per input + the invalid_json error.
    assert_eq!(out.len(), 1 + inputs.len() + 1);

    let validator = messages_validator();
    for line in &out {
        let errors: Vec<String> = validator
            .iter_errors(line)
            .map(|e| format!("{e} at {}", e.instance_path))
            .collect();
        assert!(errors.is_empty(), "schema violations: {errors:?}\n{line}");
    }

    let mut ready_value = out[0].clone();
    ready_value.as_object_mut().unwrap().remove("type");
    let ready: Ready = serde_json::from_value(ready_value).unwrap();
    assert!(host_check::check_ready(&ready).is_empty());
    // The fixture provider sends nothing anywhere.
    assert!(ready.egress.is_empty());

    for (i, input) in inputs.iter().enumerate() {
        let line = &out[1 + i];
        assert_eq!(line["type"], "result");
        assert_eq!(line["id"], format!("req-{i}"));
        let input: AnalysisInputV1 = serde_json::from_value(input.clone()).unwrap();
        let result: AnalysisResultV1 = serde_json::from_value(line["result"].clone()).unwrap();
        let violations = host_check::check_result(&ready, &input, &result);
        assert!(violations.is_empty(), "{violations:?}");
    }
    assert_eq!(out.last().unwrap()["code"], "invalid_json");
}

#[test]
fn protocol_errors_are_explicit() {
    let input = &example_inputs()[0];
    let mut undisclosed = input.clone();
    undisclosed["visibility"]["disclosure"]["tool_arguments"] = json!(false);
    let (out, _) = session(&[
        json!({"type": "analyze", "id": "early", "input": input}),
        hello(),
        json!({"type": "analyze", "id": "bad", "input": undisclosed}),
        json!({"type": "analyze", "id": "has space", "input": input}),
        json!({"type": "subscribe", "id": "x"}),
    ]);
    assert_eq!(out[0]["code"], "hello_required");
    assert_eq!(out[1]["type"], "ready");
    assert_eq!(
        (out[2]["code"].as_str(), out[2]["reason"].as_str()),
        (Some("invalid_input"), Some("subject.facts.disclosure"))
    );
    assert_eq!(out[3]["code"], "invalid_request_id");
    assert_eq!(out[4]["code"], "unsupported_message");
}

#[test]
fn wrong_protocol_ends_the_session() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_telltale-systemone"))
        .args(["serve", "--config"])
        .arg(root().join("examples/config.fixture.yaml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", json!({"type": "hello", "protocol": "telltale-extension-v9", "capabilities": ["analyzer.v1"]})).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("unsupported_protocol"));
}

#[test]
fn example_outcomes_match_the_documented_walkthrough() {
    let inputs = example_inputs();
    let mut lines = vec![hello()];
    for (i, input) in inputs.iter().enumerate() {
        lines.push(json!({"type": "analyze", "id": format!("r{i}"), "input": input}));
    }
    let (out, _) = session(&lines);
    let status = |input: usize, detector: &str| -> (Status, Value) {
        let result: AnalysisResultV1 =
            serde_json::from_value(out[1 + input]["result"].clone()).unwrap();
        let r = result
            .results
            .into_iter()
            .find(|r| r.detector_id.ends_with(detector))
            .unwrap();
        (r.status, serde_json::to_value(&r).unwrap())
    };
    // Mode A install: Telltale redacted the command to a placeholder, so the
    // model can only say "unclear" -> informational review lead.
    let (s, r) = status(0, "install.package_source");
    assert_eq!(
        (s, r["finding_kind"].as_str()),
        (Status::EvaluatedMatch, Some("threat_hunt"))
    );
    // Autostart via ~/.config/autostart: no native persistence rule, model match.
    assert_eq!(
        status(2, "persistence.autostart_change").0,
        Status::EvaluatedMatch
    );
    // Order check disagreement on the same action -> review, not a match.
    assert_eq!(
        status(2, "intent.scope_mismatch").1["tags"][0],
        "systemone.review"
    );
    // Without disclosed user text the intent check never claims a clean result.
    let (s, r) = status(6, "intent.scope_mismatch");
    assert_eq!(
        (s, r["non_evaluation_reason"].as_str()),
        (Status::NotEvaluated, Some("insufficient_visibility"))
    );
    // A credential that slipped past redaction blocks the request entirely.
    let (s, r) = status(7, "execution.action_risk");
    assert_eq!(
        (s, r["diagnostic"]["code"].as_str()),
        (Status::NotEvaluated, Some("egress_guard_aws_access_key_id"))
    );
}

#[test]
fn tampered_results_are_rejected_by_schema_and_host_checks() {
    let input = example_inputs()[1].clone();
    let (out, _) = session(&[
        hello(),
        json!({"type": "analyze", "id": "r", "input": input}),
    ]);
    let mut ready_value = out[0].clone();
    ready_value.as_object_mut().unwrap().remove("type");
    let ready: Ready = serde_json::from_value(ready_value).unwrap();
    let input: AnalysisInputV1 = serde_json::from_value(input).unwrap();
    let original: AnalysisResultV1 = serde_json::from_value(out[1]["result"].clone()).unwrap();
    let matched = original
        .results
        .iter()
        .position(|r| r.status == Status::EvaluatedMatch)
        .unwrap();

    let violations = |edit: &dyn Fn(&mut AnalysisResultV1)| {
        let mut result = original.clone();
        edit(&mut result);
        host_check::check_result(&ready, &input, &result)
    };
    // Escalating severity or risk beyond what the pack declared.
    assert!(!violations(&|r| r.results[matched].risk_points = Some(100)).is_empty());
    // Citing an observation that was not in the input.
    assert!(
        !violations(&|r| r.results[matched].observation_ids =
            vec![format!("obs:v2:sha256:{}", "f".repeat(64))])
        .is_empty()
    );
    // Re-labelling the category.
    assert!(!violations(&|r| r.results[matched].category = "exfiltration".into()).is_empty());
    // Dropping a result instead of reporting not_evaluated.
    assert!(
        !violations(&|r| {
            r.results.pop();
        })
        .is_empty()
    );
    // Claiming a different content identity than the handshake.
    assert!(
        !violations(&|r| r.analyzer.content_ref = format!("sha256:{}", "0".repeat(64))).is_empty()
    );

    // The structural schema also refuses risk on a non-match.
    let validator = messages_validator();
    let mut line = out[1].clone();
    let no_match = original
        .results
        .iter()
        .position(|r| r.status == Status::EvaluatedNoMatch)
        .unwrap();
    line["result"]["results"][no_match]["risk_points"] = json!(10);
    assert!(!validator.is_valid(&line));
}
