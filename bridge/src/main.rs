//! Emits one `telltale.analysis-input.v1` JSON line per Telltale ActionFinding.
//!
//! Mode A only: Telltale produces ActionFindings for observations its native
//! rules flagged, so this bridge cannot project unflagged actions. Text leaves
//! only for the disclosure classes enabled on the command line.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{Map, Value, json};
use telltale_core::{
    ActionContextKind, ClientId, DetailedEvaluationOptions, Pipeline, Source, SourceCoverage,
    SourceKind,
};

const USAGE: &str = "usage: telltale-analysis-input --client <claude|codex|opencode|openclaw|qwen|copilot> \
--kind <jsonl|json|sqlite|archived_jsonl|headless_jsonl|copilot_process_log> --source-id <id> <path> \
[--tool-arguments] [--user-text] [--assistant-text] [--before N] [--after N]";

fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .ok_or_else(|| format!("missing {name}\n{USAGE}"))
    };
    let switch = |name: &str| args.iter().any(|a| a == name);
    let number = |name: &str| -> Result<usize, String> {
        match args.iter().position(|a| a == name) {
            Some(i) => args
                .get(i + 1)
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| format!("{name} needs a number")),
            None => Ok(0),
        }
    };
    let path = PathBuf::from(args.last().filter(|a| !a.starts_with("--")).ok_or(USAGE)?);
    let client = match value("--client")?.as_str() {
        "claude" => ClientId::Claude,
        "codex" => ClientId::Codex,
        "opencode" => ClientId::OpenCode,
        "openclaw" => ClientId::OpenClaw,
        "qwen" => ClientId::Qwen,
        "copilot" => ClientId::Copilot,
        _ => return Err(USAGE.into()),
    };
    let kind = match value("--kind")?.as_str() {
        "jsonl" => SourceKind::Jsonl,
        "json" => SourceKind::Json,
        "sqlite" => SourceKind::Sqlite,
        "archived_jsonl" => SourceKind::ArchivedJsonl,
        "headless_jsonl" => SourceKind::HeadlessJsonl,
        "copilot_process_log" => SourceKind::CopilotProcessLog,
        _ => return Err(USAGE.into()),
    };
    let source = Source {
        client,
        kind,
        source_id: value("--source-id")?,
        path,
    };

    let disclosure = json!({
        "user_text": switch("--user-text"),
        "assistant_text": switch("--assistant-text"),
        "tool_arguments": switch("--tool-arguments"),
    });
    let mut options = DetailedEvaluationOptions::default();
    options.context.before = number("--before")?;
    options.context.after = number("--after")?;
    options.context.user_text = switch("--user-text");
    options.context.assistant_text = switch("--assistant-text");
    options.context.tool_arguments = switch("--tool-arguments");

    let pipeline = Pipeline::builder()
        .build()
        .map_err(|e| format!("pipeline: {e}"))?;
    let scans = pipeline
        .scan_sources_detailed(std::slice::from_ref(&source), &options)
        .map_err(|e| format!("scan: {e}"))?;

    for scan in &scans {
        if let Some(failure) = scan.failure() {
            return Err(format!("source failed: {}", failure.code()));
        }
        let coverage = match scan.coverage() {
            Some(SourceCoverage::WholeSource) => Some("whole_source"),
            Some(SourceCoverage::Partial) => Some("partial"),
            _ => None,
        };
        for action in &scan.action_findings {
            let mut subject = Map::new();
            subject.insert("observation_id".into(), json!(action.observation_id()));
            subject.insert("family".into(), json!(action.kind().as_str()));
            subject.insert("stage".into(), json!(action.stage().as_str()));
            if let Some(time) = action.occurred_at() {
                subject.insert("occurred_at".into(), json!(time));
            }
            if let Some(tool) = action.tool_name() {
                subject.insert("tool_name".into(), json!(tool));
            }
            let mut seen = BTreeSet::new();
            let facts: Vec<Value> = action
                .evidence()
                .iter()
                .filter_map(|e| {
                    // Tool results, tool names, URLs, and authored content are not v1 facts.
                    let (field, allowed) = match e.field() {
                        "command" => ("command", options.context.tool_arguments),
                        "arguments" => ("arguments", options.context.tool_arguments),
                        "file_path" => ("file_path", options.context.tool_arguments),
                        "user_context" => ("user_message", options.context.user_text),
                        "assistant_context" => {
                            ("assistant_message", options.context.assistant_text)
                        }
                        _ => return None,
                    };
                    let text = e.redacted_value();
                    (allowed
                        && !text.is_empty()
                        && text.len() <= 4096
                        && seen.insert((field, text.to_owned())))
                    .then(|| json!({ "field": field, "text": text }))
                })
                .take(8)
                .collect();
            if !facts.is_empty() {
                subject.insert("facts".into(), Value::Array(facts));
            }

            let context: Vec<Value> = action
                .context()
                .iter()
                .map(|entry| {
                    let mut item = Map::new();
                    item.insert("offset".into(), json!(entry.offset()));
                    let kind = match entry.kind() {
                        ActionContextKind::UserMessage => "user_message",
                        ActionContextKind::AssistantMessage => "assistant_message",
                        ActionContextKind::ToolCall => "tool_call",
                        _ => return None,
                    };
                    item.insert("kind".into(), json!(kind));
                    item.insert("stage".into(), json!(entry.stage().as_str()));
                    if let Some(time) = entry.occurred_at() {
                        item.insert("occurred_at".into(), json!(time));
                    }
                    if let Some(tool) = entry.tool_name() {
                        item.insert("tool_name".into(), json!(tool));
                    }
                    if !entry.redacted_text().is_empty() {
                        item.insert("text".into(), json!(entry.redacted_text()));
                    }
                    Some(Value::Object(item))
                })
                .collect::<Option<Vec<_>>>()
                .ok_or("unknown context kind")?;

            let native: Vec<Value> = action
                .canonical_findings()
                .iter()
                .map(|f| {
                    let mut item = Map::new();
                    item.insert("finding_id".into(), json!(f.finding_id()));
                    item.insert("detector_id".into(), json!(f.detector_id()));
                    item.insert("category".into(), json!(f.category()));
                    item.insert("severity".into(), json!(f.severity().as_str()));
                    if let Some(risk) = f.risk_points() {
                        item.insert("risk_points".into(), json!(risk));
                    }
                    Value::Object(item)
                })
                .collect();

            let mut visibility = Map::new();
            visibility.insert("source".into(), json!(scan.source.source_id));
            if let Some(coverage) = coverage {
                visibility.insert("coverage".into(), json!(coverage));
            }
            visibility.insert("disclosure".into(), disclosure.clone());
            visibility.insert("redaction".into(), json!("telltale.redact_sensitive_text"));

            let mut input = Map::new();
            input.insert("schema".into(), json!("telltale.analysis-input.v1"));
            input.insert("subject".into(), Value::Object(subject));
            if !context.is_empty() {
                input.insert("context".into(), Value::Array(context));
            }
            if !native.is_empty() {
                input.insert("native_findings".into(), Value::Array(native));
            }
            input.insert("visibility".into(), Value::Object(visibility));
            println!("{}", Value::Object(input));
        }
    }
    Ok(())
}
