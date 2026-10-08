use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use telltale_systemone::analyzer::Analyzer;
use telltale_systemone::protocol::{AnalysisInputV1, AnalysisResultV1, Ready};
use telltale_systemone::{config, host_check, pack, serve};

const USAGE: &str = "usage:
  telltale-systemone serve --config <config.yaml>
  telltale-systemone evaluate --config <config.yaml> --input <inputs.jsonl> [--print-requests]
  telltale-systemone lint <pack.yaml>...
  telltale-systemone check --ready <ready.json> --input <input.json> --result <result.json>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("serve") => serve_cmd(&args[1..]),
        Some("evaluate") => evaluate_cmd(&args[1..]),
        Some("lint") => lint_cmd(&args[1..]),
        Some("check") => check_cmd(&args[1..]),
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

fn flag(args: &[String], name: &str) -> Option<PathBuf> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
}

fn required(args: &[String], name: &str) -> Result<PathBuf, String> {
    flag(args, name).ok_or_else(|| format!("missing {name}\n{USAGE}"))
}

fn load_analyzer(args: &[String]) -> Result<Analyzer, String> {
    let path = required(args, "--config")?;
    config::load(&path)
        .map(Analyzer::new)
        .map_err(|e| format!("config_error: {e}"))
}

fn serve_cmd(args: &[String]) -> Result<ExitCode, String> {
    let analyzer = load_analyzer(args)?;
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    match serve::run(&analyzer, stdin, stdout).map_err(|e| format!("io_error: {}", e.kind()))? {
        serve::Exit::Clean => Ok(ExitCode::SUCCESS),
        serve::Exit::Protocol => Ok(ExitCode::from(2)),
    }
}

fn read_inputs(path: &Path) -> Result<Vec<AnalysisInputV1>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read input: {e}"))?;
    let trimmed = text.trim_start();
    let values: Vec<&str> =
        if trimmed.starts_with('{') && serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
            vec![trimmed]
        } else {
            text.lines().filter(|l| !l.trim().is_empty()).collect()
        };
    values
        .into_iter()
        .enumerate()
        .map(|(i, raw)| {
            let input: AnalysisInputV1 = serde_json::from_str(raw)
                .map_err(|e| format!("input {i}: invalid structure: {e}"))?;
            input
                .validate()
                .map_err(|e| format!("input {i}: invalid_input reason={}", e.0))?;
            Ok(input)
        })
        .collect()
}

fn evaluate_cmd(args: &[String]) -> Result<ExitCode, String> {
    let analyzer = load_analyzer(args)?;
    let inputs = read_inputs(&required(args, "--input")?)?;
    let print_requests = args.iter().any(|a| a == "--print-requests");
    for input in &inputs {
        if print_requests {
            for planned in analyzer.plan(input) {
                let line = serde_json::json!({
                    "subject": input.subject.observation_id,
                    "profile": planned.profile,
                    "egress_guard": planned.blocked_by.map_or("pass".to_string(), |p| format!("blocked:{p}")),
                    "request": planned.request,
                });
                println!("{}", serde_json::to_string_pretty(&line).unwrap());
            }
        } else {
            let result = analyzer.analyze(input, Instant::now() + analyzer.default_deadline());
            println!("{}", serde_json::to_string(&result).unwrap());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn lint_cmd(args: &[String]) -> Result<ExitCode, String> {
    if args.is_empty() {
        return Err(USAGE.into());
    }
    let mut failed = false;
    for path in args {
        match pack::load_file(Path::new(path)) {
            Ok(loaded) => {
                println!(
                    "ok {path}: {} {} {} ({} checks)",
                    loaded.pack.id,
                    loaded.pack.version,
                    loaded.digest,
                    loaded.pack.checks.len()
                );
                for warning in &loaded.warnings {
                    println!("  warning {warning}");
                }
            }
            Err(errors) => {
                failed = true;
                println!("error {path}:");
                for error in errors {
                    println!("  {error}");
                }
            }
        }
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {what}: {e}"))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{what}: invalid JSON: {e}"))?;
    // Accept either the bare payload or the protocol line that carried it.
    if let Some(object) = value.as_object_mut() {
        match object.get("type").and_then(|t| t.as_str()) {
            Some("ready") => {
                object.remove("type");
            }
            Some("result") => value = object.remove("result").unwrap_or_default(),
            _ => {}
        }
    }
    serde_json::from_value(value).map_err(|e| format!("{what}: does not match the schema: {e}"))
}

fn check_cmd(args: &[String]) -> Result<ExitCode, String> {
    let ready: Ready = read_json(&required(args, "--ready")?, "ready")?;
    let input: AnalysisInputV1 = read_json(&required(args, "--input")?, "input")?;
    input
        .validate()
        .map_err(|e| format!("input: invalid_input reason={}", e.0))?;
    let result: AnalysisResultV1 = read_json(&required(args, "--result")?, "result")?;
    let mut violations = host_check::check_ready(&ready);
    violations.extend(host_check::check_result(&ready, &input, &result));
    if violations.is_empty() {
        for line in host_check::detector_result_preview(&result) {
            println!("{line}");
        }
        Ok(ExitCode::SUCCESS)
    } else {
        for v in violations {
            println!("violation {v}");
        }
        Ok(ExitCode::FAILURE)
    }
}
