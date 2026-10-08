//! `telltale-extension-v1` JSONL session over stdin/stdout.
//!
//! Requests are handled one at a time. stdout carries only protocol lines;
//! stderr carries closed diagnostic codes, never content.

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::analyzer::Analyzer;
use crate::protocol::*;

pub const MAX_LINE_BYTES: usize = 1024 * 1024;

pub enum Exit {
    Clean,
    Protocol,
}

pub fn run(
    analyzer: &Analyzer,
    input: impl BufRead,
    mut output: impl Write,
) -> std::io::Result<Exit> {
    let mut reader = input;
    let mut deadline = analyzer.default_deadline();
    let mut greeted = false;
    let mut line = Vec::new();

    loop {
        line.clear();
        match read_bounded_line(&mut reader, &mut line)? {
            LineRead::Eof => return Ok(Exit::Clean),
            LineRead::TooLong => {
                send(&mut output, error(None, "line_too_long", None))?;
                continue;
            }
            LineRead::Line => {}
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Ok(message) = serde_json::from_slice::<Value>(&line) else {
            send(&mut output, error(None, "invalid_json", None))?;
            continue;
        };
        let id = message.get("id").and_then(Value::as_str).map(str::to_owned);
        let kind = message
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let body = strip_type(message);

        match kind.as_str() {
            "hello" => {
                let hello: Hello = match serde_json::from_value(body) {
                    Ok(hello) => hello,
                    Err(_) => {
                        send(&mut output, error(None, "invalid_hello", None))?;
                        return Ok(Exit::Protocol);
                    }
                };
                if hello.protocol != PROTOCOL || !hello.capabilities.iter().any(|c| c == CAPABILITY)
                {
                    send(&mut output, error(None, "unsupported_protocol", None))?;
                    return Ok(Exit::Protocol);
                }
                if let Some(ms) = hello.limits.and_then(|l| l.deadline_ms) {
                    deadline = Duration::from_millis(ms.clamp(100, 600_000));
                }
                greeted = true;
                send(&mut output, PluginMessage::Ready(analyzer.ready()))?;
            }
            "analyze" if !greeted => send(&mut output, error(id, "hello_required", None))?,
            "analyze" => {
                let Some(id) = id.filter(|id| is_opaque(id)) else {
                    send(&mut output, error(None, "invalid_request_id", None))?;
                    continue;
                };
                let input = body
                    .get("input")
                    .cloned()
                    .ok_or(InputError("input"))
                    .and_then(|v| {
                        serde_json::from_value::<AnalysisInputV1>(v)
                            .map_err(|_| InputError("structure"))
                    })
                    .and_then(|input| input.validate().map(|_| input));
                match input {
                    Ok(input) => {
                        let result = analyzer.analyze(&input, Instant::now() + deadline);
                        send(&mut output, PluginMessage::Result { id, result })?;
                    }
                    Err(InputError(reason)) => {
                        send(&mut output, error(Some(id), "invalid_input", Some(reason)))?;
                    }
                }
            }
            "shutdown" => return Ok(Exit::Clean),
            _ => send(&mut output, error(id, "unsupported_message", None))?,
        }
    }
}

fn strip_type(mut message: Value) -> Value {
    if let Some(object) = message.as_object_mut() {
        object.remove("type");
        object.remove("id");
    }
    message
}

fn error(id: Option<String>, code: &str, reason: Option<&str>) -> PluginMessage {
    eprintln!(
        "telltale-systemone: {code}{}",
        reason.map(|r| format!(" reason={r}")).unwrap_or_default()
    );
    PluginMessage::Error {
        id,
        code: code.into(),
        reason: reason.map(str::to_owned),
    }
}

fn send(output: &mut impl Write, message: PluginMessage) -> std::io::Result<()> {
    serde_json::to_writer(&mut *output, &message)?;
    output.write_all(b"\n")?;
    output.flush()
}

enum LineRead {
    Line,
    TooLong,
    Eof,
}

/// Reads one `\n`-terminated line of at most `MAX_LINE_BYTES`; an oversized
/// line is consumed and reported rather than buffered.
fn read_bounded_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> std::io::Result<LineRead> {
    let mut too_long = false;
    let mut any = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(if !any {
                LineRead::Eof
            } else if too_long {
                LineRead::TooLong
            } else {
                LineRead::Line
            });
        }
        any = true;
        let (chunk, done) = match buffer.iter().position(|b| *b == b'\n') {
            Some(i) => (&buffer[..i], Some(i + 1)),
            None => (buffer, None),
        };
        if !too_long {
            if line.len() + chunk.len() > MAX_LINE_BYTES {
                too_long = true;
                line.clear();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let consumed = done.unwrap_or(buffer.len());
        reader.consume(consumed);
        if done.is_some() {
            return Ok(if too_long {
                LineRead::TooLong
            } else {
                LineRead::Line
            });
        }
    }
}
