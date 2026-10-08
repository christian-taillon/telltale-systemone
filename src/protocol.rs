//! Wire types for `telltale-extension-v1` / `analyzer.v1`.
//!
//! These structs are the cross-process contract described in
//! `docs/protocol.md` and `schemas/`. They are dedicated wire types, not
//! projections of Telltale internals, and unknown fields are rejected.

use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "telltale-extension-v1";
pub const CAPABILITY: &str = "analyzer.v1";
pub const INPUT_SCHEMA: &str = "telltale.analysis-input.v1";
pub const RESULT_SCHEMA: &str = "telltale.analysis-result.v1";
pub const REDACTION_MARK: &str = "telltale.redact_sensitive_text";

/// Bounds mirror Telltale's Detection v2 and same-pass context limits.
pub const MAX_ID_BYTES: usize = 96;
pub const MAX_CATEGORY_BYTES: usize = 128;
pub const MAX_SUBJECT_FACTS: usize = 8;
pub const MAX_FACT_BYTES: usize = 4096;
pub const MAX_CONTEXT_ENTRIES: usize = 64;
pub const MAX_CONTEXT_TEXT_BYTES: usize = 512;
pub const MAX_CONTEXT_OFFSET: i32 = 32;
pub const MAX_TOTAL_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_NATIVE_FINDINGS: usize = 64;
pub const MAX_RESULTS: usize = 64;
pub const MAX_TAGS: usize = 32;
pub const MAX_TECHNIQUES: usize = 32;
pub const MAX_EVIDENCE: usize = 16;

// ---------------------------------------------------------------------------
// Shared vocabularies (exact Telltale spellings)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    SecurityDetection,
    PolicyViolation,
    BehavioralDeviation,
    Guardrail,
    ComplianceObservation,
    ThreatHunt,
    Informational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    EvaluatedMatch,
    EvaluatedNoMatch,
    NotApplicable,
    NotEvaluated,
    DetectorError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonEvaluationReason {
    InsufficientVisibility,
    RequiredCapabilityUnsupported,
    RequiredCapabilityUnknown,
    MissingOrderingField,
    MissingCorrelationKey,
    TypeMismatch,
    IneligibleInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticKind {
    RuntimeDetectorError,
    MalformedContentOrPackage,
    UnavailableCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Message,
    Inference,
    Tool,
    ToolDefinition,
    Mcp,
    Process,
    File,
    Network,
    Browser,
    Runtime,
    Session,
    Other,
}

impl Family {
    /// Stage spellings are family-relative in Telltale (`ObservationStage::as_str`).
    pub fn allows_stage(self, stage: &str) -> bool {
        let allowed: &[&str] = match self {
            Family::Message => &["observed"],
            Family::Inference => &["requested", "started", "completed", "failed"],
            Family::Tool => &[
                "proposed",
                "requested",
                "execution_started",
                "execution_completed",
                "result_returned",
            ],
            Family::ToolDefinition => &["changed"],
            Family::Mcp => &["inventory_changed"],
            Family::Runtime => &["observed", "changed"],
            Family::Session => &["opened", "updated", "closed"],
            Family::Process | Family::File | Family::Network | Family::Browser | Family::Other => {
                &["observed"]
            }
        };
        allowed.contains(&stage)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Supported,
    Unsupported,
    #[default]
    Unknown,
}

// ---------------------------------------------------------------------------
// AnalysisInputV1
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisInputV1 {
    pub schema: String,
    pub subject: Subject,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<ContextEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_findings: Vec<NativeFinding>,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub observation_id: String,
    pub family: Family,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facts: Vec<SubjectFact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectFact {
    pub field: FactField,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactField {
    Command,
    Arguments,
    FilePath,
    UserMessage,
    AssistantMessage,
}

impl FactField {
    pub fn as_str(self) -> &'static str {
        match self {
            FactField::Command => "command",
            FactField::Arguments => "arguments",
            FactField::FilePath => "file_path",
            FactField::UserMessage => "user_message",
            FactField::AssistantMessage => "assistant_message",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextEntry {
    pub offset: i32,
    pub kind: ContextKind,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    UserMessage,
    AssistantMessage,
    ToolCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFinding {
    pub finding_id: String,
    pub detector_id: String,
    pub category: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_points: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Visibility {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Coverage>,
    #[serde(default)]
    pub capabilities: Capabilities,
    pub disclosure: Disclosure,
    pub redaction: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    WholeSource,
    Partial,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub tool_call: Availability,
    #[serde(default)]
    pub tool_execution: Availability,
    #[serde(default)]
    pub user_context: Availability,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disclosure {
    pub user_text: bool,
    pub assistant_text: bool,
    pub tool_arguments: bool,
}

/// A closed, content-free reason why an input was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputError(pub &'static str);

impl AnalysisInputV1 {
    pub fn validate(&self) -> Result<(), InputError> {
        if self.schema != INPUT_SCHEMA {
            return Err(InputError("schema"));
        }
        if self.visibility.redaction != REDACTION_MARK {
            return Err(InputError("visibility.redaction"));
        }
        if let Some(source) = &self.visibility.source
            && !is_label(source)
        {
            return Err(InputError("visibility.source"));
        }
        let subject = &self.subject;
        if !is_observation_id(&subject.observation_id) {
            return Err(InputError("subject.observation_id"));
        }
        if !subject.family.allows_stage(&subject.stage) {
            return Err(InputError("subject.stage"));
        }
        if subject
            .occurred_at
            .as_deref()
            .is_some_and(|t| !is_timestamp(t))
        {
            return Err(InputError("subject.occurred_at"));
        }
        if subject.tool_name.as_deref().is_some_and(|t| !is_label(t)) {
            return Err(InputError("subject.tool_name"));
        }
        if subject.facts.len() > MAX_SUBJECT_FACTS {
            return Err(InputError("subject.facts"));
        }
        let disclosure = &self.visibility.disclosure;
        let mut total = 0usize;
        for fact in &subject.facts {
            if fact.text.is_empty() || fact.text.len() > MAX_FACT_BYTES {
                return Err(InputError("subject.facts.text"));
            }
            let disclosed = match fact.field {
                FactField::Command | FactField::Arguments | FactField::FilePath => {
                    disclosure.tool_arguments
                }
                FactField::UserMessage => disclosure.user_text,
                FactField::AssistantMessage => disclosure.assistant_text,
            };
            if !disclosed {
                return Err(InputError("subject.facts.disclosure"));
            }
            total += fact.text.len();
        }
        if self.context.len() > MAX_CONTEXT_ENTRIES {
            return Err(InputError("context"));
        }
        for entry in &self.context {
            if entry.offset == 0 || entry.offset.abs() > MAX_CONTEXT_OFFSET {
                return Err(InputError("context.offset"));
            }
            let stage_ok = match entry.kind {
                ContextKind::UserMessage | ContextKind::AssistantMessage => {
                    entry.stage == "observed"
                }
                // Tool results never enter v1 context.
                ContextKind::ToolCall => matches!(
                    entry.stage.as_str(),
                    "proposed" | "requested" | "execution_started" | "execution_completed"
                ),
            };
            if !stage_ok {
                return Err(InputError("context.stage"));
            }
            if entry
                .occurred_at
                .as_deref()
                .is_some_and(|t| !is_timestamp(t))
            {
                return Err(InputError("context.occurred_at"));
            }
            if entry.tool_name.as_deref().is_some_and(|t| !is_label(t)) {
                return Err(InputError("context.tool_name"));
            }
            if let Some(text) = &entry.text {
                if text.is_empty() || text.len() > MAX_CONTEXT_TEXT_BYTES {
                    return Err(InputError("context.text"));
                }
                let disclosed = match entry.kind {
                    ContextKind::UserMessage => disclosure.user_text,
                    ContextKind::AssistantMessage => disclosure.assistant_text,
                    ContextKind::ToolCall => disclosure.tool_arguments,
                };
                if !disclosed {
                    return Err(InputError("context.disclosure"));
                }
                total += text.len();
            }
        }
        if total > MAX_TOTAL_TEXT_BYTES {
            return Err(InputError("text_budget"));
        }
        if self.native_findings.len() > MAX_NATIVE_FINDINGS {
            return Err(InputError("native_findings"));
        }
        for finding in &self.native_findings {
            if !is_prefixed_digest(&finding.finding_id, "fnd:v2:sha256:") {
                return Err(InputError("native_findings.finding_id"));
            }
            if !is_detector_id(&finding.detector_id) {
                return Err(InputError("native_findings.detector_id"));
            }
            if !is_bounded_text(&finding.category, MAX_CATEGORY_BYTES) {
                return Err(InputError("native_findings.category"));
            }
            if finding.risk_points.is_some_and(|r| r > 100) {
                return Err(InputError("native_findings.risk_points"));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AnalysisResultV1
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisResultV1 {
    pub schema: String,
    pub subject_observation_id: String,
    pub analyzer: AnalyzerIdentity,
    pub results: Vec<CheckResult>,
    pub usage: Usage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerIdentity {
    pub id: String,
    pub version: String,
    pub engine: String,
    pub content_ref: String,
    pub semantics_version: u32,
    /// Model ID reported by the provider for this analysis, when any request ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub detector_id: String,
    pub detector_version: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_evaluation_reason: Option<NonEvaluationReason>,
    #[serde(default)]
    pub observation_ids: Vec<String>,
    pub finding_kind: FindingKind,
    pub category: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_points: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub techniques: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedupe_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Diagnostic>,
    /// Model output that produced the decision. Inferred, never an observed fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment: Option<Assessment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub kind: DiagnosticKind,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "primitive", rename_all = "snake_case", deny_unknown_fields)]
pub enum Assessment {
    Predicate {
        probability: f64,
    },
    Choice {
        choice: String,
        probabilities: std::collections::BTreeMap<String, f64>,
        confidence: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        order_check: Option<OrderCheck>,
    },
    Score {
        score: f64,
        probabilities: std::collections::BTreeMap<String, f64>,
        confidence: f64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderCheck {
    Consistent,
    Inconsistent,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub requests: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

// ---------------------------------------------------------------------------
// Handshake and framing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub protocol: String,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<HostLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLimits {
    /// Wall-clock budget for one `analyze` request, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub protocol: String,
    pub capability: String,
    pub extension: ExtensionInfo,
    pub detector_namespace: String,
    pub semantics_version: u32,
    pub content_ref: String,
    pub model: String,
    pub packs: Vec<PackRef>,
    pub detectors: Vec<DetectorDeclaration>,
    /// Disclosure classes the loaded checks can use. The host may refuse to
    /// start the analyzer if the operator has not approved these.
    pub disclosure_uses: Vec<String>,
    /// Network destinations that receive projection content.
    pub egress: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionInfo {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRef {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorDeclaration {
    pub id: String,
    pub version: String,
    pub category: String,
    /// Metadata carried by non-match results.
    pub base: OutcomeDeclaration,
    /// Every metadata combination an `evaluated_match` result may carry.
    pub match_outcomes: Vec<OutcomeDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeDeclaration {
    pub finding_kind: FindingKind,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_points: Option<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PluginMessage {
    Ready(Ready),
    Result {
        id: String,
        result: AnalysisResultV1,
    },
    Error {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Grammar helpers
// ---------------------------------------------------------------------------

pub fn is_bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

/// Telltale `bounded_identifier`: lowercase ASCII, digits, `.`, `_`, `-`.
pub fn is_detector_id(value: &str) -> bool {
    is_bounded_text(value, MAX_ID_BYTES)
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Telltale `bounded_opaque`: no separators, traversal, or whitespace.
pub fn is_opaque(value: &str) -> bool {
    is_bounded_text(value, MAX_ID_BYTES)
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains("..")
        && !value.chars().any(char::is_whitespace)
}

/// Readable labels such as tool names or source identities.
pub fn is_label(value: &str) -> bool {
    is_bounded_text(value, MAX_ID_BYTES)
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'[' | b']')
        })
}

pub fn is_bare_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn is_prefixed_digest(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(is_bare_digest)
}

pub fn is_observation_id(value: &str) -> bool {
    is_prefixed_digest(value, "obs:v2:sha256:")
}

/// Shape check only; the analyzer never does time arithmetic.
fn is_timestamp(value: &str) -> bool {
    value.len() <= 64
        && value.len() >= 10
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b':' | b'T' | b'Z' | b'.' | b'+'))
}

/// Telltale evidence classification token: `classification:` + safe token.
pub fn is_classification(value: &str) -> bool {
    value.len() <= MAX_ID_BYTES
        && value.strip_prefix("classification:").is_some_and(|token| {
            !token.is_empty()
                && !token.contains("..")
                && token.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'+' | b'-')
                })
        })
}

/// Telltale technique grammar: `attack:` or `atlas:` + `[A-Za-z0-9._-]+`.
pub fn is_technique(value: &str) -> bool {
    value.len() <= MAX_ID_BYTES
        && value
            .strip_prefix("attack:")
            .or_else(|| value.strip_prefix("atlas:"))
            .is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input() -> serde_json::Value {
        json!({
            "schema": INPUT_SCHEMA,
            "subject": {
                "observation_id": format!("obs:v2:sha256:{}", "a".repeat(64)),
                "family": "tool", "stage": "requested", "tool_name": "Bash",
                "facts": [{"field": "command", "text": "npm test"}]
            },
            "context": [{"offset": -1, "kind": "user_message", "stage": "observed", "text": "run tests"}],
            "visibility": {
                "disclosure": {"user_text": true, "assistant_text": false, "tool_arguments": true},
                "redaction": REDACTION_MARK
            }
        })
    }

    fn validate(value: serde_json::Value) -> Result<(), InputError> {
        serde_json::from_value::<AnalysisInputV1>(value)
            .unwrap()
            .validate()
    }

    #[test]
    fn accepts_a_minimal_valid_input() {
        assert_eq!(validate(input()), Ok(()));
    }

    #[test]
    fn refuses_text_the_host_did_not_disclose() {
        let mut v = input();
        v["visibility"]["disclosure"]["user_text"] = json!(false);
        assert_eq!(validate(v), Err(InputError("context.disclosure")));
        let mut v = input();
        v["visibility"]["disclosure"]["tool_arguments"] = json!(false);
        assert_eq!(validate(v), Err(InputError("subject.facts.disclosure")));
    }

    #[test]
    fn refuses_tool_results_unredacted_input_and_bad_ids() {
        let mut v = input();
        v["context"] =
            json!([{"offset": -1, "kind": "tool_call", "stage": "result_returned", "text": "x"}]);
        assert_eq!(validate(v), Err(InputError("context.stage")));
        let mut v = input();
        v["visibility"]["redaction"] = json!("none");
        assert_eq!(validate(v), Err(InputError("visibility.redaction")));
        let mut v = input();
        v["subject"]["observation_id"] = json!("obs:v2:sha256:ABC");
        assert_eq!(validate(v), Err(InputError("subject.observation_id")));
        let mut v = input();
        v["subject"]["stage"] = json!("observed");
        assert_eq!(validate(v), Err(InputError("subject.stage")));
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut v = input();
        v["subject"]["source_path"] = json!("/home/user/.claude/projects/x.jsonl");
        assert!(serde_json::from_value::<AnalysisInputV1>(v).is_err());
    }
}
