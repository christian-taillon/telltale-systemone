//! Guard packs: versioned YAML documents that declare System One questions and
//! the deterministic decisions that turn answers into Telltale results.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::{
    Family, FindingKind, OutcomeDeclaration, Severity, is_detector_id, is_opaque, is_technique,
};

pub const PACK_SCHEMA: &str = "telltale-systemone.guard-pack.v1";
pub const NAMESPACE: &str = "systemone";

/// Telltale ADR categories from `docs/threat-taxonomy.md`.
pub const ADR_CATEGORIES: &[&str] = &[
    "secret_access",
    "credential_pattern",
    "execution",
    "download",
    "install",
    "exfiltration",
    "persistence",
    "approval_bypass",
    "tool_injection",
    "mcp_prompt_injection",
    "credential_harvesting",
    "supply_chain",
    "mcp_enumeration",
    "defense_evasion",
    "command_and_control",
    "discovery",
    "credential_access",
    "lateral_movement",
    "impact",
    "collection",
];

/// Categories this project proposes but Telltale has not accepted.
pub const PROPOSED_CATEGORIES: &[&str] = &["intent_mismatch"];

const MAX_INSTRUCTION_BYTES: usize = 2048;
const MAX_CRITERIA_BYTES: usize = 8192;
const MAX_CHECKS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardPack {
    pub schema: String,
    pub id: String,
    pub version: String,
    pub title: String,
    /// `draft` until thresholds are tuned on labeled data for `models`.
    pub status: PackStatus,
    /// Exact model IDs the questions and thresholds are written for.
    pub models: Vec<String>,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackStatus {
    Draft,
    Evaluated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub finding_kind: FindingKind,
    pub category: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub techniques: Vec<String>,
    pub applies_to: AppliesTo,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Requirement>,
    pub state: StateProfile,
    pub question: Question,
    #[serde(default)]
    pub uncertain: UncertainPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliesTo {
    pub families: Vec<Family>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<String>,
    /// Case-insensitive exact tool names. Empty means any tool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    /// When set, the check runs only if a native Telltale finding on the
    /// subject has one of these categories (triage mode).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_categories: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// At least one disclosed subject fact.
    SubjectText,
    /// At least one disclosed user message in preceding context.
    UserContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateProfile {
    /// Only the subject action.
    Action,
    /// The subject action plus disclosed context before it.
    ActionWithContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertainPolicy {
    /// Emit an informational `threat_hunt` match with zero risk for review.
    #[default]
    Review,
    /// Treat uncertainty as an evaluated no-match.
    NoMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Question {
    /// Yes/no probability; sent to System One as a `noul`.
    Predicate {
        instructions: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        criteria: Option<PredicateCriteria>,
        match_at: f64,
        clear_below: f64,
        severity: Severity,
        risk_points: u8,
    },
    Choice {
        instructions: String,
        options: Vec<ChoiceOption>,
        #[serde(default)]
        min_confidence: f64,
        /// Ask a second, reversed-order copy in the same request; disagreement
        /// is uncertainty (Jev favours the first option).
        #[serde(default)]
        order_check: bool,
    },
    Score {
        instructions: String,
        levels: Vec<serde_json::Value>,
        match_at: f64,
        clear_below: f64,
        #[serde(default)]
        min_confidence: f64,
        /// Ascending `at` thresholds; the first must equal `match_at`.
        bands: Vec<ScoreBand>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateCriteria {
    #[serde(rename = "true")]
    pub yes: serde_json::Value,
    #[serde(rename = "false")]
    pub no: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChoiceOption {
    pub name: String,
    #[serde(default)]
    pub description: serde_json::Value,
    pub outcome: ChoiceOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_points: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChoiceOutcome {
    Match,
    NoMatch,
    Review,
    /// The model says the state cannot answer the question.
    InsufficientVisibility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreBand {
    pub at: f64,
    pub severity: Severity,
    pub risk_points: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackError {
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// A validated pack with its content digest.
#[derive(Debug, Clone)]
pub struct LoadedPack {
    pub pack: GuardPack,
    pub digest: String,
    pub warnings: Vec<String>,
}

pub fn load_file(path: &Path) -> Result<LoadedPack, Vec<PackError>> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        vec![PackError {
            path: path.display().to_string(),
            message: format!("cannot read pack: {e}"),
        }]
    })?;
    parse(&text)
}

pub fn parse(text: &str) -> Result<LoadedPack, Vec<PackError>> {
    let mut pack: GuardPack = serde_yaml::from_str(text).map_err(|e| {
        vec![PackError {
            path: "pack".into(),
            message: format!("invalid YAML or unknown field: {e}"),
        }]
    })?;
    normalize(&mut pack);
    let warnings = validate(&pack)?;
    let digest = digest(&pack);
    Ok(LoadedPack {
        pack,
        digest,
        warnings,
    })
}

/// Trim model-facing text so YAML block scalars do not send trailing newlines.
fn normalize(pack: &mut GuardPack) {
    fn trim(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => *s = s.trim().to_owned(),
            serde_json::Value::Array(items) => items.iter_mut().for_each(trim),
            serde_json::Value::Object(map) => map.values_mut().for_each(trim),
            _ => {}
        }
    }
    for check in &mut pack.checks {
        match &mut check.question {
            Question::Predicate {
                instructions,
                criteria,
                ..
            } => {
                *instructions = instructions.trim().to_owned();
                if let Some(c) = criteria {
                    trim(&mut c.yes);
                    trim(&mut c.no);
                }
            }
            Question::Choice {
                instructions,
                options,
                ..
            } => {
                *instructions = instructions.trim().to_owned();
                options.iter_mut().for_each(|o| trim(&mut o.description));
            }
            Question::Score {
                instructions,
                levels,
                ..
            } => {
                *instructions = instructions.trim().to_owned();
                levels.iter_mut().for_each(trim);
            }
        }
    }
}

/// Domain-separated SHA-256 over the canonical JSON of the parsed pack.
/// Object keys are sorted; list order is kept because option and level order
/// changes model behaviour.
pub fn digest(pack: &GuardPack) -> String {
    let value = serde_json::to_value(pack).expect("pack serializes");
    sha256_hex(
        b"telltale-systemone:guard-pack:v1\0",
        canonical_json(&value).as_bytes(),
    )
}

pub fn sha256_hex(domain: &[u8], body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(body);
    format!("sha256:{:x}", hasher.finalize())
}

/// Compact JSON with recursively sorted object keys.
pub fn canonical_json(value: &serde_json::Value) -> String {
    fn sort(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for key in keys {
                    out.insert(key.clone(), sort(&map[key]));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(sort).collect())
            }
            other => other.clone(),
        }
    }
    serde_json::to_string(&sort(value)).expect("value serializes")
}

fn validate(pack: &GuardPack) -> Result<Vec<String>, Vec<PackError>> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut err = |path: String, message: &str| {
        errors.push(PackError {
            path,
            message: message.into(),
        })
    };

    if pack.schema != PACK_SCHEMA {
        err("schema".into(), "must be telltale-systemone.guard-pack.v1");
    }
    if !is_namespaced(&pack.id) {
        err(
            "id".into(),
            "must be a lowercase identifier starting with `systemone.`",
        );
    }
    if !is_opaque(&pack.version) {
        err(
            "version".into(),
            "must be a short token without spaces or separators",
        );
    }
    if pack.title.trim().is_empty() {
        err("title".into(), "must not be empty");
    }
    if pack.models.is_empty() || pack.models.iter().any(|m| !is_opaque(m)) {
        err(
            "models".into(),
            "list the exact model IDs the questions and thresholds target",
        );
    }
    if pack.status == PackStatus::Draft {
        warnings.push("status: draft; thresholds have not been tuned on labeled data".into());
    }
    if pack.checks.is_empty() || pack.checks.len() > MAX_CHECKS {
        err("checks".into(), "must contain 1..=64 checks");
    }

    let mut ids = BTreeSet::new();
    for (index, check) in pack.checks.iter().enumerate() {
        let at = |field: &str| format!("checks[{index}].{field}");
        if !is_namespaced(&check.id) {
            err(
                at("id"),
                "must be a lowercase identifier starting with `systemone.`",
            );
        }
        if !ids.insert(check.id.as_str()) {
            err(at("id"), "duplicate check id");
        }
        if check.title.trim().is_empty() {
            err(at("title"), "must not be empty");
        }
        if !ADR_CATEGORIES.contains(&check.category.as_str()) {
            if PROPOSED_CATEGORIES.contains(&check.category.as_str()) {
                warnings.push(format!(
                    "{}: category `{}` is proposed, not a Telltale ADR category; the host must accept it",
                    at("category"),
                    check.category
                ));
            } else {
                err(
                    at("category"),
                    "must be a Telltale ADR category (docs/threat-taxonomy.md)",
                );
            }
        }
        for technique in &check.techniques {
            if !is_technique(technique) {
                err(at("techniques"), "use `attack:<id>` or `atlas:<id>`");
            }
        }
        if check.applies_to.families.is_empty() {
            err(
                at("applies_to.families"),
                "list at least one observation family",
            );
        }
        for stage in &check.applies_to.stages {
            if !check
                .applies_to
                .families
                .iter()
                .any(|f| f.allows_stage(stage))
            {
                err(
                    at("applies_to.stages"),
                    "stage is not valid for any listed family",
                );
            }
        }
        if check.requires.contains(&Requirement::UserContext)
            && check.state != StateProfile::ActionWithContext
        {
            err(
                at("requires"),
                "user_context requires state: action_with_context",
            );
        }
        validate_question(&check.question, &at("question"), &mut err, &mut warnings);
    }

    if errors.is_empty() {
        Ok(warnings)
    } else {
        Err(errors)
    }
}

fn validate_question(
    question: &Question,
    at: &str,
    err: &mut impl FnMut(String, &str),
    warnings: &mut Vec<String>,
) {
    let unit = |v: f64| v.is_finite() && (0.0..=1.0).contains(&v);
    match question {
        Question::Predicate {
            instructions,
            criteria,
            match_at,
            clear_below,
            risk_points,
            ..
        } => {
            check_instructions(instructions, at, err);
            if let Some(criteria) = criteria {
                check_json_size(&criteria.yes, &format!("{at}.criteria.true"), err);
                check_json_size(&criteria.no, &format!("{at}.criteria.false"), err);
            }
            if !unit(*match_at) || !unit(*clear_below) || clear_below > match_at {
                err(
                    format!("{at}.match_at"),
                    "need 0 <= clear_below <= match_at <= 1",
                );
            }
            if *match_at <= 0.5 {
                warnings.push(format!(
                    "{at}.match_at: {match_at} matches when `no` is at least as likely as `yes`"
                ));
            }
            if *risk_points > 100 {
                err(format!("{at}.risk_points"), "must be 0..=100");
            }
        }
        Question::Choice {
            instructions,
            options,
            min_confidence,
            ..
        } => {
            check_instructions(instructions, at, err);
            if !(2..=255).contains(&options.len()) {
                err(format!("{at}.options"), "need 2..=255 options");
            }
            let mut names = BTreeSet::new();
            for (i, option) in options.iter().enumerate() {
                let path = format!("{at}.options[{i}]");
                if !is_option_name(&option.name) {
                    err(format!("{path}.name"), "use [a-z0-9_], at most 64 bytes");
                }
                if !names.insert(option.name.as_str()) {
                    err(format!("{path}.name"), "duplicate option");
                }
                check_json_size(&option.description, &format!("{path}.description"), err);
                match option.outcome {
                    ChoiceOutcome::Match => {
                        if option.severity.is_none() || option.risk_points.is_none() {
                            err(path.clone(), "match options need severity and risk_points");
                        }
                        if option.risk_points.is_some_and(|r| r > 100) {
                            err(format!("{path}.risk_points"), "must be 0..=100");
                        }
                    }
                    _ => {
                        if option.severity.is_some() || option.risk_points.is_some() {
                            err(
                                path.clone(),
                                "only match options carry severity/risk_points",
                            );
                        }
                    }
                }
            }
            if !options.iter().any(|o| o.outcome == ChoiceOutcome::Match) {
                err(
                    format!("{at}.options"),
                    "at least one option must have outcome: match",
                );
            }
            if !options.iter().any(|o| {
                matches!(
                    o.outcome,
                    ChoiceOutcome::Review | ChoiceOutcome::InsufficientVisibility
                )
            }) {
                warnings.push(format!(
                    "{at}.options: no catch-all (review or insufficient_visibility) option"
                ));
            }
            if !unit(*min_confidence) {
                err(format!("{at}.min_confidence"), "must be within 0..=1");
            }
        }
        Question::Score {
            instructions,
            levels,
            match_at,
            clear_below,
            min_confidence,
            bands,
        } => {
            check_instructions(instructions, at, err);
            if !(2..=10).contains(&levels.len()) {
                err(format!("{at}.levels"), "need 2..=10 levels");
            }
            for (i, level) in levels.iter().enumerate() {
                let path = format!("{at}.levels[{i}]");
                check_json_size(level, &path, err);
                if level
                    .as_str()
                    .is_some_and(|s| s.trim().chars().all(|c| c.is_ascii_digit() || c == '.'))
                {
                    err(
                        path,
                        "describe a situation; bare numeric levels perform poorly",
                    );
                }
            }
            let top = levels.len().saturating_sub(1) as f64;
            let in_range = |v: f64| v.is_finite() && v >= 0.0 && v <= top;
            if !in_range(*match_at) || !in_range(*clear_below) || clear_below > match_at {
                err(
                    format!("{at}.match_at"),
                    "need 0 <= clear_below <= match_at <= top level",
                );
            }
            if !unit(*min_confidence) {
                err(format!("{at}.min_confidence"), "must be within 0..=1");
            }
            if bands.is_empty() {
                err(format!("{at}.bands"), "need at least one band");
            } else {
                if bands[0].at != *match_at {
                    err(format!("{at}.bands[0].at"), "must equal match_at");
                }
                for pair in bands.windows(2) {
                    if pair[1].at <= pair[0].at {
                        err(format!("{at}.bands"), "`at` must strictly increase");
                    }
                }
                for band in bands {
                    if !in_range(band.at) {
                        err(format!("{at}.bands"), "`at` must be within the level range");
                    }
                    if band.risk_points > 100 {
                        err(format!("{at}.bands"), "risk_points must be 0..=100");
                    }
                }
            }
        }
    }
}

fn check_instructions(value: &str, at: &str, err: &mut impl FnMut(String, &str)) {
    if value.trim().is_empty() || value.len() > MAX_INSTRUCTION_BYTES {
        err(format!("{at}.instructions"), "must be 1..=2048 bytes");
    }
}

fn check_json_size(value: &serde_json::Value, at: &str, err: &mut impl FnMut(String, &str)) {
    if serde_json::to_string(value).map_or(true, |s| s.len() > MAX_CRITERIA_BYTES) {
        err(at.into(), "must serialize to at most 8192 bytes");
    }
}

fn is_namespaced(value: &str) -> bool {
    is_detector_id(value)
        && value
            .strip_prefix(NAMESPACE)
            .and_then(|rest| rest.strip_prefix('.'))
            .is_some_and(|rest| !rest.is_empty())
}

fn is_option_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl Check {
    /// Metadata for results that are not matches: the most severe match outcome.
    pub fn base_outcome(&self) -> OutcomeDeclaration {
        let mut outcomes = self.match_outcomes();
        outcomes.sort_by_key(|o| (o.severity, o.risk_points));
        let top = outcomes
            .last()
            .copied()
            .expect("validated checks have a match outcome");
        OutcomeDeclaration {
            finding_kind: self.finding_kind,
            severity: top.severity,
            risk_points: None,
        }
    }

    /// Every (kind, severity, risk) a match result from this check can carry.
    pub fn match_outcomes(&self) -> Vec<OutcomeDeclaration> {
        let mut out = Vec::new();
        let mut push = |severity, risk: u8| {
            let declared = OutcomeDeclaration {
                finding_kind: self.finding_kind,
                severity,
                risk_points: Some(risk),
            };
            if !out.contains(&declared) {
                out.push(declared);
            }
        };
        match &self.question {
            Question::Predicate {
                severity,
                risk_points,
                ..
            } => push(*severity, *risk_points),
            Question::Choice { options, .. } => {
                for option in options {
                    if let (ChoiceOutcome::Match, Some(s), Some(r)) =
                        (option.outcome, option.severity, option.risk_points)
                    {
                        push(s, r);
                    }
                }
            }
            Question::Score { bands, .. } => {
                for band in bands {
                    push(band.severity, band.risk_points);
                }
            }
        }
        let review = review_outcome();
        if (self.uncertain == UncertainPolicy::Review || self.has_review_option())
            && !out.contains(&review)
        {
            out.push(review);
        }
        out
    }

    fn has_review_option(&self) -> bool {
        matches!(&self.question, Question::Choice { options, .. }
            if options.iter().any(|o| o.outcome == ChoiceOutcome::Review))
    }
}

/// Review results are informational threat-hunt leads with no risk.
pub fn review_outcome() -> OutcomeDeclaration {
    OutcomeDeclaration {
        finding_kind: FindingKind::ThreatHunt,
        severity: Severity::Informational,
        risk_points: Some(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "schema: telltale-systemone.guard-pack.v1\nid: systemone.test\nversion: 1\ntitle: t\nstatus: draft\nmodels: [jev-1.13.0]\nchecks:\n";

    fn check(body: &str) -> String {
        format!(
            "{HEADER}  - id: systemone.test.one\n    title: t\n    finding_kind: security_detection\n    applies_to: {{families: [tool]}}\n    state: action\n{body}"
        )
    }

    const PREDICATE: &str = "    question: {type: predicate, instructions: q, match_at: 0.8, clear_below: 0.3, severity: low, risk_points: 5}\n";

    fn errors(text: &str) -> Vec<String> {
        parse(text)
            .unwrap_err()
            .into_iter()
            .map(|e| e.to_string())
            .collect()
    }

    #[test]
    fn bundled_core_pack_is_valid() {
        let loaded = load_file(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packs/core.yaml"
        )))
        .unwrap();
        assert_eq!(loaded.pack.checks.len(), 5);
        assert!(loaded.digest.starts_with("sha256:"));
    }

    #[test]
    fn rejects_unknown_category_and_foreign_namespace() {
        let text = check(&format!("    category: vibes\n{PREDICATE}"));
        assert!(errors(&text).iter().any(|e| e.contains("ADR category")));
        let text = check(&format!("    category: execution\n{PREDICATE}"))
            .replace("systemone.test.one", "rule.one");
        assert!(
            errors(&text)
                .iter()
                .any(|e| e.contains("starting with `systemone.`"))
        );
    }

    #[test]
    fn rejects_unknown_fields_and_bare_numeric_levels() {
        let text = check(&format!(
            "    category: execution\n    surprise: 1\n{PREDICATE}"
        ));
        assert!(errors(&text)[0].contains("unknown field"));
        let text = check(
            "    category: execution\n    question:\n      type: score\n      instructions: q\n      levels: [\"0\", \"1\", \"2\"]\n      match_at: 1.0\n      clear_below: 0.5\n      bands: [{at: 1.0, severity: low, risk_points: 5}]\n",
        );
        assert!(errors(&text).iter().any(|e| e.contains("bare numeric")));
    }

    #[test]
    fn choice_needs_a_match_option_and_inverted_thresholds_fail() {
        let text = check(
            "    category: execution\n    question:\n      type: choice\n      instructions: q\n      options:\n        - {name: a, outcome: no_match}\n        - {name: b, outcome: review}\n",
        );
        assert!(errors(&text).iter().any(|e| e.contains("outcome: match")));
        let text = check(&format!(
            "    category: execution\n{}",
            PREDICATE.replace("clear_below: 0.3", "clear_below: 0.9")
        ));
        assert!(
            errors(&text)
                .iter()
                .any(|e| e.contains("clear_below <= match_at"))
        );
    }

    #[test]
    fn digest_ignores_key_order_and_yaml_whitespace() {
        let a = parse(&check(&format!("    category: execution\n{PREDICATE}"))).unwrap();
        let reordered = PREDICATE.replace(
            "type: predicate, instructions: q",
            "instructions: \"q\\n\", type: predicate",
        );
        let b = parse(&check(&format!("    category: execution\n{reordered}"))).unwrap();
        assert_eq!(a.digest, b.digest);
    }
}
