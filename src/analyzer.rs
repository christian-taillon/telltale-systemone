//! Turns one `AnalysisInputV1` into one `AnalysisResultV1`: deterministic
//! applicability first, then at most one System One request per state
//! profile, then deterministic decisions. Every declared check returns exactly
//! one result; failures are explicit, never a clean result.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::config::Loaded;
use crate::decide::{self, Decision, Outcome};
use crate::egress;
use crate::pack::{self, Check, LoadedPack, Requirement, StateProfile, review_outcome};
use crate::protocol::*;
use crate::provider::Provider;
use crate::state::{self, SEMANTICS_VERSION};
use crate::systemone::{self, Request};

pub const EXTENSION_ID: &str = "telltale-systemone";
pub const ENGINE: &str = "systemone";
const MAX_REQUEST_BYTES: usize = 128 * 1024;

pub struct Analyzer {
    model: String,
    pinned_model: bool,
    packs: Vec<LoadedPack>,
    provider: Box<dyn Provider>,
    deadline: Duration,
    content_ref: String,
}

/// One request the analyzer would send, for `evaluate --print-requests`.
pub struct PlannedRequest {
    pub profile: StateProfile,
    pub request: Request,
    pub blocked_by: Option<&'static str>,
}

struct Pending<'a> {
    check: &'a Check,
    version: &'a str,
}

impl Analyzer {
    pub fn new(loaded: Loaded) -> Self {
        let content = serde_json::json!({
            "semantics_version": SEMANTICS_VERSION,
            "model": loaded.model,
            "packs": loaded.packs.iter().map(|p| p.digest.clone()).collect::<Vec<_>>(),
        });
        let content_ref = pack::sha256_hex(
            b"telltale-systemone:content:v1\0",
            pack::canonical_json(&content).as_bytes(),
        );
        Self {
            model: loaded.model,
            pinned_model: loaded.pinned_model,
            packs: loaded.packs,
            provider: loaded.provider,
            deadline: loaded.deadline,
            content_ref,
        }
    }

    pub fn default_deadline(&self) -> Duration {
        self.deadline
    }

    fn checks(&self) -> impl Iterator<Item = Pending<'_>> {
        self.packs.iter().flat_map(|p| {
            p.pack.checks.iter().map(move |check| Pending {
                check,
                version: &p.pack.version,
            })
        })
    }

    pub fn ready(&self) -> Ready {
        let mut uses = std::collections::BTreeSet::new();
        let detectors = self
            .checks()
            .map(|Pending { check, version }| {
                if check.applies_to.families.contains(&Family::Tool) {
                    uses.insert("tool_arguments");
                }
                if check.state == StateProfile::ActionWithContext
                    || check.applies_to.families.contains(&Family::Message)
                {
                    uses.insert("user_text");
                    uses.insert("assistant_text");
                }
                DetectorDeclaration {
                    id: check.id.clone(),
                    version: version.to_owned(),
                    category: check.category.clone(),
                    base: check.base_outcome(),
                    match_outcomes: check.match_outcomes(),
                    techniques: check.techniques.clone(),
                }
            })
            .collect();
        Ready {
            protocol: PROTOCOL.into(),
            capability: CAPABILITY.into(),
            extension: ExtensionInfo {
                id: EXTENSION_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            detector_namespace: pack::NAMESPACE.into(),
            semantics_version: SEMANTICS_VERSION,
            content_ref: self.content_ref.clone(),
            model: self.model.clone(),
            packs: self
                .packs
                .iter()
                .map(|p| PackRef {
                    id: p.pack.id.clone(),
                    version: p.pack.version.clone(),
                    digest: p.digest.clone(),
                })
                .collect(),
            detectors,
            disclosure_uses: uses.into_iter().map(String::from).collect(),
            egress: self.provider.egress(),
        }
    }

    /// The requests `analyze` would send for this input, without sending.
    pub fn plan(&self, input: &AnalysisInputV1) -> Vec<PlannedRequest> {
        let (_, groups) = self.gate(input);
        groups
            .into_iter()
            .map(|(profile, pending)| {
                let (request, blocked_by) = self.build_request(input, profile, &pending);
                PlannedRequest {
                    profile,
                    request,
                    blocked_by,
                }
            })
            .collect()
    }

    pub fn analyze(&self, input: &AnalysisInputV1, deadline: Instant) -> AnalysisResultV1 {
        let subject = input.subject.observation_id.as_str();
        let (mut done, groups) = self.gate(input);
        let mut usage = Usage::default();
        let mut answered_model = None;

        for (profile, pending) in groups {
            let (request, blocked_by) = self.build_request(input, profile, &pending);
            let fail_all = |done: &mut BTreeMap<String, CheckResult>,
                            result: &dyn Fn(&Pending) -> CheckResult| {
                for p in &pending {
                    done.insert(p.check.id.clone(), result(p));
                }
            };
            if let Some(pattern) = blocked_by {
                let code = format!("egress_guard_{pattern}");
                fail_all(&mut done, &|p| {
                    not_evaluated(
                        p,
                        NonEvaluationReason::IneligibleInput,
                        Some(diag(DiagnosticKind::UnavailableCapability, &code)),
                    )
                });
                continue;
            }
            let encoded = serde_json::to_vec(&request)
                .map(|b| b.len())
                .unwrap_or(usize::MAX);
            if encoded > MAX_REQUEST_BYTES {
                fail_all(&mut done, &|p| {
                    not_evaluated(
                        p,
                        NonEvaluationReason::IneligibleInput,
                        Some(diag(
                            DiagnosticKind::UnavailableCapability,
                            "request_too_large",
                        )),
                    )
                });
                continue;
            }
            let response = match self.provider.evaluate(&request, subject, deadline) {
                Ok(response) => response,
                Err(error) => {
                    fail_all(&mut done, &|p| detector_error(p, error.0));
                    continue;
                }
            };
            usage.requests += 1;
            usage.input_tokens += response.input_tokens;
            usage.output_tokens += response.output_tokens;
            if self.pinned_model && response.model != self.model {
                fail_all(&mut done, &|p| detector_error(p, "model_mismatch"));
                continue;
            }
            answered_model = Some(response.model.clone());

            for p in &pending {
                let questions = state::questions(p.check);
                let parsed: Result<Vec<_>, _> = questions
                    .iter()
                    .map(|(key, _, expect)| systemone::parse_answer(&response, key, expect))
                    .collect();
                let result = match parsed {
                    Err(error) => detector_error(p, error.code()),
                    Ok(answers) => match decide::decide(p.check, &answers[0], answers.get(1)) {
                        Err(error) => detector_error(p, error.0),
                        Ok(decision) => decided(p, subject, decision),
                    },
                };
                done.insert(p.check.id.clone(), result);
            }
        }

        let results = self
            .checks()
            .map(|p| done.remove(&p.check.id).expect("every check has a result"))
            .collect();
        AnalysisResultV1 {
            schema: RESULT_SCHEMA.into(),
            subject_observation_id: subject.into(),
            analyzer: AnalyzerIdentity {
                id: EXTENSION_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                engine: ENGINE.into(),
                content_ref: self.content_ref.clone(),
                semantics_version: SEMANTICS_VERSION,
                answered_model,
            },
            results,
            usage,
        }
    }

    /// Deterministic applicability and visibility. Returns finished results
    /// and the checks that need a model answer, grouped by state profile.
    fn gate<'a>(
        &'a self,
        input: &AnalysisInputV1,
    ) -> (
        BTreeMap<String, CheckResult>,
        BTreeMap<StateProfile, Vec<Pending<'a>>>,
    ) {
        let mut done = BTreeMap::new();
        let mut groups: BTreeMap<StateProfile, Vec<Pending<'a>>> = BTreeMap::new();
        for pending in self.checks() {
            match applicability(pending.check, input) {
                Gate::Proceed => groups.entry(pending.check.state).or_default().push(pending),
                Gate::NotApplicable => {
                    done.insert(
                        pending.check.id.clone(),
                        base_result(&pending, Status::NotApplicable),
                    );
                }
                Gate::NotEvaluated(reason) => {
                    done.insert(
                        pending.check.id.clone(),
                        not_evaluated(&pending, reason, None),
                    );
                }
            }
        }
        (done, groups)
    }

    fn build_request(
        &self,
        input: &AnalysisInputV1,
        profile: StateProfile,
        pending: &[Pending],
    ) -> (Request, Option<&'static str>) {
        let state = state::build_state(input, profile);
        let blocked_by = egress::scan(&serde_json::to_string(&state).unwrap_or_default());
        let questions: BTreeMap<String, Value> = pending
            .iter()
            .flat_map(|p| state::questions(p.check))
            .map(|(key, question, _)| (key, question))
            .collect();
        (
            Request {
                state,
                model: self.model.clone(),
                questions,
            },
            blocked_by,
        )
    }
}

enum Gate {
    Proceed,
    NotApplicable,
    NotEvaluated(NonEvaluationReason),
}

fn applicability(check: &Check, input: &AnalysisInputV1) -> Gate {
    let subject = &input.subject;
    let scope = &check.applies_to;
    if !scope.families.contains(&subject.family) {
        return Gate::NotApplicable;
    }
    if !scope.stages.is_empty() && !scope.stages.contains(&subject.stage) {
        return Gate::NotApplicable;
    }
    if !scope.tools.is_empty() {
        let named = subject
            .tool_name
            .as_deref()
            .is_some_and(|name| scope.tools.iter().any(|t| t.eq_ignore_ascii_case(name)));
        if !named {
            return Gate::NotApplicable;
        }
    }
    if !scope.native_categories.is_empty()
        && !input
            .native_findings
            .iter()
            .any(|f| scope.native_categories.contains(&f.category))
    {
        return Gate::NotApplicable;
    }
    for requirement in &check.requires {
        match requirement {
            Requirement::SubjectText if subject.facts.is_empty() => {
                return Gate::NotEvaluated(NonEvaluationReason::InsufficientVisibility);
            }
            Requirement::UserContext => {
                let present = input.context.iter().any(|e| {
                    e.offset < 0 && e.kind == ContextKind::UserMessage && e.text.is_some()
                });
                if !present {
                    let visibility = &input.visibility;
                    return Gate::NotEvaluated(match visibility.capabilities.user_context {
                        Availability::Unsupported => {
                            NonEvaluationReason::RequiredCapabilityUnsupported
                        }
                        _ if !visibility.disclosure.user_text => {
                            NonEvaluationReason::InsufficientVisibility
                        }
                        Availability::Unknown => NonEvaluationReason::RequiredCapabilityUnknown,
                        Availability::Supported => NonEvaluationReason::InsufficientVisibility,
                    });
                }
            }
            Requirement::SubjectText => {}
        }
    }
    Gate::Proceed
}

fn base_result(p: &Pending, status: Status) -> CheckResult {
    let base = p.check.base_outcome();
    CheckResult {
        detector_id: p.check.id.clone(),
        detector_version: p.version.to_owned(),
        status,
        non_evaluation_reason: None,
        observation_ids: Vec::new(),
        finding_kind: base.finding_kind,
        category: p.check.category.clone(),
        severity: base.severity,
        risk_points: None,
        confidence: None,
        confidence_score: None,
        tags: Vec::new(),
        techniques: p.check.techniques.clone(),
        evidence: Vec::new(),
        dedupe_key: None,
        diagnostic: None,
        assessment: None,
    }
}

fn diag(kind: DiagnosticKind, code: &str) -> Diagnostic {
    Diagnostic {
        kind,
        code: code.to_owned(),
    }
}

fn not_evaluated(
    p: &Pending,
    reason: NonEvaluationReason,
    diagnostic: Option<Diagnostic>,
) -> CheckResult {
    CheckResult {
        non_evaluation_reason: Some(reason),
        diagnostic,
        ..base_result(p, Status::NotEvaluated)
    }
}

fn detector_error(p: &Pending, code: &str) -> CheckResult {
    CheckResult {
        diagnostic: Some(diag(DiagnosticKind::RuntimeDetectorError, code)),
        ..base_result(p, Status::DetectorError)
    }
}

fn decided(p: &Pending, subject: &str, decision: Decision) -> CheckResult {
    let confidence = Some(decide::confidence_label(decision.confidence_score));
    let confidence_score = Some(round4(decision.confidence_score));
    let common = |status| CheckResult {
        observation_ids: vec![subject.to_owned()],
        confidence,
        confidence_score,
        evidence: vec![decision.evidence.clone()],
        assessment: Some(decision.assessment.clone()),
        ..base_result(p, status)
    };
    match decision.outcome {
        Outcome::Match {
            severity,
            risk_points,
        } => CheckResult {
            severity,
            risk_points: Some(risk_points),
            tags: vec!["systemone.match".into()],
            dedupe_key: Some(dedupe_key(&p.check.id, subject, "match")),
            ..common(Status::EvaluatedMatch)
        },
        Outcome::Review => {
            let review = review_outcome();
            CheckResult {
                finding_kind: review.finding_kind,
                severity: review.severity,
                risk_points: review.risk_points,
                tags: vec!["systemone.review".into()],
                dedupe_key: Some(dedupe_key(&p.check.id, subject, "review")),
                ..common(Status::EvaluatedMatch)
            }
        }
        Outcome::NoMatch => common(Status::EvaluatedNoMatch),
        Outcome::NotEvaluated(reason) => CheckResult {
            non_evaluation_reason: Some(reason),
            observation_ids: Vec::new(),
            ..common(Status::NotEvaluated)
        },
    }
}

/// Replay-stable, content-free identity for one outcome on one observation.
fn dedupe_key(detector: &str, subject: &str, outcome: &str) -> String {
    pack::sha256_hex(
        b"telltale-systemone:dedupe:v1\0",
        format!("{detector}\0{subject}\0{outcome}").as_bytes(),
    )
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}
