//! Host-side validation: the checks Telltale must apply before an analyzer
//! result becomes a `DetectorResult`. This is the executable form of
//! `docs/telltale-host.md`; Telltale itself does not implement it yet.

use std::collections::BTreeSet;

use crate::config::is_model_alias;
use crate::protocol::*;

pub fn check_ready(ready: &Ready) -> Vec<String> {
    let mut v = Vec::new();
    if ready.protocol != PROTOCOL {
        v.push("ready.protocol: unsupported".into());
    }
    if ready.capability != CAPABILITY {
        v.push("ready.capability: unsupported".into());
    }
    if !is_detector_id(&ready.detector_namespace) || ready.detector_namespace.contains('.') {
        v.push("ready.detector_namespace: must be a single lowercase segment".into());
    }
    if !is_prefixed_digest(&ready.content_ref, "sha256:") {
        v.push("ready.content_ref: must be sha256:<64 hex>".into());
    }
    if !is_opaque(&ready.model) {
        v.push("ready.model: invalid".into());
    }
    let prefix = format!("{}.", ready.detector_namespace);
    let mut ids = BTreeSet::new();
    for d in &ready.detectors {
        if !is_detector_id(&d.id) || !d.id.starts_with(&prefix) {
            v.push(format!(
                "ready.detectors[{}]: id must be inside the declared namespace",
                d.id
            ));
        }
        if !ids.insert(d.id.as_str()) {
            v.push(format!("ready.detectors[{}]: duplicate", d.id));
        }
        if !is_opaque(&d.version) {
            v.push(format!("ready.detectors[{}].version: invalid", d.id));
        }
        if !is_bounded_text(&d.category, MAX_CATEGORY_BYTES) {
            v.push(format!("ready.detectors[{}].category: invalid", d.id));
        }
        if d.match_outcomes.is_empty()
            || d.match_outcomes
                .iter()
                .any(|o| o.risk_points.is_none_or(|r| r > 100))
        {
            v.push(format!(
                "ready.detectors[{}].match_outcomes: need declared risk 0..=100",
                d.id
            ));
        }
        if d.techniques.iter().any(|t| !is_technique(t)) || d.techniques.len() > MAX_TECHNIQUES {
            v.push(format!("ready.detectors[{}].techniques: invalid", d.id));
        }
    }
    if ready.detectors.is_empty() || ready.detectors.len() > MAX_RESULTS {
        v.push("ready.detectors: need 1..=64".into());
    }
    for uses in &ready.disclosure_uses {
        if !matches!(
            uses.as_str(),
            "user_text" | "assistant_text" | "tool_arguments"
        ) {
            v.push(format!("ready.disclosure_uses: unknown class `{uses}`"));
        }
    }
    for destination in &ready.egress {
        if !destination.starts_with("https://") {
            v.push("ready.egress: destinations must be https".into());
        }
    }
    v
}

pub fn check_result(
    ready: &Ready,
    input: &AnalysisInputV1,
    result: &AnalysisResultV1,
) -> Vec<String> {
    let mut v = Vec::new();
    if result.schema != RESULT_SCHEMA {
        v.push("result.schema: unsupported".into());
    }
    if result.subject_observation_id != input.subject.observation_id {
        v.push("result.subject_observation_id: does not match the input".into());
    }
    if result.analyzer.content_ref != ready.content_ref
        || result.analyzer.semantics_version != ready.semantics_version
    {
        v.push("result.analyzer: content identity differs from the handshake".into());
    }
    if let Some(model) = &result.analyzer.answered_model
        && !is_model_alias(&ready.model)
        && model != &ready.model
    {
        v.push("result.analyzer.answered_model: differs from the pinned model".into());
    }
    if result.results.len() != ready.detectors.len() {
        v.push("result.results: need exactly one result per declared detector".into());
    }
    // Observations this result may cite. Context entries carry no IDs in v1.
    let allowed: BTreeSet<&str> = [input.subject.observation_id.as_str()].into();

    for (index, (r, d)) in result.results.iter().zip(&ready.detectors).enumerate() {
        let at = format!("result.results[{index}]");
        if r.detector_id != d.id || r.detector_version != d.version {
            v.push(format!(
                "{at}: detector identity does not match declaration order"
            ));
            continue;
        }
        if r.category != d.category {
            v.push(format!("{at}.category: differs from the declaration"));
        }
        match (r.status, r.non_evaluation_reason) {
            (Status::NotEvaluated, None) => v.push(format!("{at}: not_evaluated needs a reason")),
            (Status::NotEvaluated, Some(_)) => {}
            (_, Some(_)) => v.push(format!("{at}: only not_evaluated carries a reason")),
            _ => {}
        }
        match r.status {
            Status::EvaluatedMatch => {
                if r.observation_ids.is_empty() {
                    v.push(format!("{at}: a match needs supporting observations"));
                }
                let outcome = OutcomeDeclaration {
                    finding_kind: r.finding_kind,
                    severity: r.severity,
                    risk_points: r.risk_points,
                };
                if !d.match_outcomes.contains(&outcome) {
                    v.push(format!(
                        "{at}: kind/severity/risk not declared for this detector"
                    ));
                }
            }
            status => {
                if r.finding_kind != d.base.finding_kind
                    || r.severity != d.base.severity
                    || r.risk_points.is_some()
                {
                    v.push(format!(
                        "{at}: non-match metadata must equal the declared base"
                    ));
                }
                if matches!(
                    status,
                    Status::NotApplicable | Status::NotEvaluated | Status::DetectorError
                ) && !r.observation_ids.is_empty()
                {
                    v.push(format!("{at}: non-evaluated results cite no observations"));
                }
                if status == Status::DetectorError && r.diagnostic.is_none() {
                    v.push(format!("{at}: detector_error needs a diagnostic"));
                }
            }
        }
        if r.observation_ids
            .iter()
            .any(|id| !allowed.contains(id.as_str()))
        {
            v.push(format!(
                "{at}.observation_ids: cites an observation outside the input"
            ));
        }
        if r.techniques.len() > MAX_TECHNIQUES
            || r.techniques.iter().any(|t| !d.techniques.contains(t))
        {
            v.push(format!("{at}.techniques: not declared"));
        }
        if r.tags.len() > MAX_TAGS || r.tags.iter().any(|t| !is_detector_id(t)) {
            v.push(format!("{at}.tags: invalid"));
        }
        if r.evidence.len() > MAX_EVIDENCE || r.evidence.iter().any(|e| !is_classification(e)) {
            v.push(format!(
                "{at}.evidence: only classification tokens are accepted"
            ));
        }
        if r.dedupe_key.as_deref().is_some_and(|k| !is_opaque(k)) {
            v.push(format!("{at}.dedupe_key: invalid"));
        }
        if r.confidence_score
            .is_some_and(|s| !s.is_finite() || !(0.0..=1.0).contains(&s))
        {
            v.push(format!("{at}.confidence_score: outside 0..=1"));
        }
        if r.diagnostic
            .as_ref()
            .is_some_and(|diag| !is_detector_id(&diag.code))
        {
            v.push(format!("{at}.diagnostic.code: invalid"));
        }
        if let Some(assessment) = &r.assessment {
            let unit = |p: &f64| p.is_finite() && (0.0..=1.0).contains(p);
            let ok = match assessment {
                Assessment::Predicate { probability } => unit(probability),
                Assessment::Choice {
                    probabilities,
                    confidence,
                    ..
                } => unit(confidence) && probabilities.values().all(unit),
                Assessment::Score {
                    score,
                    probabilities,
                    confidence,
                } => score.is_finite() && unit(confidence) && probabilities.values().all(unit),
            };
            if !ok {
                v.push(format!("{at}.assessment: values outside 0..=1"));
            }
        }
    }
    v
}

/// How a validated result maps onto Telltale's Detection v2 path.
pub fn detector_result_preview(result: &AnalysisResultV1) -> Vec<String> {
    let engine = match &result.analyzer.answered_model {
        Some(model) => format!("{}:{model}", result.analyzer.engine),
        None => result.analyzer.engine.clone(),
    };
    result
        .results
        .iter()
        .map(|r| {
            let status = serde_json::to_value(r.status).unwrap();
            let mut line = format!(
                "DetectorResult kind=guard_model id={} version={} engine={} content_ref={} status={}",
                r.detector_id,
                r.detector_version,
                engine,
                result.analyzer.content_ref,
                status.as_str().unwrap()
            );
            if let Some(reason) = r.non_evaluation_reason {
                line.push_str(&format!(" reason={}", serde_json::to_value(reason).unwrap().as_str().unwrap()));
            }
            if let Some(d) = &r.diagnostic {
                line.push_str(&format!(" diagnostic={}", d.code));
            }
            if r.status == Status::EvaluatedMatch {
                line.push_str(&format!(
                    " finding_kind={} category={} severity={} risk_points={} confidence={} -> Signal + atomic Finding",
                    serde_json::to_value(r.finding_kind).unwrap().as_str().unwrap(),
                    r.category,
                    serde_json::to_value(r.severity).unwrap().as_str().unwrap(),
                    r.risk_points.unwrap_or(0),
                    r.confidence
                        .map(|c| serde_json::to_value(c).unwrap().as_str().unwrap().to_owned())
                        .unwrap_or_else(|| "none".into()),
                ));
            } else {
                line.push_str(" -> no Signal");
            }
            line
        })
        .collect()
}
