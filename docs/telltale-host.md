# Telltale host side

**Proposed extension.** None of this exists in Telltale. It describes what
Telltale would need for analyzer results to come back as ordinary Findings.
It is written so it can be lifted into a Telltale OpenSpec change once the
scope is accepted. [`src/host_check.rs`](../src/host_check.rs) implements the
validation rules so they can be tested now.

Governing Telltale material (the analyzer section and the embedding "analyzer provenance"
note are on the unpublished Telltale branch `prep/0.7-embedding-contract`, not yet on `main`):
Telltale `docs/development-principles.md`, "Analyzer extensions (direction, not implemented)", on the unpublished branch `prep/0.7-embedding-contract`,
[Detection v2](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/detection-v2.md)
(`guard_model` is a reserved detector kind that "may enter only through
DetectorResult/imported normalization and never gains Decision or Action authority"),
and the [privacy model](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/privacy-model.md).

## Pieces Telltale would own

1. **Projection.** Build `AnalysisInputV1` from canonical observations. The
   operator chooses the disclosure classes, and they default to off.
2. **Supervision.** Spawn the configured command, send `hello`, and read
   `ready`. Refuse to continue if `egress` or `disclosure_uses` exceed what the
   operator approved. Enforce `deadline_ms` per request and kill the process
   on timeout. Restart a bounded number of times.
3. **Validation.** Apply every rule below before anything becomes a
   `DetectorResult`.
4. **Conversion.** Map validated results into `DetectorResult → Signal →
   Finding`, with analyzer provenance.
5. **Isolation from native detection.** Analyzer work runs after native
   evaluation and projection. It never changes native results, never gates
   acquisition progress or cursor commits, and never delays native output.

## Two projection modes

| Mode | Source | Status |
| --- | --- | --- |
| A | `ActionFinding` + same-pass context from `Pipeline::scan_*_detailed` | **Validated observation**: [`bridge/`](../bridge/) builds it with the public API today |
| B | Every eligible Tool observation (`proposed`..`execution_completed`), flagged or not | **Proposed extension**: needs new projection code in Telltale |

Mode A only assesses actions a native rule already matched. That makes it
triage: a second opinion, reclassification, intent checks. Mode B is what
complements signatures. In the bridge run, the autostart write and
`--no-verify && history -c` were never projected, because no native rule matched them.

## Validation rules (host)

Reject the whole result when any rule fails, and record every declared detector
as `detector_error` with code `analyzer_result_invalid`:

- `schema`, `subject_observation_id`, `content_ref`, `semantics_version`
  match the input and the `ready` message.
- `answered_model` equals the pinned `ready.model` unless the model is an alias.
- Exactly one result per declared detector, in declaration order, with
  matching `detector_id`, `detector_version`, and `category`.
- `not_evaluated` ⇔ a reason from Telltale's closed set.
- `evaluated_match` cites ≥ 1 observation. `not_applicable`, `not_evaluated`,
  and `detector_error` cite none. Every cited ID was in the input (v1: the
  subject only).
- A match's `(finding_kind, severity, risk_points)` is one of the detector's
  declared `match_outcomes`. Non-matches carry exactly the declared `base` and
  no risk. An extension cannot escalate at runtime.
- Techniques are a subset of the declared techniques. Evidence holds
  `classification:` tokens only. Tags, dedupe keys, and diagnostic codes follow
  Telltale's identifier grammars and bounds (`MAX_TAGS` 32, `MAX_EVIDENCE_REFS` 16).
- `detector_error` carries a diagnostic.

## Conversion to Detection v2

| `AnalysisResultV1` | Telltale |
| --- | --- |
| — | `DetectorIdentity::new(DetectorKind::GuardModel, detector_id)` |
| `detector_version` | `.with_version(…)` |
| `analyzer.engine` + `answered_model` | `.with_engine("systemone:jev-1.13.0")` |
| `analyzer.content_ref` | `.with_content_ref("sha256:…")` |
| `status`, `non_evaluation_reason` | `EvaluationStatus`, `NonEvaluationReason` (same spellings) |
| `observation_ids` | `DetectorResult::evaluated_match(…, &[ObservationId])` |
| `finding_kind`, `category`, `severity` | `FindingMetadata::new(…)` |
| `risk_points`, `confidence`, `confidence_score` | `.with_risk_points`, `.with_confidence`, `.with_confidence_score` |
| `tags`, `techniques` | `.with_tags`, `.with_techniques` |
| `evidence[]` | `EvidenceReference::classification(…)` |
| `dedupe_key` | `.with_dedupe_key` / semantic identity |
| `diagnostic` | `Diagnostic` (kinds `runtime_detector_error`, `unavailable_capability`, `malformed_content_or_package`) |
| session scope | from the host's own observation record, never from the extension |
| `assessment` | analyzer audit record, `inferred` provenance. Not a `DetectorResult` field. |

Only `evaluated_match` materializes a Signal, and the default atomic Finding
follows. Extension failure is recorded per detector and never becomes
`evaluated_no_match`.

`check` prints this mapping for a result:

```text
DetectorResult kind=guard_model id=systemone.persistence.autostart_change version=0.1.0
  engine=systemone:jev-1.13.0 content_ref=sha256:c667… status=evaluated_match finding_kind=security_detection
  category=persistence severity=medium risk_points=35 confidence=high -> Signal + atomic Finding
```

## What a check can see today

Against Telltale 0.7.0-rc.2 (read-only inspection plus the bridge run):

| Context | Today | Why | Telltale tranche |
| --- | --- | --- | --- |
| Tool call | Yes, lossy | Rule v1 compatibility evidence, SIEM-redacted; arguments not structured | 2, 6 |
| Unflagged tool calls | No | `ActionFinding`s exist only where a native rule matched | 4 |
| User's last prompt | Sometimes | Only if it falls inside an observation-counted window | 5 |
| System / developer prompt | No | COv2 keeps `System`/`Developer` roles (Codex, inference), but action context has only user, assistant, tool call | 7 |
| Reasoning | No, by design | Telltale retains no raw reasoning; assistant messages are the only substitute | 1 (decision only) |
| Tool results | No | Same-pass context excludes them | 10 |
| Agent role, sub-agent | No | `delegation_id` exists in COv2; no adapter sets it | 8 |
| Runtime (sandbox, approval, privilege) | No | `runtime.*` selectors exist; no source emits Runtime observations | 9 |
| Source capabilities | No | Not on `ActionFinding`; the bridge sends `unknown` | 2 |
| Native findings | ID, category, severity, risk | No rule explanation | — |
| Policy text | Plugin side | Pack authors write it into `instructions`/`criteria`; see [PLAN.md](../PLAN.md) | — |

## Other gaps

| Gap | Evidence | Telltale tranche |
| --- | --- | --- |
| `guard_model` is not runtime-supported | `DetectorKind::runtime_supported()` covers only `observation_match` and `process_chain` | 3 |
| Analyzer provenance not designed | `ActionFinding::detector_kind()` and finding kind are "closed string vocabularies until analyzer provenance is designed" (`docs/embedding.md`) | 3 |
| Context entries lack observation IDs | `ActionContextEntry` has offset, kind, stage, time, tool, text | 2 |
| `intent_mismatch` is not an ADR category | `docs/threat-taxonomy.md` | 1 |
| Scan-time network egress | Telltale is "offline at scan time" (`docs/embedding.md`) | 1, 3 |
| No result cache | Re-scans would re-bill and could answer differently | 11 |
| No conformance kit for third-party extensions | `host_check` here is the only executable form of the rules | 12 |
| Output surface | Event 3.0 is frozen | 13 |

## Proposed Telltale work

A 13-tranche draft task series for Telltale is kept in the Telltale maintainer's
local workspace and is not published. Nothing in it is accepted. The direction it
relies on is in Telltale's development principles (unpublished branch above).

Order: decisions (1) → projection core replacing `bridge/` (2) → host,
validation, `guard_model` import (3) → all eligible observations (4). Context
tranches 5–10 then run in any order. The schema moves to Telltale as
`telltale.analysis-input.v2` with selector-keyed facts; this repository then
consumes it.
