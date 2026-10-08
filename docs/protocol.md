# Protocol: `telltale-extension-v1`, capability `analyzer.v1`

**Proposed extension.** Telltale records this as direction, not implementation:
Telltale `docs/development-principles.md`, "Analyzer extensions (direction, not implemented)", on the unpublished branch `prep/0.7-embedding-contract`.
This repository implements the extension side. Schemas are in [`../schemas/`](../schemas/).

## Transport

- The host starts the extension as a child process. No shared libraries, no Rust ABI.
- UTF-8 JSON, one object per `\n`-terminated line, at most 1 MiB per line.
- stdin carries host messages and stdout carries extension messages. stderr
  carries only closed diagnostic codes (for example
  `telltale-systemone: provider provider_overloaded attempt=1`), never content.
  The host may log stderr but must not parse it.
- Requests are handled one at a time, in order.

## Messages

| Direction | `type` | Purpose |
| --- | --- | --- |
| host → ext | `hello` | `protocol`, `capabilities` (must contain `analyzer.v1`), optional `host`, optional `limits.deadline_ms` (per request, 100..600000) |
| ext → host | `ready` | Identity and binding declarations (below) |
| host → ext | `analyze` | `id` (opaque, no whitespace or `/`) and `input` (`AnalysisInputV1`) |
| ext → host | `result` | Same `id`, `result` (`AnalysisResultV1`) |
| ext → host | `error` | `code`, optional `id`, optional `reason` (closed token) |
| host → ext | `shutdown` | Extension exits 0. EOF does the same. |

Error codes: `invalid_json`, `line_too_long`, `invalid_hello`,
`unsupported_protocol`, `hello_required`, `invalid_request_id`,
`invalid_input` (with `reason`, e.g. `subject.facts.disclosure`),
`unsupported_message`. After `invalid_hello` or `unsupported_protocol` the
extension exits 2. Other errors leave the session usable.

### `ready` is binding

`ready` declares everything the host later enforces:

- `detector_namespace`: every detector ID starts with `<namespace>.`, so an
  extension cannot impersonate native rule IDs.
- `detectors[]`: `id`, `version`, `category`, `base` (metadata for non-match
  results), and `match_outcomes` (every `finding_kind`/`severity`/`risk_points`
  combination a match may carry).
- `content_ref`: a digest over the semantics version, model, and pack digests.
  Results must repeat it.
- `model`: the requested model ID.
- `disclosure_uses`: which disclosure classes the checks use.
- `egress`: destinations that receive projection text (empty for the fixture provider).

A host can refuse to start an extension whose `egress` or `disclosure_uses`
the operator has not approved.

## `AnalysisInputV1`

A projection Telltale builds. It is not a Telltale internal structure.

```json
{
  "schema": "telltale.analysis-input.v1",
  "subject": {
    "observation_id": "obs:v2:sha256:…",
    "family": "tool", "stage": "requested",
    "occurred_at": "2026-10-01T10:00:30Z", "tool_name": "Bash",
    "facts": [{"field": "command", "text": "bash -c 'sudo setenforce 0; …'"}]
  },
  "context": [{"offset": -7, "kind": "user_message", "stage": "observed", "text": "Add a pre-commit lint step…"}],
  "native_findings": [{"finding_id": "fnd:v2:sha256:…", "detector_id": "execution.shell", "category": "execution", "severity": "low", "risk_points": 15}],
  "visibility": {
    "source": "claude.projects", "coverage": "whole_source",
    "capabilities": {"tool_call": "supported", "tool_execution": "unknown", "user_context": "supported"},
    "disclosure": {"user_text": true, "assistant_text": true, "tool_arguments": true},
    "redaction": "telltale.redact_sensitive_text"
  }
}
```

Rules the extension enforces (refusal gives `invalid_input` with the field as `reason`):

- `family`/`stage` use Telltale's spellings, and the stage must be valid for
  the family.
- Facts: at most 8, each 1..4096 bytes. Fields are `command`, `arguments`,
  `file_path` (`tool_arguments` disclosure), `user_message` (`user_text`), and
  `assistant_message` (`assistant_text`).
- Context: at most 64 entries, offset in −32..32 and not 0, text ≤ 512 bytes.
  Tool results never appear (`result_returned` is refused), matching
  Telltale's same-pass context.
- Total text ≤ 64 KiB.
- **Text is refused for any class whose disclosure flag is false.** The host
  states the disclosure, and the extension holds it to that statement.
- `redaction` must be `telltale.redact_sensitive_text`. This is a declaration,
  not proof.
- No source paths, raw references, local evidence handles, or session IDs. An
  unknown field fails the whole input.

## `AnalysisResultV1`

One result per declared detector, in declaration order:

```json
{
  "schema": "telltale.analysis-result.v1",
  "subject_observation_id": "obs:v2:sha256:…",
  "analyzer": {"id": "telltale-systemone", "version": "0.1.0", "engine": "systemone",
               "content_ref": "sha256:…", "semantics_version": 1, "answered_model": "jev-1.13.0"},
  "results": [{
    "detector_id": "systemone.persistence.autostart_change", "detector_version": "0.1.0",
    "status": "evaluated_match", "observation_ids": ["obs:v2:sha256:…"],
    "finding_kind": "security_detection", "category": "persistence", "severity": "medium",
    "risk_points": 35, "confidence": "high", "confidence_score": 0.88,
    "tags": ["systemone.match"], "techniques": ["attack:TA0003"],
    "evidence": ["classification:predicate.yes"], "dedupe_key": "sha256:…",
    "assessment": {"primitive": "predicate", "probability": 0.94}
  }],
  "usage": {"requests": 2, "input_tokens": 0, "output_tokens": 0}
}
```

Statuses and reasons are Telltale's exact Detection v2 vocabulary
(`evaluated_match`, `evaluated_no_match`, `not_applicable`, `not_evaluated`,
`detector_error`, and the seven `not_evaluated` reasons).

| Situation | Status |
| --- | --- |
| Family, stage, tool, or native-category filter excludes the subject | `not_applicable` |
| Required text or user context missing (disclosure off, capability unsupported or unknown) | `not_evaluated` with the matching reason |
| Egress guard hit, request over 128 KiB | `not_evaluated` / `ineligible_input` + diagnostic |
| Model answers "the state cannot tell" (pack option `insufficient_visibility`) | `not_evaluated` / `insufficient_visibility` |
| Provider error, timeout, deadline, model mismatch, malformed answer | `detector_error` + diagnostic code |
| Clear yes | `evaluated_match` with pack metadata |
| Uncertain (middle band, low confidence, order-check flip) | `evaluated_match`, `threat_hunt`/`informational`/risk 0, tag `systemone.review`. Or `evaluated_no_match` if the pack sets `uncertain: no_match`. |
| Clear no | `evaluated_no_match` |

`assessment` is model output and should be stored with `inferred` provenance.
`evidence` holds only Telltale `classification:` tokens, never excerpts.
`dedupe_key` is a domain-separated SHA-256 over detector, subject, and
outcome, so a review lead and a later match do not collide.

Diagnostic codes: `provider_timeout`, `provider_unavailable`,
`provider_overloaded`, `provider_auth`, `provider_rejected_request`,
`provider_invalid_response`, `provider_missing_answer`,
`provider_wrong_answer_type`, `provider_invalid_answer`, `model_mismatch`,
`deadline_exceeded`, `fixture_miss`, `order_check_answer_missing`,
`request_too_large`, `egress_guard_<pattern>`.

## Versioning

- A wire change bumps the schema string (`…v2`). There is no silent extension.
- A change to state layout, the evidence note, or question encoding bumps
  `SEMANTICS_VERSION` in [`src/state.rs`](../src/state.rs). That changes `content_ref`.
- A pack change changes its digest and therefore `content_ref`.

## Known v1 limits (proposed for v2)

- Facts are Rule v1 compatibility fields, not canonical selectors.
- One subject per request; context entries have no observation IDs, so results
  cite only the subject.
- `visibility.capabilities` covers three context kinds; no instruction,
  tool-result, agent, or runtime classes.
- `assessment` is System One-shaped. A generic analyzer would need a neutral
  annotations field.
- The schemas live here. Under the Telltale draft series they move to
  Telltale as `telltale.analysis-input.v2`
  ([telltale-host.md](telltale-host.md#proposed-telltale-work)).
