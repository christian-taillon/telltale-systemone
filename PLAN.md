# Plan

## Now: plugin-side authoring (no Telltale dependency)

Ordered. Each changes the pack schema; bump it to `guard-pack.v2` once, not per item.

1. **Deterministic prefilter.** `where:` on a check using Telltale's
   `observation_match` condition grammar over projected facts. No model call
   unless it holds. Lint rejects unknown fields and operators.
2. **Per-check state includes.** Replace the closed `state` enum with
   `state: {include: [action, user_request, context_window, policy:<id>, runtime, agent]}`.
   A missing include gives `not_evaluated` with the matching reason, not a
   smaller state. Bumps `SEMANTICS_VERSION`.
3. **Reusable policies.** Pack-level `policies:` (prose rules, allowlists),
   referenced by ID and placed in state next to the action.
4. **Composition.** A check may combine other checks' outcomes
   deterministically (all/any/not, score thresholds). The combination runs in
   code, not in the question.
5. **Pack tests.** `telltale-systemone test <pack>` runs labeled synthetic
   cases with expected outcomes; `evaluate --record` saves live answers on
   synthetic inputs as fixtures, keyed by case name rather than observation ID.

## Next

- Labeled synthetic corpus, then tune `core` thresholds and move it to `evaluated`.
- Check whether the evidence note (`about_the_state`) changes answers on
  injected-instruction cases.
- Telltale work is a draft 13-tranche series kept outside this repository;
  summary in [docs/telltale-host.md](docs/telltale-host.md#proposed-telltale-work). When
  its projection core ships: drop `bridge/`, consume `telltale.analysis-input.v2`,
  and make `assessment` a neutral annotations field.
- Analysis redaction profile with Token Guard (Telltale tranche 6).
- Confirm whether other System One models exist and accept the same request
  shape. The TypeSafe docs list only `jev-1.13.0` (2026-10-07).

## Blocked

- Mode A over real local session stores. Needs explicit approval to read real
  transcripts and send their redacted projection to TypeSafe.
- System/developer prompt, agent role, runtime, and tool-result checks. Need
  Telltale tranches 7–10. Reasoning checks are not planned: Telltale retains
  no raw reasoning.
