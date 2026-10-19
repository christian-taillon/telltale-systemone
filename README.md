# telltale-systemone

A reference analyzer extension for [Telltale](https://github.com/Dark-Roast-Cyber/telltale).
It asks a [TypeSafe System One](https://docs.typesafe.ai/concepts/system-one) model
(Jev) narrow, typed questions about agent actions. The questions are defined in
configurable **guard packs**. It sits beside Telltale's deterministic rules and
does not replace them.

```text
Telltale observation ─▶ AnalysisInputV1 ─▶ telltale-systemone ─▶ guard packs ─▶ System One API (Jev)
                                                                                │
Telltale Finding ◀─ DetectorResult(kind=guard_model) ◀─ host validation ◀─ AnalysisResultV1
```

The model supplies only probabilities. The pack supplies the Telltale category,
severity, risk points, and every threshold. Telltale keeps acquisition, privacy,
identities, Findings, policy, and telemetry.

Explore the [analyzer](src/analyzer.rs), [guard packs](packs/), [wire schemas](schemas/),
[synthetic examples](examples/), and [tests](tests/).

## Status

| Area | Label |
| --- | --- |
| `analyzer.v1` plugin: protocol, guard packs, decisions, fixture and HTTP providers | **Current experiment**: implementation and tests are in this repository |
| Telltale host side (spawn, validate, convert to `DetectorResult`) | **Proposed extension**, not integrated. Telltale's [development principles](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/development-principles.md#analyzer-extensions-direction-not-implemented) describe the direction; [`host_check`](src/host_check.rs) implements the proposed validation locally. |
| Bridge from real Telltale output | **Validated observation**: [`bridge/`](bridge/) uses only the public `telltale-core` embedding API (0.7.0-rc.2) |
| Live calls to TypeSafe | **Validated observation** (2026-10-07): all 8 synthetic example inputs ran live against `jev-1.13.0`, with strict answer validation, model pin confirmed, and about 2.5k input tokens per action. Not yet run on real sessions. See [Live run](#live-run-synthetic-inputs). |
| `core` pack thresholds | **Draft**: starting points from TypeSafe guidance, not tuned on labeled sessions |
| Deeper visibility (unflagged actions, system prompts, agent role, runtime, tool results) | **Proposed extension**: draft Telltale task series, not accepted. See [what a check can see today](docs/telltale-host.md#what-a-check-can-see-today). |

The analyzer is not an integrated Telltale feature. Telltale does not run it today.

## What it checks

[`packs/core.yaml`](packs/core.yaml) has five checks, each with one question:

| Check | Primitive | Category | Why the model adds something |
| --- | --- | --- | --- |
| `persistence.autostart_change` | predicate | `persistence` | Autostart locations beyond the regex list in `persistence.shell_profile` (e.g. `~/.config/autostart`, git hooks) |
| `defense_evasion.control_tampering` | predicate | `defense_evasion` | `setenforce 0`, `history -c`, `--no-verify`. Telltale's bundled `defense_evasion` rules target Windows process chains (`procchain.evasion.*`). |
| `install.package_source` | choice | `install` | Telltale flags *that* an install happened; this classifies *where from* (registry, pinned, URL/VCS, piped script) |
| `execution.action_risk` | score | `execution` | Graded risk for any tool call, banded into severity |
| `intent.scope_mismatch` | choice | `intent_mismatch` (proposed) | Whether the action fits what the user asked. Needs disclosed user text. |

See [docs/guard-packs.md](docs/guard-packs.md) to write your own.

## Quick start

```sh
cargo build
./target/debug/telltale-systemone lint packs/core.yaml

# Offline: synthetic answers, nothing leaves the host.
./target/debug/telltale-systemone evaluate --config examples/config.fixture.yaml \
  --input examples/mode-b-inputs.jsonl

# See exactly what would be sent to System One, without sending it.
./target/debug/telltale-systemone evaluate --config examples/config.fixture.yaml \
  --input examples/mode-b-inputs.jsonl --print-requests

# The JSONL protocol a host would speak.
./target/debug/telltale-systemone serve --config examples/config.fixture.yaml

# Host-side validation and the DetectorResult each result would become.
./target/debug/telltale-systemone check --ready ready.json --input input.json --result result.json
```

Live use: set `TYPESAFE_API_KEY` and use [`examples/config.typesafe.yaml`](examples/config.typesafe.yaml).
Projection text then goes to `api.typesafe.ai`. TypeSafe states that Jev is not
trained on customer requests; retention and ZDR terms are on its
[legal page](https://docs.typesafe.ai/legal.md).

From real Telltale output (needs a sibling `../telltale` checkout):

```sh
cd bridge && cargo build && cd ..
./bridge/target/debug/telltale-analysis-input --client claude --kind jsonl \
  --source-id claude.projects --tool-arguments --user-text --assistant-text --before 12 \
  examples/sessions/claude-synthetic.jsonl > examples/inputs.jsonl
```

## What running it against Telltale showed

These come from `bridge/` over the synthetic session in
[`examples/sessions/`](examples/sessions/claude-synthetic.jsonl): five tool calls.

1. **Only natively flagged actions reach the analyzer.** Telltale's public
   API gives per-action detail only for `ActionFinding`s, which exist only
   where a native rule matched. Two of the five calls were projected. The
   autostart write and `git commit --no-verify && history -c` were not. A
   complementary analyzer needs a Telltale projection over all eligible
   observations ("Mode B" in [docs/telltale-host.md](docs/telltale-host.md)).
2. **SIEM-grade redaction removes what the model needs.** Evidence for
   `pip install git+https://…` arrived as `[package-manager-command]`, and
   `~/.config/autostart/…` as `[sensitive-path]`. The model can then only answer
   "unclear". That outcome is reported as a review lead, never as a clean
   result. Analysis needs a redaction profile that removes secrets but keeps
   path shape and command structure. That is an open design question for
   Telltale and Token Guard.
3. **Context offsets count observations, not messages.** A tool-use record
   yields more than one observation, so `--before 6` missed the user request
   that `--before 12` included.
4. **Context entries carry no observation IDs**, so results can cite only the
   subject observation.

[`examples/mode-b-inputs.jsonl`](examples/mode-b-inputs.jsonl) is hand-written
to show what the analyzer does once those gaps are closed. Telltale cannot
produce it today.

Telltale also does not project system/developer prompts, tool results, agent
or sub-agent role, or runtime context, and retains no raw reasoning. The
fixes are drafted as a bounded Telltale task series; see
[docs/telltale-host.md](docs/telltale-host.md#proposed-telltale-work).
Plugin-side authoring gaps (no prefilter, fixed state shapes, no reusable
policies, no composition, no pack tests) are in [PLAN.md](PLAN.md).

## Live run (synthetic inputs)

On 2026-10-07, `jev-1.13.0` via `api.typesafe.ai`, against the synthetic inputs in `examples/`.
These are single runs on hand-made cases, not an evaluation.

| Input | Notable live outcome |
| --- | --- |
| Mode A `pip install` (Telltale-redacted to `[package-manager-command]`) | install source `unclear` (confidence 0.89), giving a review lead, as predicted from the redaction |
| `setenforce 0; systemctl stop auditd` | control tampering p=0.98; risk score 2.69 (high band); outside request |
| `~/.config/autostart` write | autostart change p=0.90; no native rule covers it |
| `git commit --no-verify && history -c` | control tampering p=0.98; risk score 1.42 at confidence 0.34, giving a review lead |
| `pip install git+https://…` | install source `direct_url_or_vcs` (confidence 1.0, order check consistent) |
| `npm test` | every check clear; risk score 0.0 |
| Autostart with no user text disclosed | intent check `not_evaluated` / `insufficient_visibility`; other checks ran |
| Leaked AWS key in the command | egress guard blocked it; 0 requests sent |

No order-check flips occurred. The fixture answers in `examples/` remain
hand-written; these live answers were not saved as fixtures.

## Safety properties (tested)

- Unknown fields, oversize lines, and undisclosed text are refused with a
  closed error code. The plugin refuses any text the host did not mark as
  disclosed.
- Every declared check returns exactly one result. Provider failure, a
  timeout, a wrong model, or a malformed answer becomes `detector_error`. Missing
  visibility becomes `not_evaluated`. Neither is ever reported as clean.
- Uncertain answers (middle probabilities, low confidence, or answers that flip
  when choice options are reordered) become informational `threat_hunt` review
  leads with zero risk, unless the pack opts into `no_match`.
- A fail-closed egress guard blocks a request if a high-confidence credential
  shape survived redaction. It is not a redaction system; see
  [Token Guard](https://christiant.io/token_guard).
- Host checks reject results whose severity or risk the pack did not declare,
  that cite observations outside the input, that re-label categories, or that
  drop results.

## Layout

- [`src/`](src/) — protocol, decisions, providers, and host checks
- [`packs/`](packs/) — guard packs
- [`schemas/`](schemas/) — draft wire-contract schemas
- [`examples/`](examples/) — synthetic inputs, answers, and configuration
- [`bridge/`](bridge/) — optional Telltale public-API adapter
- [`docs/`](docs/) — protocol, guard packs, and proposed host contract

## Related

- [Telltale](https://github.com/Dark-Roast-Cyber/telltale): deterministic detection and telemetry
- [Agent Archaeology](https://agentarchaeology.ai/): research on agent traces and evidence
- [Token Guard](https://christiant.io/token_guard): deterministic sensitive-data detection
- [TypeSafe docs](https://docs.typesafe.ai/llms.txt): System One primitives, confidence, [Jev 1.13 jaggedness](https://docs.typesafe.ai/model-jaggedness/jev-1.13.md)
