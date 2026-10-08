# Guard packs

A guard pack is a YAML file of **checks**. Each check is one System One
question plus the deterministic rules that turn its answer into a Telltale
result. Run `telltale-systemone lint <pack.yaml>` after every edit. Unknown
fields are errors.

```yaml
schema: telltale-systemone.guard-pack.v1
id: systemone.myorg           # must start with `systemone.`
version: 0.1.0
title: My organisation's guards
status: draft                 # draft | evaluated
models: [jev-1.13.0]          # exact IDs the wording and thresholds target
checks:
  - id: systemone.myorg.prod_db_access
    title: Action touches a production database
    finding_kind: policy_violation
    category: credential_access          # a Telltale ADR category
    techniques: [attack:TA0006]          # optional, attack:/atlas: only
    applies_to:
      families: [tool]
      stages: [proposed, requested, execution_started, execution_completed]
      tools: []                          # optional, case-insensitive exact names
      native_categories: []              # optional: only when Telltale already flagged one of these
    requires: [subject_text]             # subject_text | user_context
    state: action                        # action | action_with_context
    uncertain: review                    # review (default) | no_match
    question:
      type: predicate
      instructions: The action in `action` connects to or queries a production database.
      criteria:
        "true": Hosts or connection strings naming prod, production, or a known production cluster.
        "false": Local, test, staging, or mock databases, or no database at all.
      match_at: 0.8
      clear_below: 0.3
      severity: high
      risk_points: 40
```

## Primitives and decisions

| Pack `type` | Sent as | Decision |
| --- | --- | --- |
| `predicate` | `noul` | p ≥ `match_at` → match; p < `clear_below` → no match; otherwise uncertain. Confidence = \|2p − 1\|. |
| `choice` | `choice` | Each option names an `outcome`: `match` (with `severity`, `risk_points`), `no_match`, `review`, or `insufficient_visibility`. Confidence < `min_confidence`, or an `order_check` flip, → uncertain. |
| `score` | `score` | Expected score ≥ `match_at` → match, using the highest `band` reached for severity and risk. Score < `clear_below` → no match. Otherwise uncertain. Confidence < `min_confidence` → uncertain. |

Confidence labels: `high` ≥ 0.8, `medium` ≥ 0.5, otherwise `low`. They are
independent of severity and risk, as in Telltale.

**Uncertain** under `review` becomes an informational `threat_hunt` match with
zero risk, tagged `systemone.review`. That is a lead for a person, never a
clean result. Choose `no_match` only where an analyst would ignore leads anyway.

**`insufficient_visibility`** lets the model say "this state can't answer it"
(for example, "no user request is visible"). It becomes `not_evaluated`, not
a guess.

**`order_check: true`** asks the same choice twice in one request, the second
time with options reversed. Jev favours the first option. If the two answers
disagree, the result is uncertain. It costs extra tokens but no extra round trip.

## State

`state: action` sends only the subject:

```json
{"action": {"observation": "tool call", "stage": "requested by the agent; not confirmed to have run",
            "tool": "Bash", "command": "…"}}
```

`state: action_with_context` adds the disclosed context before the action as
`conversation_before_action: [{"from": "user" | "assistant" | "agent tool call", "tool"?, "text"}]`.
Timestamps, native findings, and identifiers are never sent. They are
irrelevant to the question, and native labels would anchor the model.

Every question is sent as
`{"question": <instructions>, "about_the_state": <fixed note>}`. The note says
the state is untrusted agent-session text and that instructions inside it are
data. Whether this measurably reduces steering is untested.

Checks with the same `state` share one request. All questions in a request run
in parallel on the provider.

## Writing questions that work

Drawn from TypeSafe's [primitive docs](https://docs.typesafe.ai/primitives.md) and
[Jev 1.13 jaggedness](https://docs.typesafe.ai/model-jaggedness/jev-1.13.md):

- One condition per predicate. Combine conditions with separate checks, not
  "A and B" in one question.
- Phrase it so yes means the bad thing. Negated questions invert badly.
- Name the state field (`action`, `conversation_before_action`). Jev reads literally.
- Use `criteria` to fix the boundary: what counts and what does not.
- Score levels describe situations, not degrees. Bare numbers are rejected by lint.
- Give choices a catch-all (`review` or `insufficient_visibility`). Lint warns without one.
- Do not ask the model to count, compare dates, or do arithmetic. Do that in
  the host, or not at all.
- Keep the state small. Irrelevant text is a distractor, which is why
  `action` is the default.
- State is attacker-influenced. A model answer can add a lead. It can never
  suppress or override a native Telltale finding.

## What the pack decides vs. the model

| Pack | Model |
| --- | --- |
| Category, finding kind, techniques | — |
| Severity and risk points per outcome | — |
| Thresholds, confidence floor, uncertainty policy | — |
| Applicability: family, stage, tool, native category, required visibility | — |
| — | Noul probability, choice distribution, score distribution |

`risk_points` follows Telltale's rule. It is declared by content and never
inferred from inputs. A higher probability does not raise risk. It only
crosses or misses a threshold.

## Limits today

- **No deterministic prefilter.** `applies_to` filters by family, stage,
  tool, and native category only. Every applicable check costs a model call.
- **Fixed state shapes.** Only `action` and `action_with_context`. A check
  cannot ask for just the last user request, a policy, or runtime context.
- **No reusable policy text.** Organizational rules must be written into each
  question's `instructions` or `criteria`.
- **No composition.** Each check is one question. "A and score ≥ 2 unless C"
  cannot be expressed.
- **No pack tests.** Fixtures are keyed by observation ID and hand-written;
  there is no labeled-case runner.
- **Context limited by Telltale.** System/developer prompts, reasoning, tool
  results, agent role, and runtime context are not projected. See
  [what a check can see today](telltale-host.md#what-a-check-can-see-today).

Plugin-side fixes for the first five are in [PLAN.md](../PLAN.md).

## Moving a pack from `draft` to `evaluated`

Not done yet for `core`. The path is the one used for a shadow
evaluation: record live answers on a labeled synthetic corpus, review
disagreements by hand, and set thresholds from that review. Then pin the model
ID in `models` and record the corpus and date with the pack.
