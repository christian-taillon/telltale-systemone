# telltale-systemone agent instructions

Reference `analyzer.v1` extension for Telltale. Keep it small and honest.

- Telltale (`../telltale`, a sibling checkout) may be edited from here when the
  change is within Telltale's accepted scope and follows Telltale's `AGENTS.md`.
  Keep context where it belongs: Telltale changes stay generic (`analyzer.v1`,
  canonical observations, selectors), with no plugin names, paths, or
  dependencies in its code, schemas, tests, or docs. Plugin-specific rationale
  stays in this repository.
- Dependency direction is one-way. Telltale never depends on
  telltale-systemone or on any other plugin. Plugins depend on Telltale's public
  contracts only. Put this repo's name in Telltale only if Telltale itself needs
  to refer to a plugin, and that should not happen.
- Record Telltale host-side proposals in `docs/telltale-host.md` and keep them
  as direction until Telltale accepts the scope.
- The wire contract is `src/protocol.rs` + `schemas/`. Change both together,
  and bump the schema string for any incompatible change.
- Changing state layout, the evidence note, or question encoding means
  bumping `SEMANTICS_VERSION` in `src/state.rs`.
- Fixtures are synthetic. Never commit real transcripts, live answers from
  private sessions, or API keys. `examples/fixture-answers.json` is hand-written,
  not Jev output; keep that label.
- Do not call the live TypeSafe API from tests.
- Label claims as existing capability, validated observation, current
  experiment, proposed extension, or open question. Never describe the
  analyzer as integrated with Telltale until Telltale ships the host side.
- Checks: `cargo fmt --check && cargo clippy --all-targets && cargo test`.
  The bridge builds separately: `cd bridge && cargo build`.

## PR scope and Git workflow

Use one owning branch and PR for a coherent plugin outcome. Keep its protocol,
schema, implementation, related fixes, synthetic tests, and documentation together
as meaningful commits. Reuse that PR for review corrections; a worker, session,
task, or commit does not require a separate PR, and there is no commit-count quota.

Split for independent shipping or rollback, a materially different risk/approval
boundary, or an incoherent review. Do not accumulate unrelated work or move
plugin-specific changes into Telltale to combine PRs. Host-side changes retain
Telltale's accepted scope and its own repository review and publication boundary.

Independent concurrent writers use isolated worktrees and one integration owner.
Run focused checks while developing and required checks on the integrated result;
worker-local passes do not qualify a different final revision. Batch authorized
pushes at useful checkpoints. Preserve signing, ignored files, required checks,
and human merge approval. This grants no additional commit, push, PR, merge,
release, live-model access, or deployment authority.
