# telltale-systemone agent instructions

Reference `analyzer.v1` extension for Telltale. Keep it small and honest.

- Telltale (`../telltale`) is read-only from here. Do not edit it. Its host-side
  work needs accepted scope there; record proposals in `docs/telltale-host.md`.
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
