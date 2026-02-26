# TODO / Plan

## Task: Regenerate canonical project documentation set

- [x] Read governance files (`AGENTS.md`) and available spec context (`legacy/docs/SPEC.md` after docs reset).
- [x] Rebuild planning artifacts for this pass (`.AGENTS/todo.md` + `.AGENTS/plans` entry).
- [x] Synthesize architecture and behavior details from all workspace crates (`core`, `desktop`, `server`, `relay`, `cli`) plus CI/release scripts.
- [x] Generate fresh docs set in `docs/`:
  - `README.md`
  - `index.md`
  - `SPEC.md`
  - `ARCHITECTURE.md`
  - `API.md`
  - `TOOLING.md`
  - `alerts.md`
- [x] Restore root `README.md` as a docs pointer.
- [x] Update `docs/PROGRESS.md` with completed generation log.
- [x] Run `just ci-fast`.
- [x] Run `just ci-deep`.
- [ ] Commit verified documentation change set locally (no push).

## Review

- `just ci-fast`: PASSED.
- `just ci-deep`: PASSED.
- Quality gates, coverage, security policy checks, and docs build completed successfully in this pass.
