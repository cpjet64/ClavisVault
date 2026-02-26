# Plan: regenerate-canonical-docs-set

## Objective
Recreate `docs/` as the single current documentation source after archival, using live codebase behavior and current CI/release tooling.

## Steps
1. Collect implementation facts from crates (`core`, `desktop`, `server`, `relay`, `cli`) and automation assets (`Justfile`, `.github/workflows/ci.yml`, `scripts/release.*`).
2. Author a complete docs suite:
   - `docs/README.md`
   - `docs/index.md`
   - `docs/SPEC.md`
   - `docs/ARCHITECTURE.md`
   - `docs/API.md`
   - `docs/TOOLING.md`
   - `docs/alerts.md`
3. Restore root `README.md` with a concise pointer to `docs/index.md`.
4. Update `docs/PROGRESS.md` with generation and verification entries.
5. Run `just ci-fast` then `just ci-deep`.
6. Commit the verified documentation change set locally.

## Constraints
- Keep scope to documentation and required tracker updates only.
- Preserve security invariants and avoid introducing behavioral/code changes.
- No push.
