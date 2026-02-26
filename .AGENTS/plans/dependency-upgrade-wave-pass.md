# Plan: dependency-upgrade-wave-pass

## Objective
Upgrade dependencies in the current repository using conservative waves, preserve compatibility, and verify with full gates.

## Scope
- Repository: `C:\Dev\repos\active\ClavisVault`
- Stacks detected: Rust workspace + desktop Node/TypeScript package.

## Waves
1. Baseline + risk planning
   - Build inventory of toolchains/dependencies and current gates.
   - Capture upgrade strategy and rollback notes in `docs/dependency-upgrade-report.md`.
2. Rust dependency wave (conservative)
   - Apply lockfile-compatible updates (`cargo update`) without widening manifest version constraints.
   - Validate with stack + security gates.
3. Node dependency wave (conservative)
   - Apply lockfile-compatible updates (`npm update` in `crates/desktop`).
   - Rebuild desktop frontend and rerun global gates.
4. Final verification and reporting
   - Run `just ci-fast` and `just ci-deep`.
   - Summarize changed dependencies, validation outcomes, and residual risk in report.
   - Commit each verified wave locally (no push).

## Risk controls
- No major-version manifest jumps unless required for security and validated.
- Keep rollback path via per-wave local commits.
- Stop and report if upgrade introduces unresolved gate failures.
