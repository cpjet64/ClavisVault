# TODO / Plan

## Task: Coverage maximization pass (autonomous-coverage-maximizer)

- [x] Create safety branch `coverage-max-1772070359`.
- [x] Confirm language/tooling coverage surfaces and required commands.
- [x] Run baseline coverage with 2026 combo (`cargo nextest run --all-features && cargo llvm-cov --html`).
- [x] Generate uncovered lines/functions inventory per module.
- [x] Classify uncovered items: dead / placeholder / uncoverable / testable.
- [x] Add or extend tests for testable uncovered paths.
- [x] Re-run coverage and iterate until no meaningful gain remains.
- [x] Add detailed inline comments for any truly uncoverable code.
- [x] Update `docs/coverage-report.md` with before/after metrics and evidence.
- [x] Commit each verified coverage change set locally (no push).

## Review (in progress)

- Scope detected:
  - Rust workspace crates (`core`, `desktop`, `server`, `relay`, `cli`)
  - TypeScript desktop frontend/e2e sources present, but no Vitest test harness scripts currently defined.
- Coverage tools available:
  - `cargo-nextest 0.9.128`
  - `cargo-llvm-cov 0.8.4`
- Baseline full-workspace coverage snapshot (`cargo llvm-cov report` after full run):
  - TOTAL line coverage: `78.66%`
  - Largest missed-line contributors: `desktop/src-tauri/lib.rs`, `cli/main.rs`, `server/main.rs`, `relay/main.rs`
- Core uncovered-line inventory (from `coverage-baseline.lcov` parsing):
  - `audit_log.rs`: lines `926`, `981`, `1073`
  - `policy.rs`: line `172`
  - `project_linker.rs`: line `100`
- Classification:
  - `policy.rs:172`: testable branch-path tail in wildcard matcher, covered by new unit test.
  - `project_linker.rs:100`: testable watcher creation happy-path, covered by new unit test.
  - `audit_log.rs` misses are non-functional brace-line artifacts in assertion blocks with surrounding logic exercised.
- New tests added:
  - `policy::tests::pattern_matches_non_wildcard_prefix_branch_consumes_first_segment`
  - `project_linker::tests::create_watcher_with_single_valid_watch_folder_is_ok`
- Iteration result (`cargo llvm-cov --package clavisvault-core --lib --summary-only`):
  - Core TOTAL line coverage: `99.19%`
  - `policy.rs` line misses down to 2; `project_linker.rs` line misses down to 4; both target lines now covered.
- Required integration gates (pre-commit):
  - `just ci-fast`: PASSED
  - `just ci-deep`: PASSED
- Local commit completed:
  - `490355d` `test[core]: cover residual policy and watcher branches`
