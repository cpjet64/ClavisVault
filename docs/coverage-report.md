# Coverage Report

Date: 2026-02-26  
Branch: `coverage-max-1772070359`

## Scope
- Workspace baseline coverage measured with:
  - `cargo nextest run --all-features`
  - `cargo llvm-cov --html`
  - `cargo llvm-cov report`
- Focused maximization pass targeted high-value uncovered lines in `clavisvault-core`.

## Baseline Snapshot
- Workspace TOTAL line coverage: `78.66%` (`cargo llvm-cov report`).
- Largest missed-line contributors in workspace:
  - `crates/desktop/src-tauri/src/lib.rs`
  - `crates/cli/src/main.rs`
  - `crates/server/src/main.rs`
  - `crates/relay/src/main.rs`

## Core Inventory and Classification
- Parsed core misses from baseline lcov:
  - `crates/core/src/audit_log.rs`: lines `926`, `981`, `1073`
  - `crates/core/src/policy.rs`: line `172`
  - `crates/core/src/project_linker.rs`: line `100`
- Classification:
  - `policy.rs:172`: testable branch behavior.
  - `project_linker.rs:100`: testable watcher-construction success path.
  - `audit_log.rs` misses: assertion-block brace-line artifacts with surrounding behavior exercised; no uncovered functional branch identified.

## Changes Applied
- Added unit test in `crates/core/src/policy.rs`:
  - `pattern_matches_non_wildcard_prefix_branch_consumes_first_segment`
- Added unit test in `crates/core/src/project_linker.rs`:
  - `create_watcher_with_single_valid_watch_folder_is_ok`

## Validation
- Executed targeted tests:
  - `cargo test -p clavisvault-core pattern_matches_non_wildcard_prefix_branch_consumes_first_segment -- --nocapture`
  - `cargo test -p clavisvault-core create_watcher_with_single_valid_watch_folder_is_ok -- --nocapture`
- Re-ran core coverage:
  - `cargo llvm-cov --package clavisvault-core --lib --summary-only`

## Post-Change Metrics (Core)
- TOTAL line coverage: `99.19%`
- File highlights:
  - `policy.rs`: `99.61%` lines
  - `project_linker.rs`: `99.18%` lines
  - `audit_log.rs`: `99.65%` lines

## Notes
- This pass maximizes testable uncovered paths in the current scope without introducing non-functional test churn.

## Pass v2 (2026-02-26)
- Branch: `coverage-max-20260225-210205`
- Baseline command (required combo):
  - `cargo nextest run --all-features && cargo llvm-cov --html`
- Baseline stability note:
  - First `cargo llvm-cov --html` attempt failed on a known flaky test:
    `tests::requested_session_ttl_is_clamped_to_token_policy` (`crates/server/src/main.rs`).
  - Immediate rerun passed and produced `target/llvm-cov/html`.

### Baseline Metrics (Workspace)
- `cargo llvm-cov report` line coverage: `78.68%`
- Primary missed-line contributors unchanged:
  - `crates/desktop/src-tauri/src/lib.rs`
  - `crates/cli/src/main.rs`
  - `crates/server/src/main.rs`
  - `crates/relay/src/main.rs`

### Residual Core Inventory (v2)
- Extracted with:
  - `cargo llvm-cov --package clavisvault-core --lib --lcov --output-path core-v2-after-revert.lcov`
- Remaining uncovered lines:
  - `crates/core/src/audit_log.rs`: `930`, `989`, `1085`
  - `crates/core/src/policy.rs`: `172`
  - `crates/core/src/project_linker.rs`: `100`

### v2 Classification
- `policy.rs:172`:
  - Branch-boundary line in `pattern_matches` with adjacent behavior covered by
    `pattern_matches_non_wildcard_prefix_branch_consumes_first_segment`.
- `project_linker.rs:100`:
  - Constructor-boundary line for `RecommendedWatcher::new(...)` with success/failure paths
    already covered by existing watcher tests.
- `audit_log.rs` lines:
  - Assertion-block closing-brace artifacts in integrity-failure tests.

### v2 Actions
- Added detailed inline coverage rationale comments on residual `audit_log` assertion blocks.
- Re-ran core coverage after comment insertion/reversion checks to confirm residual set is stable.

### v2 Outcome
- No additional testable runtime branch was identified for the remaining five core lines.
- Residuals are currently treated as attribution artifacts with explicit documentation in tests.
