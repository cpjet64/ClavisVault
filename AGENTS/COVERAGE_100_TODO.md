# Coverage 100% TODO

## Goal
- Achieve and sustain **100% lines + functions** coverage for:
  - `cargo llvm-cov --package clavisvault-core --lib`
- Keep this plan as the single source of truth for coverage work until gates are green and stable.
- Rebaseline after every meaningful test addition before and after each commit.

## Evidence (as of 2026-02-24)
- Core coverage summary currently at:
  - Lines: 87.56% (4510 covered / 561 missed)
  - Functions: 79.16% (451 covered / 94 missed)
- Current top debt modules:
  - `crates/core/src/safe_file.rs` (Lines 69.23%, Functions 56.86%)
  - `crates/core/src/shell.rs` (Lines 67.20%, Functions 66.67%)
  - `crates/core/src/audit_log.rs` (Lines 86.23%, Functions 80.00%)
  - `crates/core/src/encryption.rs` (Lines 87.58%, Functions 86.67%)
- Source of truth for this doc trail should be `AGENTS/WORKLOG.md` and `AGENTS/COVERAGE_100_TODO.md`.

## Working assumption
- `core` is currently the highest-impact slice to unblock the project gate:
  - `cargo llvm-cov --package clavisvault-core --lib --fail-under-lines 95` must pass first.
  - Full 100% is only meaningful once the mandated gate is met and branch flake is controlled.

## Coverage Command Set (runbook)
- `cargo llvm-cov --package clavisvault-core --lib --summary-only`
- `cargo llvm-cov --package clavisvault-core --lib --show-missing-lines --output-path target/coverage-missing.txt`
- `cargo llvm-cov --package clavisvault-core --lib --text --output-path target/coverage.txt`
- Store any hard failures in `AGENTS/WORKLOG.md` "Evidence".

## TODO (priority order)

1. Make branch outcomes deterministic where possible
- [ ] Replace flaky assertions around permission-denied tests with structural checks that remain deterministic across Linux runner privilege modes.
- [ ] Add a minimal set of "must-fail" vs "may-pass" branches for Unix permission tests where writes can be bypassed by privileged runners.
- [ ] Keep coverage intent notes inline with `// COVERAGE NOTE ...`.

2. Close missing logic branches in `crates/core/src/safe_file.rs`
- [ ] Add/assert tests for `atomic_replace_path` candidate exhaustion and backup cleanup fallback behavior.
- [ ] Add explicit negative path for:
  - empty filename parent allocation failures.
  - restore failures after partial write swap succeeds.
- [ ] Ensure each uncovered path in `atomic_write_with_fs_ops` has deterministic test control.
- [ ] Verify `fn trim_backups` older-backup pruning is deterministic on malformed directory contents.

3. Close remaining debt in `crates/core/src/audit_log.rs`
- [ ] Add mixed-checkpoint retention edge-case coverage:
  - both `max_entries` and `max_age_days` apply in one pass,
  - `verify_ledger_integrity` after partial checkpoint corruption.
- [ ] Validate prune behavior when retention settings remove all but boundary checkpoint.

4. Close remaining debt in `crates/core/src/encryption.rs` and `crates/core/src/shell.rs`
- [ ] Add branch tests for authentication fallback order (cached + biometric + legacy) where behavior is currently unexercised.
- [ ] Add missing shell path for non-default env/permissions handling that currently lacks negative coverage.

5. Stabilize coverage-only assertions
- [ ] Expand in-code rationales for any branch that cannot be tested on one platform.
- [ ] For non-deterministic host-policy behavior, convert to dual-path assertions.
- [ ] Gate any host-sensitive tests behind explicit `cfg(unix)`/`cfg(windows)` and document why they are not universal.

6. Validate target gate
- [ ] Re-run summary-only coverage and verify:
  - 100.00% lines
  - 100.00% functions
- [ ] Reconcile `just ci-fast` and at minimum run `cargo clippy --all-targets --all-features -D warnings` after each atomic increment.

## Impossible / conditionally untestable items (must stay with explicit rationale)

- `crates/core/src/safe_file.rs`: Windows-only path semantics in `#[cfg(windows)]` tests
  - `backup_with_reserved_filename_reports_empty_file_error`:
    - This scenario is inherently Windows-specific because reserved/invalid filename characters are validated by Windows APIs before file creation; Unix test runners do not hit that path.
  - `atomic_write_revert_when_target_is_locked`:
    - Windows supports native shared-lock behavior via `OpenOptionsExt::share_mode`; lock failure here depends on Windows file-share flags, which do not exist in the same form on Unix platforms.
  - `atomic_write_over_readonly_file_succeeds`:
    - Read-only attribute transitions are implemented through Windows metadata semantics; Unix permission model is mode-bit based and this test is not meaningful there.
- `crates/core/src/safe_file.rs`: Unix-only path semantics in `#[cfg(unix)]` tests
  - `atomic_replace_path_rejects_path_without_filename`:
    - This validation is tied to Unix-style root-path edge cases and does not exist as the same runtime behavior on Windows.
- `crates/core/src/safe_file.rs`: Host-privilege-sensitive permission behavior
  - `permission_denied_is_reported` and
    `backup_empty_file_creation_reports_error_when_parent_is_read_only`
    - Permission-denied outcomes are influenced by runner privilege level (for example, elevated or permissive CI settings). These branches are covered structurally and intentionally allow both "hard deny" and "graceful passthrough" outcomes to keep the suite deterministic across environments.

## Completion criteria
- The TODO is complete only when every unchecked item here is done and the repository-level coverage artifact in `AGENTS/WORKLOG.md` is updated with a 100.00% snapshot.
