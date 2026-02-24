# Coverage 100% TODO

## Scope
- Goal: raise **core crate test coverage to 100%** for `cargo llvm-cov --package clavisvault-core --lib --summary-only` and then keep it stable.
- Date recorded: 2026-02-24
- Current measured baseline (from latest run):
  - Lines covered: 87.56% (4510 covered / 561 missed)
  - Functions covered: 79.16% (451 covered / 94 missed)
  - Top-lagging modules:
    - `crates/core/src/safe_file.rs` (`Lines 69.23%`, `Functions 56.86%`)
    - `crates/core/src/shell.rs` (`Lines 67.20%`, `Functions 66.67%`)
    - `crates/core/src/audit_log.rs` (`Lines 86.23%`, `Functions 80.00%`)
    - `crates/core/src/encryption.rs` (`Lines 87.58%`, `Functions 86.67%`)

## Why this is not already 100%
- In `safe_file.rs` and `shell.rs`, many lines are currently not exercised because these files still contain large trailing blank/testless blocks after the last test and non-deterministic OS-permission handling paths.
- Some branches are platform-restricted (Windows-only vs Unix-only) and are necessarily absent from a single platform run.

## Active TODOs

### 1) Establish baseline measurement artifact
- [ ] Create a reproducible coverage command set:
  - `cargo llvm-cov --package clavisvault-core --lib --summary-only`
  - `cargo llvm-cov --package clavisvault-core --lib --show-missing-lines`
  - `cargo llvm-cov --package clavisvault-core --lib --text --output-path target/coverage.txt`
- [ ] Add a short script in `scripts/` (if needed) to print per-file missed lines for each core file.
- [ ] Capture and version a baseline snapshot in `AGENTS/WORKLOG.md` “Evidence” when each sweep updates.

### 2) Remove non-code coverage debt
- [ ] Audit `crates/core/src/safe_file.rs`, `crates/core/src/shell.rs`, `crates/core/src/encryption.rs`, `crates/core/src/types.rs` for trailing dead lines/comments that provide no executable semantics.
- [ ] Trim trailing blank segments and non-code noise only when confirmed they are not part of intentional formatting contract.
- [ ] Re-run summary coverage after each cleanup commit.

### 3) Add missing branch/path tests where practical
- [ ] Fill remaining uncovered branches in:
  - `safe_file.rs`:
    - explicit backup-path allocation success/failure edge branches not yet deterministically asserted
    - restoration rollback failure branch in `atomic_write_with_fs_ops` with mocked restore failure
  - `audit_log.rs`:
    - `verify_ledger_integrity` branch coverage for mixed checkpoint retention invariants after partial corruption
    - `prune_for_retention` edge when both `max_entries` and `max_age_days` apply simultaneously
  - `encryption.rs`:
    - `unlock_with_password_or_biometric` branch when `cached_key` and `biometric` are both provided but hook fails before cached fallback
- [ ] Confirm branch tests use deterministic fixtures (no privileged/environment-dependent assertions without fallback handling).

### 4) Document untestable or conditionally testable paths
- [ ] Keep the following in-code coverage notes (already added in `safe_file.rs`):
  - `#[cfg(windows)]` file-lock and read-only path handling
  - `#[cfg(unix)]` permission-bit dependent tests
- [ ] For each future intentionally untestable branch, add an inline comment in the form:
  - `// COVERAGE NOTE: ... why it cannot be covered in this test environment ...`
- [ ] Include fallback assertions where environment privilege differences can make results non-deterministic.

### 5) Validate final target
- [ ] Verify core crate `--summary-only` is at 100% for lines and functions.
- [ ] Reconcile `just ci-fast` or project-mandated gate outputs to ensure no collateral regressions.

## Impossible / non-coverable items (by definition, with justification)
- `crates/core/src/safe_file.rs` Windows-only test paths under `#[cfg(windows)]`
  - Why: rely on Windows `OpenOptionsExt::share_mode` and Windows read-only attribute semantics that do not execute on Unix.
- `crates/core/src/safe_file.rs` Unix-only permission-bit tests under `#[cfg(unix)]`
  - Why: Unix mode-bit behavior and root-owned directory edge cases are unavailable on Windows.
- Permission-bypass branch handling in:
  - `permission_denied_is_reported` and `backup_empty_file_creation_reports_error_when_parent_is_read_only`
  - Why: write-denial behavior can vary on privileged CI/host runners; deterministic failure is not guaranteed, so assertions are intentionally tolerant.

## Ownership
- Primary owner: security / platform hardening owner
- Verification owner: core test maintainer

