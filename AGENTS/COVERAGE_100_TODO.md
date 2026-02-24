# Coverage 100% TODO

## Goal
- Reach and sustain **100% line + function coverage** for:
  - `cargo llvm-cov --package clavisvault-core --lib`
- Maintain this file as the working execution plan for core coverage closure.
- Preserve correctness: add tests/fixtures where behavior is truly executable; only mark as impossible when behavior is platform/privilege constrained and proven non-portable.

## Current state (2026-02-24)
- Core summary:
  - Lines: `87.80%` (4,589 covered / 560 missed, as of latest `cargo llvm-cov`)
  - Functions: `79.48%` (458 covered / 94 missed, as of latest `cargo llvm-cov`)
- Largest debt files:
  - `crates/core/src/safe_file.rs` (Lines `69.23%`, Functions `56.86%`)
  - `crates/core/src/shell.rs` (Lines `70.49%`, Functions `70.00%`)
  - `crates/core/src/audit_log.rs` (Lines `86.23%`, Functions `80.00%`)
  - `crates/core/src/types.rs` (Lines `87.65%`, Functions `76.60%`)
  - `crates/core/src/encryption.rs` (Lines `87.58%`, Functions `86.67%`)

## Working assumption
- This is a **core IN-PROGRESS** cycle while the required core coverage gate remains unresolved.
- Coverage hardening should not be traded against semantics: only behaviorally safe tests and deterministic assertions can raise coverage.

## Runbook (required for every high-impact change)
- `cargo test -p clavisvault-core --lib`
- `cargo llvm-cov --package clavisvault-core --lib --summary-only`
- `cargo llvm-cov --package clavisvault-core --lib --show-missing-lines --output-path target/coverage-missing.txt`
- `cargo llvm-cov --package clavisvault-core --lib --fail-under-lines 95`
- `cargo clippy --all-targets --all-features -D warnings`

## TODO (priority order)

1. Reduce misses in shell surface generation first (lowest risk, high gain)
- [x] Add explicit coverage for `ShellKind::Zsh` in `shell_env_assignment` and `shell_session_token_file_snippets`.
- [ ] Add explicit coverage for full hook payload constants on all variants in `shell_session_clear_snippets`.
- [ ] Add explicit coverage for empty-value assignment semantics for `$Env:` (`shell_safe_pwsh_single_quote`) across all shells.
- [ ] Add explicit validation that `shell_session_token_file_snippets` and `shell_env_assignments` avoid outputting legacy `CLAVISVAULT_SESSION_TOKEN` in token file flows.

2. Expand deterministic branches in `crates/core/src/types.rs`
- [ ] Add tests for:
  - `default_created_at` fallback path for `timestamp_opt` edge behavior.
  - `migrate_in_place` behavior when version == `VAULT_VERSION` and when vault data already matches defaults.
  - `signer_matches_existing_key` for unknown key-id branch and explicit mismatch branch.
- [ ] Add assertions for all public constructors and drop-paths already validated by secret hygiene.

3. Close validation debt in policy/rotation
- [ ] Cover remaining `pattern_matches` wildcard and edge branches in `policy.rs`:
  - `pattern == "*"`, `""`, and non-object pattern fragments still show coverage misses.
- [ ] Cover rotation due/expired/healthy and no-policy branches with boundary-day assertions in `rotation.rs` for `warn_before_days` default and due threshold equality.

4. Cover `audit_log.rs` ledger/integrity and retention interactions
- [ ] Add tests for:
  - Partial checkpoint retention with both retention size and retention age trimming in one scenario.
  - Recovery path with `verify_ledger_integrity` after corrupting a prior hash link and an earlier operation type mismatch.
  - `should_lock` at exact timeout boundary and with repeated touches.

5. Cover encryption fallback branches
- [ ] Add missing tests for:
  - `unlock_with_password_or_biometric` with `password = Some("")` (explicit empty-string password branch).
  - Wrong-password path with cached key present (ensuring password remains highest priority).
  - `derive_master_key` failure handling if Argon2 parameter derivation/config fails in unusual salt/time conditions (guarded with deterministic fixture where feasible).

6. Finish `safe_file.rs` atomic write/error branches and privilege-sensitive determinism
- [ ] Cover deterministic non-error branches for backup name/path handling and backup write+readback restoration.
- [ ] Add explicit tests for `atomic_replace_path_with` candidate exhaustion and malformed `parent` paths where parent can be represented.
- [ ] Keep privileged-environment-conditional tests as dual-path asserts (`Err` vs `Ok`) to prevent flake.

7. Close remaining low-volume misses in small modules
- [ ] `openclaw.rs`: line-level branch near parse fallback and comment insertion.
- [ ] `project_linker.rs`: event-path and watcher collection edge branches.
- [ ] `recovery.rs`: missing export-read/report path combinations.

8. Gate and reconcile
- [ ] Re-run full summary + fail-under-lines after each file-level slice.
- [ ] Update `AGENTS/WORKLOG.md` evidence and this TODO’s completion marks until all checkboxes are done.
- [ ] Final pass: confirm all `COVERAGE NOTE` entries still match `target/coverage-missing.txt`.

## Impossible / conditionally untestable paths

### `crates/core/src/safe_file.rs` (annotate inline with `// COVERAGE NOTE`)
- `#[cfg(windows)]` paths around:
  - `backup_with_reserved_filename_reports_empty_file_error`
  - `atomic_write_revert_when_target_is_locked`
  - `atomic_write_over_readonly_file_succeeds`
  are executed only on Windows because they depend on native path-character validation, lock share modes, and readonly metadata semantics that differ from Unix. These APIs do not have a direct Unix equivalent and would produce false assumptions if simulated.

- `#[cfg(unix)]` path `atomic_replace_path_rejects_path_without_filename` exercises a Unix-root edge (`/`) that is not semantically equivalent on Windows path parsing.

- `permission_denied...` and `backup_empty_file_creation_reports_error_when_parent_is_read_only` are host-privilege-sensitive:
  they are covered with outcome-flexible assertions where CI privilege levels can legitimately bypass mode restrictions. These cannot be forced deterministically on all CI runners, so exact branch assertions must remain conditional.

### Non-core behavior and environment-sensitive verification assumptions
- If a path depends on platform event ordering or notification APIs (for example file-watcher startup events in `project_linker.rs`), assertions should be structural (no crash, path locality, event presence) instead of ordering-sensitive.
- If a code path requires mutable OS policy toggles we cannot set in CI (permission systems, read-only mount simulation), the plan requires explicit comments and dual assertions rather than hard-fail expectations.

### Required documentation
- Every new platform-sensitive test or assertion must be paired with one `COVERAGE NOTE` comment near the corresponding test explaining:
  1. Why this branch is not universally testable;
  2. Which environment/OS combinations were observed;
  3. Which assertions are accepted as equivalent outcomes.

## Completion criteria
- All non-impossible TODO items are complete.
- `AGENTS/WORKLOG.md` records `100.00%` line/function snapshots in Evidence once achieved.
- No false `#[cfg]`-only behavior is counted as fully covered without explicit `COVERAGE NOTE` justification.
