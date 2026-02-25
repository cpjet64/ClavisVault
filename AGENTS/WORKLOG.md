# Now
- Keep improving in-progress status: raise clavisvault-core library coverage to satisfy
  `cargo llvm-cov --package clavisvault-core --lib --fail-under-lines 95`.
- Continue coverage-focused work in `audit_log`, `encryption`, `openclaw`, `policy`, and
  `project_linker` from current `--show-missing-lines` evidence.
- Preserve the `collect_events` debounce-window correctness fix and keep `ci-fast` green
  while coverage work continues.

# Next
- Add the next test-only coverage slice in the highest-gap files.
- Re-run:
  - `cargo test -p clavisvault-core --lib`
  - `cargo llvm-cov test --package clavisvault-core --lib --fail-under-lines 95`
  - `cargo llvm-cov test --package clavisvault-core --lib --show-missing-lines`
- Repeat until the 95% gate passes.

# Later
- Review any remaining misses for low-risk cleanup.
- Re-run full target checks from repository gate scripts if present and clean.

# Done
- Classified repository as IN-PROGRESS from fresh gates.
- Ran `just ci-fast`; first failed at `cargo fmt --check`.
- Ran `cargo fmt` and re-ran `just ci-fast`; then failed at clippy with two test lints.
- Fixed clippy issues in:
  - `crates/core/src/audit_log.rs` (`unnecessary_to_owned`)
  - `crates/core/src/project_linker.rs` (`needless_borrows_for_generic_args`)
- Re-ran `just ci-fast`; isolated one failing nextest case:
  `project_linker::tests::collect_events_disregards_events_arriving_after_debounce_window`.
- Fixed real debounce-boundary bug in `ProjectLinker::collect_events` by clamping receive
  timeout to remaining debounce window.
- Re-ran targeted project_linker tests for both late-event rejection and follow-up event
  collection paths (PASS).
- Re-ran `just ci-fast` to clean pass (fmt/lint/build/test all green).
- Re-ran core coverage gate:
  `cargo llvm-cov test --package clavisvault-core --lib --fail-under-lines 95`
  -> FAIL at 92.70% line coverage.
- Re-ran `cargo llvm-cov test --package clavisvault-core --lib --show-missing-lines`
  and refreshed uncovered-line focus areas.
- Re-ran baseline validation from previous pass.
- Confirmed no functional stubs blocking build in core target files.
- Confirmed all core library tests pass after fixing `audit_log::tests::prune_for_retention_filters_checkpoints_before_ledger_floor`.
- Added coverage-focused tests for `crates/core/src/openclaw.rs`, including comment stripping
  with comment-like tokens inside quoted strings.
- Added coverage-focused tests for `crates/core/src/policy.rs` around leading/trailing
  wildcard edge behavior.
- Added coverage-focused tests for `crates/core/src/project_linker.rs` to cover watcher success
  and case-insensitive `agents.md` discovery.
- Added coverage-focused tests for `crates/core/src/encryption.rs` for attempt limiter windows
  and backoff saturation.
- Added a coverage-focused `audit_log` test for hash-mismatch detection in chain verification.
- Added `AGENTS/WORKLOG.md` planning update in this pass and documented the remaining
  `openclaw`, `policy`, `project_linker`, `audit_log`, and `encryption` miss profile.
- Re-ran full coverage and confirmed misses remain at 92.70% line coverage.

# Decisions Needed
- None currently.

# Evidence
- `just ci-fast` now passes clean after debounce + clippy fixes.
- `cargo llvm-cov test --package clavisvault-core --lib --fail-under-lines 95`
  currently fails at 92.70% line coverage.
- `cargo llvm-cov test --package clavisvault-core --lib --show-missing-lines` currently
  flags remaining gaps in: `audit_log.rs`, `encryption.rs`, `openclaw.rs`, `policy.rs`,
  `project_linker.rs`.

# Assumptions
- Existing unit-test style is acceptable for adding branch coverage.
- No functional bug fix required; objective is coverage uplift to satisfy threshold.
- Remaining misses are branch coverage in non-error happy-path-heavy code paths and are safe to address via targeted tests.
