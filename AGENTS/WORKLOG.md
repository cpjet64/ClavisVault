# Now
- Implementing Phase-0 GUI verification path for the desktop app (unlock → add key → lock) with
  Playwright + Tauri launch and deterministic test IDs.
- Verifying the first canonical Phase-0 in-app flow pass and updating canonical evidence files
  (`EXECUTION-PLAN.md`, `MASTER-CHECKLIST.md`).

# Next
- Run optional persistence smoke:
  - `CLAVIS_E2E_PERSISTENCE_SMOKE=1 npm --prefix crates/desktop run test:e2e`
- Expand optional GUI assertions for copy/delete/rotate paths after flow stability is confirmed.
- Capture flaky-window cleanup evidence after repeated GUI runs.

# Later
- Expand E2E coverage with optional input-validation and copy/delete/rotate action tests.
- Capture optional CI hardening for other platforms after Windows pass (`.github/workflows/ci.yml`).

# Done
- Phase-0 unlock/add/key-count flow is now addressable via UI test IDs:
  - `unlock-form`, `master-password-input`, `unlock-button`, `lock-button`, `lock-status-indicator`,
    `last-action-message`, `search-input`, `key-name-input`, `key-description-input`,
    `key-tags-input`, `key-secret-input`, `save-key-button`, `key-row`, `vault-key-count`,
    `copy-key-button`, `delete-key-button`, `rotate-key-button`.
- Desktop test automation scaffolding added:
  - `crates/desktop/playwright.config.ts`
  - `crates/desktop/tests/e2e/global.setup.ts`
  - `crates/desktop/tests/e2e/global.teardown.ts`
  - `crates/desktop/tests/e2e/desktop-flow.spec.ts` with unlock/add/lock + persistence smoke.
- Added GUI data-root overrides for E2E in `crates/desktop/src-tauri/src/lib.rs` via
  `CLAVIS_E2E_HOME`/`CLAVIS_E2E_TEMP_DIR`.
- Optional Windows GUI E2E CI job added to `.github/workflows/ci.yml` (`desktop-gui-e2e`).
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
- Executed and passed desktop GUI E2E gate commands for phase-0:
  - `npm --prefix crates/desktop run build`
  - `npm --prefix crates/desktop run test:e2e:install`
  - `npm --prefix crates/desktop run test:e2e` (1 passed, 1 skipped persistence smoke)
- Ran full `just ci-fast` after GUI changes (pass).

# Decisions Needed
- None currently.

# Evidence
- Phase-0 GUI E2E harness and specs are implemented in `crates/desktop/tests/e2e/*.ts` and
  wired through `playwright.config.ts`.
- E2E environment isolation added in `global.setup.ts` for HOME/profile/app data/temp paths.
- `just ci-fast` now passes clean after debounce + clippy fixes.
- Recorded GUI flow command evidence on 2026-02-25:
  - `npm --prefix crates/desktop run build` (pass)
  - `npm --prefix crates/desktop run test:e2e:install` (pass)
  - `npm --prefix crates/desktop run test:e2e` (pass, 1 passed, 1 skipped)
  - `just ci-fast` (pass, 377 tests)
- Updated `EXECUTION-PLAN.md`/`MASTER-CHECKLIST.md` with unlock/add/lock E2E completion.
- `cargo llvm-cov test --package clavisvault-core --lib --fail-under-lines 95`
  currently fails at 92.70% line coverage.
- `cargo llvm-cov test --package clavisvault-core --lib --show-missing-lines` currently
  flags remaining gaps in: `audit_log.rs`, `encryption.rs`, `openclaw.rs`, `policy.rs`,
  `project_linker.rs`.

# Assumptions
- Tauri runtime path resolution can safely use `CLAVIS_E2E_HOME`/`CLAVIS_E2E_TEMP_DIR` during tests
  without impacting default production behavior.
- Playwright browser automation against the app at `http://127.0.0.1:1420` is sufficient for this
  phase; native webview-only interactions are deferred until first milestone closure.
- `just ci-fast` remains the repo-quality baseline; GUI E2E is a targeted extension on Windows.
- Persistence smoke remains intentionally optional behind `CLAVIS_E2E_PERSISTENCE_SMOKE=1`.
