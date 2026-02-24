# Worklog

## Now
- Repository remains classified as `FINISHED` / mostly complete after repeated production-risk verification.
- Core verification remains green and no implementation stubs are active in production code.
- Completed final panic/unreachable sweep focused on runtime crash risk in non-test code paths.

## Next
- Proceed to optional low-priority maintenance backlog only if a specific trigger appears (coverage policy changes, new advisories, or explicit user request).
- Keep periodic checks for regressions in docs/spec sync.

## Later
- Expand routine security posture review if dependency policy or release requirements change.
- Optional periodic review of advisory exceptions and relay/desktop runtime threat assumptions.

## Done
- Re-ran `rg` panic/unreachable risk sweep in production candidate paths.
- Confirmed remaining `panic!`/`unreachable!` instances are limited to `#[test]` modules.
- Canonicalized worklog path to repository-defined `AGENTS/WORKLOG.md`.
- Logged the latest risk/repo state evidence and assumptions.

## Decisions Needed
- None.

## Evidence
- `rg -n "panic!\(|unreachable!\(" crates`
- `just ci-fast` baseline gates from earlier cycle remain green (`just ci-fast`: 258 tests passed, 0 failed) and no new regression was introduced during this step.

## Assumptions
- `AGENTS/WORKLOG.md` is the canonical worklist due existing `AGENTS/` directory.
- No user-directed work is pending that would force `IN-PROGRESS` completion tasks now.

## Archive

### Previous Worklog Entries

## Now
- Repository is now classified as IN-PROGRESS.
- Trigger cause: `cargo llvm-cov --package clavisvault-core --lib --fail-under-lines 95` still fails on current branch; core line coverage remains below gate.
- Current highest-priority focus: add focused core tests for currently low-coverage modules (`audit_log`, `safe_file`, `export`, `encryption`, and related policy/type validation branches).

## Next
- Expand `crates/core/src/audit_log.rs` tests for integrity failures, checkpoint behavior, and retention pruning with checkpoints.
- Expand `crates/core/src/safe_file.rs` tests to cover atomic-write rollback branches and restoration failure handling.
- Expand `crates/core/src/export.rs` and `crates/core/src/encryption.rs` tests for malformed manifest/key-count/signature and auth-key error paths.

## Later
- Verify `cargo fmt`, `cargo clippy --all-targets --all-features`, and full `cargo llvm-cov` pass after each atomic slice.
- Update `docs/SPEC.md`/`README.md` only if behavioral semantics change.

## Done
- Confirmed this cycle is in-progress mode due failing verification gate despite prior partial test additions.
- Maintained worklog updates per autopilot protocol.

## Decisions Needed
- None.

## Evidence
- `cargo llvm-cov --package clavisvault-core --lib --fail-under-lines 95` remains the decisive signal for completion status.
- Existing core file-miss map includes substantial untested branches in `audit_log.rs`, `safe_file.rs`, `export.rs`, and `encryption.rs`.

## Assumptions
- Coverage-only deficits are acceptable to address via unit tests unless they require nondeterministic platform-specific behavior, in which case targeted test-only code paths should be introduced.

## Now
- Repository remains FINISHED/mostly complete after full required gates and high-confidence verification:
  - `just ci-fast` passes (`hygiene`, `fmt`, `clippy`, `machete`, `build`, `test-quick`).
  - 213 tests passed (`0` skipped) in the last quick suite.
- Current in-progress work item is now closed: advisory-policy migration to baseline-managed exceptions is complete and stable.
- Ongoing residual risk is transitive advisory debt in the desktop stack with known unmaintained crates; no exploitable vulnerabilities are reported.

## Next
- Continue periodic security posture review:
  - Validate `security/advisory-baseline.toml` every release against current `cargo deny` advisories output.
  - Track the earliest baseline expiry date and prepare remediation plans before any entry expires.
  - Add follow-up review when dependency upgrades become feasible for the desktop GTK path.

## Later
- Optional: triage low-risk follow-up hardening based on future findings.

## Done
- Completed advisory-policy migration for the zero-ignore baseline workflow:
  - Migrated advisory handling from denied `advisories.ignore` entries to `security/advisory-baseline.toml`.
  - Baseline includes the current observed advisory set (`RUSTSEC-2024-0370`, `2024-0384`, `2024-0388`, `2024-0411..0420`, `2025-0057`, `2025-0075`, `2025-0080`, `2025-0081`, `2025-0098`, `2025-0100`).
  - Verified:
    - `python scripts/validate_audit_exceptions.py --deny-toml deny.toml` returns 0.
    - `python scripts/enforce_advisory_policy.py` returns 0.
    - `python scripts/validate_audit_exceptions_test.py` passes.
    - `python scripts/enforce_advisory_policy_test.py` passes.
- Completed repo-wide status refresh in-line with AGENTS/SPEC instructions:
  - `just ci-fast` (hygiene + fmt + clippy + machete + build + nextest) passes cleanly.
  - `213 tests run: 213 passed, 0 skipped` in the latest quick suite.
  - In-source marker scan found no remaining high-confidence stubs (`todo!`, `unimplemented!`, `pass`, etc.) except test-only panic guards.
  - Replaced a remaining test-only `panic!` in relay fanout-cap coverage with explicit `matches!` assertion plus count checks.
- Completed repo-wide status refresh in-line with AGENTS/SPEC instructions:
  - `just ci-fast` (hygiene + fmt + clippy + machete + build + nextest) passes cleanly.
  - `213 tests run: 213 passed, 0 skipped` in the latest quick suite.
  - In-source marker scan found no remaining high-confidence stubs (`todo!`, `unimplemented!`, `pass`, etc.) except test-only panic guards.
  - Replaced a remaining test-only `panic!` in relay fanout-cap coverage with explicit `matches!` assertion plus count checks.
- Implemented remote scope propagation from desktop settings into pairing and push payloads, plus server-side scope enforcement and TTL policy mapping.
- Added request validation and normalization for remote permissions/scopes; fixed compile regressions and stabilized the slice with unit coverage.
- Added desktop startup normalization so invalid legacy permission values now fail closed with explicit mapping errors.
- Removed deprecated plaintext session shell snippet API surface from core shell helpers and CLI tests.
  - `shell_session_exports` / `shell_session_export_snippets` are no longer exposed from `crates/core/src/shell.rs`.
  - `clavisvault-cli` now only documents/uses token-file based env-load snippets; tests were tightened accordingly.
- Added explicit compatibility gating for legacy `CLAVISVAULT_SESSION_TOKEN` env-var session-token fallback.
- Ran `just ci-deep` end-to-end:
  - Hygiene, fmt, clippy, machete, build, test-full, security, and docs completed.
  - `213 tests run: 213 passed, 0 skipped`.
  - `cargo deny check` passed.
  - `cargo audit` and policy enforcement returned success with existing advisory allow-list.
  - `cargo doc --no-deps --all-features` generated documentation.

## Done
- Removed silent fallback for missing session signing key in CLI keyring:
  - `load_or_generate_session_token_secret` now fails fast when keyring is unavailable and reports recovery guidance instead of generating a divergent local secret.
  - Preserves compatibility in test mode via in-memory key cache while hardening release behavior.
- Completed CLI/desktop shell hardening follow-up slice:
  - `clavisvault_core::shell` now exposes `CLAVISVAULT_SESSION_TOKEN_FILE`-based snippets and clear-path cleanup.
  - `clavisvault-cli` now accepts `--session-token-file` (`--token-file`) and prefers it over env/plaintext token.
  - Token files are parsed, validated, and removed after use; invalid files are removed and fail fast.
  - Added/updated tests for token-file preference, one-time consumption, invalid token cleanup, and write failures.
  - `cargo fmt --all`, targeted `cargo test` (cli/core), and `cargo clippy` for touched crates are clean.
- Fixed `rand` trait import in core export signing path.
- Added desktop export import trust enforcement with legacy policy handling and TOFU persistence path.
- Added audit ledger retention policy support for max age and adjusted verification to allow safe checkpoint-safe compaction boundaries.
- Cleared clippy/rustfmt nits introduced by the security refactor across core/cli/server:
  - `ExportLegacyMode` now derives `Default` correctly and uses `Warn` as canonical default.
  - `shell` command export test paths now avoid post-initialization mutation of defaults.
  - CLI session-cache/signer test helpers avoid unnecessary `return` statements.
  - Server token verification logic now uses explicit combined checks.
- Hardened desktop settings startup path so invalid cached remote identity material is repaired in-place instead of panicking.
- Hardened relay input handling in `crates/relay/src/main.rs`:
  - Added source-IP sender limiter and relay peer-table size limit.
  - Enforced destination deduplication before fanout checks.
  - Added hard-drop reasons for source peer and peer-table limit hits.
  - Added tests for source-peer quota and full peer table rejection.
- Added relay burst-flood regression coverage:
  - New `source_rate_limit_blocks_bursts_per_ip` test verifies per-source IP rate limiting returns `SourceRateLimit` under burst conditions and recovers after window expiry.
- Added relay trust-boundary signaling and docs updates:
  - `clavisvault-relay` help/startup now explicitly states unauthenticated forwarding boundary assumptions.
  - `docs/SPEC.md` and `README.md` now document relay trust boundary expectations for operators.
- Completed a focused repository security sweep for inline TODO/TODO-like markers:
  - Scanned core/cli/server/desktop-tauri/relay/doc set for high-confidence placeholders (`TODO`, `FIXME`, `XXX`, `HACK`, `NotImplemented`, `unimplemented!`, and obvious fallback stubs).
  - No new high-confidence placeholders were identified beyond already-tracked migration decisions.

## Decisions Needed
- Export signer persistence location and migration model: server-side keyring + explicit migration mode or dedicated CLI-managed trust file.
- Whether to allow legacy v1 export import via explicit `--allow-legacy-export` in default CLI profile or environment-only emergency override.
- Whether relay destination caps should be hard fail (disconnect sender) or silent drop with telemetry.
- Whether legacy plain `--session-token` output compatibility should stay supported indefinitely in non-production mode.
- Whether to gate legacy v1 import default as `warn` only or default to reject in CI mode without extra flag.
- Whether to reduce desktop dependency risk by reworking transitive advisory-heavy crates or retaining allow-list with documented justification.

## Evidence
- Security policy evidence for this change cycle:
  - `python scripts/validate_audit_exceptions.py --deny-toml deny.toml` now passes.
  - `python scripts/enforce_advisory_policy.py` now passes after baseline updates.
  - `cargo deny check advisories` now reports the expected advisory set when no deny `ignore` entries are configured.
- Reviewed `crates/core/src/export.rs`, `crates/core/src/types.rs`, `crates/core/src/policy.rs`, `crates/core/src/shell.rs`, `crates/core/src/audit_log.rs`.
- Reviewed `crates/cli/src/main.rs`, `crates/desktop/src-tauri/src/lib.rs`, `crates/server/src/main.rs`, `crates/relay/src/main.rs`.
- Verified format/lint/test gates after this change set (`just ci-fast`, package clippy/tests for core/cli/server/desktop-tauri/relay plus updated scope work).
- Verified targeted relay regression path after assertion cleanup with:
  - `cargo fmt --check`
  - `cargo test -p clavisvault-relay destination_fanout_cap_causes_drop`
- Full-gate verification evidence:
  - `just ci-deep` completed and documented all phases (`ci-fast`, `test-full`, `coverage`, `security`, `docs`) as passing.
  - Security policy script (`python scripts/enforce_advisory_policy.py`) remains green with allow-list entries only.
- Latest security sweep:
  - `cargo audit --json` reports no dependency vulnerabilities.
  - Informational warnings remain for `atk`, `gtk` and related GTK3 bindings (`RUSTSEC-2024-0412`..`-0419`) plus several legacy/unmaintained crates (`RUSTSEC-2024-0384`, `RUSTSEC-2024-0370`, `RUSTSEC-2025-0080` family).
- Environment date used for evidence: 2026-02-24.

## Assumptions
- No behavior changes should silently reduce CLI compatibility.
- Build must continue to pass with existing workspace gates.
- Legacy v1 paths remain available only through explicit compatibility controls.

