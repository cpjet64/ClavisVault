# Worklog

## Now
- Classified repository as FINISHED/mostly complete from gates and marker scan:
  - `just ci-fast` was run and is currently passing.
  - Remaining risk is limited to security policy posture: advisory exceptions were still defined in `deny.toml` but `python scripts/validate_audit_exceptions.py` enforces zero-ignore policy for that file.
- Current top-priority in-work item:
  - Migrate advisory exception handling from `deny.toml` ignores to baseline-managed `security/advisory-baseline.toml` entries.
- Classified repository state as FINISHED/mostly complete after the latest full documented gate and security verification reruns.
- No remaining high-confidence blocked implementation stubs or failing tests are visible in source paths.
- Re-ran advisory checks; only non-blocking informational advisories remain (known unmaintained/unsound transitive crates, no exploitable CVE findings).

## Next
- Close the advisory-policy migration task by ensuring `deny.toml` is zero-ignore and `security/advisory-baseline.toml` contains all currently observed unmaintained/unsound advisories.
- Keep tracking transitive advisory pressure in `security/advisory-baseline.toml` until dependency upgrades remove the GTK3-era/Unicode transitive chain.
- Add a follow-up security review if/when relay protocol changes require additional malformed-traffic hardening.

## Later
- Optional: triage low-risk follow-up hardening based on future findings.

## Done
- Completed advisory-policy migration for the new zero-ignore baseline workflow:
  - Removed advisory entries from `deny.toml` `advisories.ignore` and left it empty for advisory suppression.
  - Added observed unmaintained/unsound advisories to `security/advisory-baseline.toml` with expiry/rationale entries.
  - Updated baseline to match active advisory set (`RUSTSEC-2024-0384`/`0388` added; stale `RUSTSEC-2024-0429` removed).
  - Verified:
    - `python scripts/validate_audit_exceptions.py --deny-toml deny.toml` returns 0.
    - `python scripts/enforce_advisory_policy.py` returns 0.
    - `python scripts/validate_audit_exceptions_test.py` (7 tests) passes.
    - `python scripts/enforce_advisory_policy_test.py` (7 tests) passes.
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
  - Informational warnings remain for `atk`, `gtk` and related GTK3 bindings (`RUSTSEC-2024-0412`..`-0419`) plus several legacy/unmaintained crates (`RUSTSEC-2024-0384`, `RUSTSEC-2024-0370`, `RUSTSEC-2025-0080` family, `RUSTSEC-2024-0429` on `glib`).
- Environment date used for evidence: 2026-02-24.

## Assumptions
- No behavior changes should silently reduce CLI compatibility.
- Build must continue to pass with existing workspace gates.
- Legacy v1 paths remain available only through explicit compatibility controls.
