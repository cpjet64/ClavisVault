# Worklog

## Now
- Complete relay hardening follow-up by removing plaintext session-env helper surface for env-load flows.
- Keep validating relay trust-boundary and TTL/scoping behavior under load.

## Next
- Continue deep-dive security sweep: relay trust-boundary hardening and scope/TTL mismatch checks under load.
- Run a repository-wide pass for remaining high-confidence security TODOs and update evidence.

## Later
- Finalize relay trust-boundary documentation updates and any remaining migration notes in `docs/SPEC.md` and `README.md`.
- Optional: triage low-risk follow-up hardening based on future findings.

## Done
- Implemented remote scope propagation from desktop settings into pairing and push payloads, plus server-side scope enforcement and TTL policy mapping.
- Added request validation and normalization for remote permissions/scopes; fixed compile regressions and stabilized the slice with unit coverage.
- Added desktop startup normalization so invalid legacy permission values now fail closed with explicit mapping errors.
- Removed deprecated plaintext session shell snippet API surface from core shell helpers and CLI tests.
  - `shell_session_exports` / `shell_session_export_snippets` are no longer exposed from `crates/core/src/shell.rs`.
  - `clavisvault-cli` now only documents/uses token-file based env-load snippets; tests were tightened accordingly.

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

## Decisions Needed
- Export signer persistence location and migration model: server-side keyring + explicit migration mode or dedicated CLI-managed trust file.
- Whether to allow legacy v1 export import via explicit `--allow-legacy-export` in default CLI profile or environment-only emergency override.
- Whether relay destination caps should be hard fail (disconnect sender) or silent drop with telemetry.
- Whether legacy plain `--session-token` output compatibility should stay supported indefinitely in non-production mode.
- Whether to gate legacy v1 import default as `warn` only or default to reject in CI mode without extra flag.

## Evidence
- Reviewed `crates/core/src/export.rs`, `crates/core/src/types.rs`, `crates/core/src/policy.rs`, `crates/core/src/shell.rs`, `crates/core/src/audit_log.rs`.
- Reviewed `crates/cli/src/main.rs`, `crates/desktop/src-tauri/src/lib.rs`, `crates/server/src/main.rs`, `crates/relay/src/main.rs`.
- Verified format/lint/test gates after this change set (`cargo fmt --all`, package clippy/tests for core/cli/server/desktop-tauri/relay).

## Assumptions
- No behavior changes should silently reduce CLI compatibility.
- Build must continue to pass with existing workspace gates.
- Legacy v1 paths remain available only through explicit compatibility controls.
