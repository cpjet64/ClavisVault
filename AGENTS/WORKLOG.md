# Worklog

## Now
- Validate remaining high-risk startup and session-handoff paths after the desktop identity repair changes.

## Next
- Run a focused pass on CLI session-token compatibility warnings and relay hardening telemetry behavior.
- Stage and commit the next highest-confidence hardening slice once validation completes.
- Update AGENTS/WORKLOG after that commit.

## Later
- Finalize any remaining docs/notes cleanup (masterplan/alerts migration notes).
- Optional: triage low-risk follow-up hardening based on future findings.

## Done
- Fixed `rand` trait import in core export signing path.
- Added desktop export import trust enforcement with legacy policy handling and TOFU persistence path.
- Added audit ledger retention policy support for max age and adjusted verification to allow safe checkpoint-safe compaction boundaries.
- Cleared clippy/rustfmt nits introduced by the security refactor across core/cli/server:
  - `ExportLegacyMode` now derives `Default` correctly and uses `Warn` as canonical default.
  - `shell` command export test paths now avoid post-initialization mutation of defaults.
  - CLI session-cache/signer test helpers avoid unnecessary `return` statements.
  - Server token verification logic now uses explicit combined checks.
- Hardened desktop settings startup path so invalid cached remote identity material is repaired in-place instead of panicking.

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
