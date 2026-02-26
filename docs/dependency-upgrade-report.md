# Dependency Upgrade Report

Created: `2026-02-26T01:00:22Z`
Completed: `2026-02-26T20:10:43-05:00`

| Step | Status | Notes |
|---|---|---|
| Baseline inventory and risk plan | Completed | Toolchain and dependency baselines captured. |
| Rust conservative wave | Completed | `cargo update --workspace` produced no lockfile changes (`Locking 0 packages`). |
| Node conservative wave | Completed | `npm --prefix crates/desktop update` refreshed desktop lockfile entries. |
| Validation gates | Completed | `just ci-fast` and `just ci-deep` passed. |
| Security checks | Completed | `cargo audit` warning-only per existing policy; `npm audit --omit=dev` found 0 vulnerabilities. |
| Local commit | Completed | Changes committed locally, no push performed. |

---

## Phase 0 Baseline and Wave Plan

Timestamp: `2026-02-26T01:00:22Z`

- Scope: `C:\Dev\repos\active\ClavisVault`
- Stack detection:
  - Rust workspace (`Cargo.toml`, `Cargo.lock`)
  - Node desktop package (`crates/desktop/package.json`, `crates/desktop/package-lock.json`)
- Toolchain/runtime baseline:
  - `cargo 1.93.1`
  - `rustc 1.93.1`
  - `node v22.16.0`
  - `npm 11.4.1`
  - `python 3.14.3`
- Native bootstrap:
  - `ensure-vcvars.ps1 -Quiet`: PASS
- Pre-change checks:
  - `cargo update --workspace --dry-run`: updates available but no dry-run lockfile write.
  - `npm --prefix crates/desktop outdated`: patch/minor and major updates visible; conservative wave chosen.
  - `cargo audit`: warning-only output tied to existing allowlisted advisory policy.
  - `npm --prefix crates/desktop audit --omit=dev`: `0 vulnerabilities`.

Planned conservative waves:
1. Rust lockfile-compatible updates only.
2. Node lockfile-compatible updates only in `crates/desktop`.
3. Run full validation (`just ci-fast`, `just ci-deep`) and report residual risk.

---

## Phase 1 Rust Wave

Command:
- `cargo update --workspace`

Outcome:
- No lockfile modifications were required (`Locking 0 packages`).
- No Rust dependency graph changes were introduced in this wave.

Risk:
- Minimal; no effective dependency delta.

Rollback:
- Not required for this wave (no file change).

---

## Phase 2 Node Wave

Commands:
- `npm --prefix crates/desktop update`
- `npm --prefix crates/desktop run build`

Outcome:
- `crates/desktop/package-lock.json` updated.
- Frontend build passed after update.
- No manifest (`package.json`) widening was introduced.

Risk:
- Low; lockfile-compatible refresh only.

Rollback:
- Revert `crates/desktop/package-lock.json`.

---

## Validation and Verification

Executed gates:
- `just ci-fast`: PASS
- `just ci-deep`: PASS

`just ci-deep` included:
- Workspace tests (`377 passed, 0 failed`)
- Coverage export (`lcov.info` generated)
- `cargo deny` (`bans ok, licenses ok, sources ok` with duplicate-version warnings)
- `cargo audit` (warning-only, `20 allowed warnings found` per policy)
- Advisory policy enforcement script
- `cargo doc --no-deps --all-features` with `RUSTDOCFLAGS="-D warnings"`: PASS

Security snapshot:
- `npm --prefix crates/desktop audit --omit=dev`: `0 vulnerabilities`
- Rust advisories remained in previously expected, policy-allowed warning state.

---

## Residual Risk and Follow-ups

- Major-version candidates remain intentionally deferred in this conservative pass.
- Existing Rust advisory warnings are transitive and policy-allowlisted; these should be revisited when upstream GTK/Tauri dependency paths move.
- Duplicate crate versions reported by `cargo deny` are currently non-blocking but can be reduced in a future coordinated major upgrade wave.
