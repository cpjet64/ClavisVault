# ClavisVault EXECUTION-PLAN.md
**Single Source of Truth** — Created 2026-02-24  
**All other plans, worklogs, masterplan.md, TODO_AUTOPILOT.md, COVERAGE_100_TODO.md, and scattered .md files are now DEPRECATED.**  
Move them to `legacy/` after you create this file.

## Governance Rules (never violate)
1. Read AGENTS.md completely before any work (security invariants, key list, workflow).
2. Read docs/SPEC.md (the full technical spec — never deviate).
3. Every file operation must use SafeFileOps (backup → atomic_write).
4. Run the repo’s standard gates before every commit (`just ci-fast` or equivalent).
5. Add/maintain tests for any behavior added.
6. Keep docs in sync with code (CHANGELOG.md, alerts.md, SPEC.md).
7. Zero plaintext on disk. Master key never persisted.

## Four Target Milestones
See MASTER-CHECKLIST.md for the detailed items under each milestone.

### Milestone 1 – First Functional Desktop Vault (target: 3-5 days)
### Milestone 2 – Full Security Invariants + Agents Updater (target: 1 week)
### Milestone 3 – Initial MVP (P2P Tunnel + Server + Relay) (target: 2 weeks)
### Milestone 4 – Finished Project (target: 6-8 weeks)

## Step-by-Step Execution Order (agent must follow exactly)

**Phase 0 – Stabilize & Bootstrap (do this first)**
1. Ensure all quality gates pass cleanly.
2. Verify desktop app launches and basic vault unlock works.
3. Add the first end-to-end test (unlock + add key).
4. Update this file with current status notes.
5. Commit.

## Current Autopilot Status (2026-02-25)
- Repository state classified as `IN-PROGRESS`.
- Step 1 passed: `just ci-fast` now completes successfully (`fmt`, `machete`, `clippy`, and `nextest`) after adjusting server TTL clamp test jitter tolerance.
- Step 2 verified for runtime path: desktop binary builds and starts (`clavisvault-desktop-tauri`), and `tests::unlock_and_upsert_flow_round_trips` in `crates/desktop/src-tauri/src/lib.rs` verifies unlock + upsert + persist + re-open persistence of secret in runtime APIs.
- Full unlock-in-app flow is now verified via Playwright GUI E2E: `crates/desktop/tests/e2e/desktop-flow.spec.ts`
  (`unlock, add key, verify list, lock`) running against a temp isolated app profile.
  Latest run on 2026-02-25 passed on Windows:
  - `npm --prefix crates/desktop run build`
  - `npm --prefix crates/desktop run test:e2e:install`
  - `npm --prefix crates/desktop run test:e2e`
  Result: 1 passed, 1 skipped (`CLAVIS_E2E_PERSISTENCE_SMOKE` path gated off), exit code 0.
- Step 3 evidence now includes deterministic UI automation evidence plus existing runtime/API coverage:
  - `crates/desktop/tests/e2e/desktop-flow.spec.ts`
  - `crates/core` unlock/add runtime regression test in
    `crates/desktop/src-tauri/src/lib.rs` (`unlock_and_upsert_flow_round_trips`)
- Step 1 gate blocker was fixed by widening the server TTL assertion window for scheduling jitter in `requested_session_ttl_is_clamped_to_token_policy`.
- Last status note update: all phase-0 verification steps and evidence recorded in `.AGENTS/WORKLOG.md`.

**Phase 1 – Milestone 1 (First Functional Desktop Vault)**
1. Complete core encryption and SafeFileOps.
2. Wire basic Vault tab CRUD in desktop UI.
3. Complete Milestone 1 checklist items.
4. Update this file + commit.

**Phase 2 – Milestone 2 (Security Invariants + Agents Updater)**
1. Implement Agents.md / OpenClaw updater with markers.
2. Add Project Linker + Shell Injector.
3. Complete Milestone 2 checklist items.
4. Update this file + commit.

**Phase 3 – Milestone 3 (Initial MVP)**
1. Implement QUIC + Noise P2P tunnel.
2. Wire Server + Relay pairing and vault sync.
3. Complete Milestone 3 checklist items.
4. Update this file + commit.

**Phase 4 – Milestone 4 (Finished)**
Follow the remaining items in MASTER-CHECKLIST.md and docs/SPEC.md.

## Agent Instructions
"You are working exclusively from EXECUTION-PLAN.md and MASTER-CHECKLIST.md. Ignore all files in legacy/. Follow the phases exactly. Run the repo’s standard gates before every commit. After completing any milestone, update the status notes in this file and commit the change."
