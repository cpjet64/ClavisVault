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
- Step 1 passed: `just ci-fast` completed successfully (fmt + machete + build + nextest).
- Step 2 not yet verified with a desktop launch path in this environment.
- Step 3 evidence exists via CLI test `add_and_list_cycle_works_with_core_vault` (`crates/cli/src/main.rs`) covering unlock + add-key flow.
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
