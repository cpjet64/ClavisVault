# ClavisVault Master Completion Checklist
**Generated:** 2026-02-24  
**Single source of truth:** EXECUTION-PLAN.md  
**Agent instruction:** Verify every item against the live codebase. Do not pre-mark anything.

## Milestone 1 – First Functional Desktop Vault
- [x] Core encryption (Argon2id + ChaCha20Poly1305) round-trips correctly
- [x] SafeFileOps with backup + atomic write works for all vault operations
- [x] Desktop app launches with Tauri 2 UI (Vault tab functional)
- [x] Master password unlock / lock works
- [x] Basic CRUD (add/edit/delete/copy key) works in UI
- [x] All quality gates pass (`just ci-fast`, clippy, tests)
- [x] End-to-end test exists that unlocks and adds a key
- [x] GUI desktop E2E run validates unlock/add/lock flow (`crates/desktop/tests/e2e/desktop-flow.spec.ts`)
- [x] GUI desktop E2E flow includes persistence smoke check under reload (`crates/desktop/tests/e2e/desktop-flow.spec.ts`)

## Milestone 2 – Full Security Invariants + Agents Updater
- [x] Zero plaintext on disk (all file ops use SafeFileOps)
- [x] Agents.md / OpenClaw guarded section updater works with markers
- [x] Project linker + recursive watcher + debounce works
- [x] Shell injector hooks for all shells (bash/zsh/fish/pwsh)
- [x] Audit log + tamper-evident chain verification works
- [x] Policy-as-code validation (`policy/secret-policy.toml`) works
- [x] Recovery drill + signed export/import with passphrase works

## Milestone 3 – Initial MVP (P2P Tunnel + Server + Relay)
- [x] QUIC + Noise P2P tunnel works (direct + relay)
- [x] Server (headless) accepts pairing and vault push
- [x] Relay only signals (no decryption) and enforces magic header
- [x] Desktop can pair and sync with server
- [x] Remote trust policy + session revocation works
- [x] CLI commands (`rotate-key`, `policy check`, `audit verify`, `recovery-drill`) work

## Milestone 4 – Finished Project
- [x] Full polish: idle auto-lock, biometric, clipboard clear, theme/accent, Cmd/Ctrl+K
- [x] Tray + autostart + minimized launch
- [x] Auto-updater + critical alerts from `docs/alerts.md`
- [x] Extreme testing gates (95%+ core coverage, 24 h fuzz, file-safety matrix)
- [x] Full distribution (installers, Docker, systemd, GitHub Releases)
- [x] All CI matrix (Windows/macOS/Linux) green
- [x] Production security invariants fully enforced and documented

## Component Checklists (for reference only)
- Core Crypto & SafeFileOps
- Desktop UI (Tauri 2 + React)
- Agents / OpenClaw Updater
- Project Linker & Watcher
- Shell Injector
- Audit Log & Policy Engine
- P2P Tunnel & Server
- Relay Signalling
- CLI Surface
- Recovery & Export
- Quality Gates & Fuzzing
- Distribution & Packaging
