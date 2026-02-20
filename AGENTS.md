# AGENTS.md - ClavisVault

**This file is automatically managed by ClavisVault itself.**

Before starting any work on this project (coding, testing, reviewing, etc.) you **must** read this entire file, then read `docs/SPEC.md` (the single source of truth).

The only section that ClavisVault will ever modify is the guarded block below.  
Never manually edit anything between `<!-- CLAVISVAULT-START -->` and `<!-- CLAVISVAULT-END -->`.  
Everything else in this file is for human/AI developers and agents.

<!-- CLAVISVAULT-START -->
## ClavisVault Managed Keys
**Last updated:** (automatically filled by the app)

**Purpose of this file for AI coding agents:**  
Give you full context about every API key / environment variable used in ClavisVault development **without ever exposing the actual secret values**.

### Currently Stored Keys & Vars
(No keys have been added to the vault yet. Once you add keys via the desktop app, this section will be auto-updated in all linked agents.md files.)

<!-- CLAVISVAULT-END -->

## Security & Development Rules (AI Agents MUST Follow)

### 1. Core Security Invariants (Never Violate)
- Never write plaintext secrets to disk — use only `core::SafeFileOps`.
- Every file operation (agents.md, openclaw.json, vault file) **must** backup first, then atomic_write.
- All secrets **must** be zeroized on drop (`zeroize` crate).
- Desktop app has zero network capability except the controlled updater and the optional P2P tunnel.
- Relay server **must never** be able to decrypt any traffic.
- All P2P communication uses Noise_XX handshake + QUIC.
- Master key is never persisted — derived per unlock session only.

### 2. Architecture Rules
- Build order: `core` → `desktop` → `server` → `relay` → `cli`.
- Core crate = pure logic, no UI, no network (only traits).
- Desktop = Tauri 2 + React 19 + Tailwind + shadcn/ui (glassmorphic, dark default).
- Server = headless tokio daemon.
- Relay = pure signalling, magic `b"CLAVISRL"` enforced.
- Rust 2024 edition, rust-version = 1.93.1, zero `unsafe` unless reviewed.
- All public items fully documented.

### 3. Code Quality & Testing (Mandatory)
- `cargo clippy --all-targets --all-features -D warnings` must pass.
- `cargo tarpaulin --lib` ≥ 95% on core crate.
- Every new function gets unit tests.
- File-safety tests for **every** file touch (simulate corrupt, permission denied, etc.).
- Encryption round-trip tests (10 000+ random vaults).
- Full matrix testing (Windows 11, macOS 15, Ubuntu 24.04) via CI.
- Always run the verification prompt after any implementation prompt.

### 4. Implementation Workflow for AI Agents
- When user gives an “Implementation Prompt”, implement **exactly** as written.
- When user gives a “Verification Prompt”, run all checks and fix until it says “PASSED”.
- Use only workspace dependencies (never add new crates without updating root Cargo.toml).
- Prefer explicit code, modern Rust 2024 patterns, `anyhow` for errors, `tracing` for logs.
- Keep UI beautiful and consistent (shadcn style, lucide icons).

### 5. Common Keys You Will See in the Managed Section
- `GITHUB_TOKEN` – Used by updater & CI (read-only, repo scope).
- `TEST_RELAY_HOST` – For integration tests against public/self-hosted relay.
- `TEST_SERVER_IP` – For P2P pairing flow tests.
- Any other keys you add via the desktop app will appear here automatically.

### 6. Contribution Rules
- All changes must go through the sequential prompt → verify process.
- Never commit real keys (the vault handles them).
- Update `CHANGELOG.md` and `docs/alerts.md` when appropriate.
- Keep `CHANGELOG.md` at repository root (no `docs/CHANGELOG.md` copy).
- Keep the project “extreme level of testing” at every step.

You are now fully briefed for ClavisVault development.  
Proceed only after reading both this file and `docs/SPEC.md`.
