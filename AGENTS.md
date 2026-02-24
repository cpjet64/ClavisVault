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
- `cargo llvm-cov test --package clavisvault-core --lib --fail-under-lines 95` ≥ 95% on core crate.
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

## Additional Context

# CLAUDE.md - ClavisVault AI Instructions

**Critical first step for every task:**

1. Read `AGENTS.md` completely (it is the project-specific rulebook and contains the safe list of all keys/vars).
2. Then read `docs/SPEC.md` (the full technical specification — never deviate).

This project has extremely high security, encryption, and testing standards.  
Any deviation can break the security invariants or file-safety guarantees.

When the user gives you:
- An “Implementation Prompt” → implement exactly, nothing more, nothing less.
- A “Verification Prompt” → run every check and fix until it reports “PASSED”.

Current status: Documentation and implementation have been actively implemented and validated as a source for this cleanup pass; continue with routine verification before release gates.

Primary goal: Build the most secure, beautiful, and thoughtful developer key vault ever made.

Good luck! 🗝️

## Environment

### Cache Locations
All caches are centralized under `C:\Dev\cache\`. These environment variables are set system-wide — do not override them in project config or scripts.

| Cache | Path | Env Variable |
|---|---|---|
| Cargo registry/git/bin | `C:\Dev\cache\cargo` | `CARGO_HOME` |
| Rustup toolchains | `C:\Dev\cache\rustup` | `RUSTUP_HOME` |
| sccache | `C:\Dev\cache\sccache` | `SCCACHE_DIR` |


#### Cargo Cache Rules
- **sccache is enabled globally** via `$CARGO_HOME/config.toml` (`[build] rustc-wrapper = "sccache"`). All projects inherit this through Cargo's hierarchical config — do not duplicate it.
- **Do NOT** add `rustc-wrapper = "sccache"` to per-project `.cargo/config.toml` — it is inherited from the global config.
- **Do NOT** set `SCCACHE_DIR`, `RUSTC_WRAPPER`, or `CARGO_INCREMENTAL` in `.cargo/config.toml` `[env]` — these are set via system environment variables.
- **Do NOT** set `target-dir` to a shared path (e.g. `C:\Dev\cache\target`) — this causes cross-project build artifact collisions. Use the default per-project `./target/`.
- **Do NOT** create a local `.cargo-home/` directory — the global `CARGO_HOME` provides the registry, git checkouts, and installed binaries.
- Per-project `.cargo/config.toml` **is appropriate** for: linker flags, cargo aliases, build targets, source replacement, rustflags, and profile overrides.

### Agent Temp Directory
If you need a temporary working directory, use `C:\Dev\agent-temp`. Do NOT use system temp or create temp dirs inside the project.

### Project Location
This project lives at `C:\Dev\repos\active\ClavisVault`.

## Workflow Orchestration

### 1. Plan Node Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy
- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One tack per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update `//reporoot/.AGENTS/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake to AGENTS.md
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests - then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

## Task Management

1. **Initialize**: Check for the existence of and read the contents of the Justfile if present.
2. **Plan First**: Write plan to `//reporoot/.AGENTS/todo.md` with checkable items
3. **Save Plan**: Once a plan has been generated, save it to `//reporoot/.AGENTS/plans/shortnamethatdescribeswhattheplanis.md`
4. **Verify Plan**: Check in before starting implementation
5. **Track Progress**: Mark items complete as you go
6. **Explain Changes**: High-level summary at each step
7. **Document Results**: Add review section to `//reporoot/.AGENTS/todo.md`
8. **Capture Lessons**: Update `//reporoot/.AGENTS/lessons.md` after corrections

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.
