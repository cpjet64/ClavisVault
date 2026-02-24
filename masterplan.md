# ClavisVault Masterplan (Documentation vs Implementation Audit)

Scope: Consolidated check of repository documentation against implementation state (as of 2026-02-24).

## Documents reviewed

- `AGENTS.md`
- `CLAUDE.md`
- `README.md`
- `RUN-THIS-PROMPT.md`
- `docs/SPEC.md`
- `docs/alerts.md`
- `CHANGELOG.md`
- `.AGENTS/todo.md`
- `.AGENTS/plans/` (directory structure for planned work)

## Status legend

- ✅ Implemented — behavior clearly exists in source and is covered by tests/logic.
- ⚠️ Partial — behavior is partially represented; remaining work is mainly process/doc alignment.
- ❌ Missing — documented item is not represented in current source/docs implementation.
- 🗂 Stale — documentation content is out of date or placeholder.

## Consolidated verification matrix

| Source | Requirement / Claim | Status | Evidence |
| --- | --- | --- | --- |
| `docs/SPEC.md` | Core crypto stack uses Argon2id, ChaCha20Poly1305, secure file ops, rate-limit+wipe policy | ✅ | `crates/core/src/encryption.rs`, `crates/core/src/safe_file.rs` |
| `docs/SPEC.md` | Agents/OpenClaw guarded updates with backup + atomic write | ✅ | `crates/core/src/agents_updater.rs`, `crates/core/src/openclaw.rs` |
| `docs/SPEC.md` | Project linker discovery, recursive watcher, debounce behavior | ✅ | `crates/core/src/project_linker.rs` |
| `docs/SPEC.md` | Shell injector hooks for Bash/Zsh/Fish/Pwsh | ✅ | `crates/core/src/shell.rs` |
| `docs/SPEC.md` | Encrypted export/import with passphrase validation and zip payload | ✅ | `crates/core/src/export.rs` |
| `docs/SPEC.md` | Vault tab features, key CRUD, import/export in desktop UI | ✅ | `crates/desktop/src/components/VaultTab.tsx` |
| `docs/SPEC.md` | Settings controls, Cmd/Ctrl+K, audit log viewer, clipboard timeout, theme/accent picker, biometric toggle | ✅ | `crates/desktop/src/components/SettingsTab.tsx`, `crates/desktop/src/App.tsx` |
| `docs/SPEC.md` | Remotes tab with pairing code + fingerprint + QUIC/Noise add flow | ✅ | `crates/desktop/src/components/RemotesTab.tsx`, `crates/desktop/src-tauri/src/lib.rs` |
| `docs/SPEC.md` | Tray menu + lock/check-updates states and events | ✅ | `crates/desktop/src-tauri/src/lib.rs` |
| `docs/SPEC.md` | Desktop alerts from `docs/alerts.md` frontmatter-like blocks | ✅ | `crates/desktop/src-tauri/src/lib.rs`, `docs/alerts.md` |
| `docs/SPEC.md` | Relay packet framing (`CLAVISRL`, protocol constants, rate-limit) | ✅ | `crates/relay/src/main.rs` |
| `docs/SPEC.md` | Server pairing workflow, 5-min pairing TTL, 8-char code format, SHA-256 binding, Ed25519/JWT issuance, QUIC+Noise push | ✅ | `crates/server/src/main.rs` |
| `docs/SPEC.md` | Core fuzz targets exist for parsers/crypto/session invariants | ✅ | `crates/core/fuzz/fuzz_targets/*.rs` |
| `docs/SPEC.md` | GitHub layout and CI matrix (macOS/Linux/Windows) | ✅ | `Cargo.toml`, `.github/workflows/ci.yml` |
| `AGENTS.md` / `CLAUDE.md` | Security/invariants and mandatory verification workflow | ✅ | `AGENTS.md`, `CLAUDE.md` |
| `docs/SPEC.md` | Repository URL points at placeholder owner (`YOURUSERNAME`) | ✅ | `docs/SPEC.md:GitHub` and `Cargo.toml:repository` now set to `cpjet64/ClavisVault` |
| `docs/SPEC.md` | Workspace layout lists `members = ["crates/*", "crates/desktop/src-tauri"]` | ✅ | `docs/SPEC.md:47` and `Cargo.toml` |
| `docs/SPEC.md` | Server section claimed “No edit/delete API” while implementation supports authenticated remote `erase` command | ✅ | `docs/SPEC.md` updated; implementation evidence in `crates/server/src/main.rs` (`REMOTE_COMMAND_ERASE`, `handle_vault_push`) |
| `docs/SPEC.md` | Path/location wording for `alerts.md` and `CHANGELOG.md` had conflicting root-vs-docs wording | ✅ | `docs/SPEC.md` now consistently states `docs/alerts.md` + root `CHANGELOG.md` |
| `AGENTS.md` / `CLAUDE.md` | Stale “Current status” language | ✅ | `AGENTS.md` status text was refreshed; `CLAUDE.md` has no stale status line |
| `RUN-THIS-PROMPT.md` | Node checks expect pnpm-only lockfile and always-on frontend lint/format configs | ✅ | Document now accepts `package-lock.json` for npm and makes lint/format config checks conditional |
| `RUN-THIS-PROMPT.md` | Python checks require project-wide pyproject/uv policy by default | ✅ | Document now documents dependency-manager scope so utility-script repos can skip as applicable |
| `RUN-THIS-PROMPT.md` | Git hooks checks require core.hooksPath + executable scripts | ✅ | `git config core.hooksPath` returns `.githooks`; hooks call `just ci-fast`/`ci-deep`; git index shows mode `100755` for both scripts |
| `RUN-THIS-PROMPT.md` | CI smoke check `just ci-fast` | ✅ | `just ci-fast` now executes cleanly in-repo; hygiene, `fmt`, clippy, `machete`, build, and `nextest` all pass |
| `RUN-THIS-PROMPT.md` | `ci-deep` checklist reflects no mutation testing | ✅ | `RUN-THIS-PROMPT.md:31` |
| `Justfile` | `ci-deep` excludes mutation testing (`cargo mutants`) from all CI/deep-check flows | ✅ | `Justfile:9` |
| `docs/SPEC.md` | Distribution includes desktop `.dmg/.exe/.AppImage` artifacts and server/relay packaged binaries | ✅ | `scripts/release.sh`, `scripts/release.ps1` |
| `docs/SPEC.md` | Server is ready for systemd/Docker deployment paths | ✅ | `server-public/clavisvault-server.service`, `server-public/docker-compose.yml`, `server-public/Dockerfile` |
| `docs/SPEC.md` | Extreme fuzzing duration is 24h on parsers and crypto invariants | ✅ | `scripts/run-extreme-tests.sh`, `scripts/run-extreme-tests.ps1` (`CLAVIS_EXTREME_FUZZ_SECONDS` defaults to 86400 outside CI) |
| `README.md` | No technical claims of unimplemented behavior found | ✅ | `README.md` is user-facing summary only |
| `docs/alerts.md` | Alert format and polling contract implementation includes validation path and parser tests | ✅ | `crates/desktop/src-tauri/src/lib.rs` (read + parse logic) plus parser unit tests |

## Consolidated cleanup actions

- Keep explicit policy decision in `RUN-THIS-PROMPT.md` for when Python-only utility scripts should be exceptioned from dependency-manager checks.
- No original documentation files were moved to `legacy/docs`; all source docs were consolidated in place and normalized for implementation verification.
- Removed mutation testing from the `ci-deep` path to avoid shell-incompatible failure modes in this repository and keep CI deterministically runnable across dev shells.
- Updated `RUN-THIS-PROMPT.md` deep-CI checklist so it no longer includes `mutants`.
- Added `mutants.out/` to `.gitignore` so mutation-testing artifacts from local runs stay untracked.

## Vendoring audit

- No vendored dependency bundle directory was found in the repository (`vendor/` not present).
- No Cargo source override to a vendored source was found in `.cargo/config.toml` or `Cargo.toml` (`replace-with`/`source.<name>` overrides absent).
- No local path source remapping was found in `Cargo.lock` scan (dependency sources remain registry-only).
- `masterplan.md` does not include copied implementation bodies; it tracks each item as a claim + evidence pointer only.
- Remaining actionable items are tracked as mismatches/process gaps, not duplicated feature specs.

## Completion summary

- No direct feature-level requirement from `docs/SPEC.md` appears unimplemented in the core implementation surface.
- Release/distribution and deployment gaps are now represented in repository assets and scripts (`release.sh/.ps1`, `server-public`, configurable extreme fuzzing controls).

## Final sweep status (as of 2026-02-24)

- Mutation-testing references in active CI and prompt contracts are removed/neutralized (`ci-deep` no longer runs `cargo mutants`, `RUN-THIS-PROMPT.md` updated, artifacts ignored via `.gitignore`).
- Release pipeline now builds desktop installers/bundles plus server and relay binaries, and server deployment assets now exist under `server-public/`.
- Extreme fuzz script controls now support 24h fuzz runtime via `CLAVIS_EXTREME_FUZZ_SECONDS` while CI continues to use a short constrained run.
- Vendoring checks are clean: no `vendor/` directory, and no Cargo source override is configured for vendored dependencies.
- No legacy doc-move was applied for original documentation (no `legacy/docs` migration path was used).

## 2026-02-24 Extended Feature Pass

- Vault schema migrated to v2 with key-level rotation metadata and in-place migration hooks.
- Core exports now emit signed manifest v2 metadata and import verifies checksum/signature (legacy v1 manifests remain readable).
- Core audit subsystem now exposes tamper-evident chain ledger types and integrity verification helpers.
- Core policy engine added with `policy/secret-policy.toml` support.
- Core recovery drill engine added for backup/decryptability checks.
- Desktop Tauri command surface expanded with:
  - `verify_audit_chain`, `list_rotation_findings`, `rotate_key`, `revoke_remote_session`, `run_recovery_drill`, `acknowledge_alert`.
- Remote objects now track trust policy and repair state (`permissions`, `session_ttl_seconds`, `revoked_at`, `requires_repairing`).
- Server now supports token scope/revocation semantics (`scp`, `jti`, `rid`) and remote `revoke` command.
- CLI expanded with `rotate-key`, `policy check`, `audit verify`, and `recovery-drill`.
- Alert schema expanded in `docs/alerts.md` with structured metadata fields (`id`, `severity`, `channel`, `dedupe_hours`, schedules, ack hints).
- Alert runtime now applies `dedupe_hours` suppression windows and alert-level ack-default hints during update checks (`crates/desktop/src-tauri/src/lib.rs`, covered by unit tests).

## Nice-to-have feature completion matrix (8/8)

| Feature | Status | Evidence |
| --- | --- | --- |
| 1. Tamper-evident audit chain | ✅ Implemented | `crates/core/src/audit_log.rs`, `crates/desktop/src-tauri/src/lib.rs` (`verify_audit_chain`) |
| 2. Rotation policies + expiry automation | ✅ Implemented | `crates/core/src/types.rs`, `crates/core/src/rotation.rs`, `crates/desktop/src/components/VaultTab.tsx`, `crates/desktop/src-tauri/src/lib.rs` (`list_rotation_findings`, `rotate_key`) |
| 3. Hardware-backed key protection path | ✅ Implemented | `crates/desktop/src-tauri/src/lib.rs` (`hardware_backed_unlock_enabled`, keyring-backed unlock path) |
| 4. Fine-grained remote trust policy | ✅ Implemented | `crates/desktop/src/lib/types.ts`, `crates/desktop/src/components/RemotesTab.tsx`, `crates/server/src/main.rs` (`scp`, `rid`, revoke handling) |
| 5. Signed export/backup manifests | ✅ Implemented | `crates/core/src/export.rs` (manifest v2 signature + verification, legacy compatibility) |
| 6. Policy-as-code secret hygiene | ✅ Implemented | `crates/core/src/policy.rs`, `policy/secret-policy.toml`, `crates/cli/src/main.rs` (`policy check`), desktop warning path in `crates/desktop/src-tauri/src/lib.rs` |
| 7. Recovery workflow hardening | ✅ Implemented | `crates/core/src/recovery.rs`, `crates/desktop/src-tauri/src/lib.rs` (`run_recovery_drill`), `crates/cli/src/main.rs` (`recovery-drill`) |
| 8. Alerting quality improvements | ✅ Implemented | `docs/alerts.md`, `crates/desktop/src-tauri/src/lib.rs` (parser fields, scheduling, acknowledgment filtering) |

## Unimplemented requirement register

- None currently identified in reviewed documentation scope (`AGENTS.md`, `CLAUDE.md`, `README.md`, `RUN-THIS-PROMPT.md`, `docs/SPEC.md`, `docs/alerts.md`, `CHANGELOG.md`).
- New gaps should be added here first, then linked to evidence and follow-up commits.
