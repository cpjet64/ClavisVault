# ClavisVault API Surface

## Desktop Tauri Commands
Defined in `crates/desktop/src-tauri/src/lib.rs`, consumed via `crates/desktop/src/lib/api.ts`.

Vault and auth:
- `bootstrap`
- `unlock_vault_command`
- `lock_vault_command`
- `change_master_password`

Key management:
- `list_keys`
- `upsert_key`
- `delete_key`
- `copy_single_key`
- `export_vault`
- `import_vault`
- `rotate_key`

Linking/remotes:
- `sync_links`
- `list_remotes`
- `pair_and_add_remote`
- `remove_remote`
- `revoke_remote_session`

Policy/audit/recovery:
- `list_audit_entries`
- `verify_audit_chain`
- `list_rotation_findings`
- `run_recovery_drill`

Runtime/settings/ops:
- `get_settings`
- `save_settings`
- `acknowledge_alert`
- `shell_hooks`
- `biometric_available`
- `check_updates`

## CLI Commands
Binary: `clavisvault` (`crates/cli/src/main.rs`).

Global options:
- `--data-dir PATH`
- `--vault PATH`

Commands:
- `env-load`
- `add-key`
- `list`
- `remove-key` (alias `rm-key`)
- `rotate-key`
- `policy check`
- `audit verify`
- `recovery-drill`
- `shell-hook`

Auth-related flags:
- `--password`
- `--session-token` / `--token` (legacy compatibility path)
- `--session-token-file` / `--token-file`
- `--allow-legacy-session-token`

## Server Binary Interface
Binary: `clavisvault-server` (`crates/server/src/main.rs`).

Modes:
- `clavisvault-server` (daemon)
- `clavisvault-server set-password [--password VALUE]`
- `clavisvault-server push-sim --vault PATH [--token T | --pairing-code C | --password P]`

Push request model (`PushRequest`):
- auth: `token` or `pairing_code` (+ optional `password`)
- binding: `client_fingerprint`, `server_fingerprint`
- command: optional `erase` or `revoke`
- payload: `encrypted_vault_hex`
- token policy request: `requested_scopes`, `session_ttl_seconds`

Push response model (`PushResponse`):
- `ack_sha256`
- `server_fingerprint`
- `issued_token` (pairing success path)

## Relay Binary Interface
Binary: `clavisvault-relay` (`crates/relay/src/main.rs`).

CLI:
- `clavisvault-relay [--bind 0.0.0.0:51820]`

Protocol envelope:
- `[8] CLAVISRL`
- `[1] protocol version`
- `[2] payload len`
- `[32] sender_pubkey_hash`
- `[payload]`

Behavior:
- per-source and per-peer rate limits,
- source-peer churn cap,
- peer table cap,
- destination fanout cap,
- optional target-hint routing from payload prefix.

## Core Library Interfaces
Representative exported capabilities from `crates/core`:
- encryption: `derive_master_key`, `lock_vault`, `unlock_vault`, `unlock_with_password_or_biometric`, `PasswordAttemptLimiter`
- file safety: `SafeFileOps`, `LocalSafeFileOps`
- managed files: `AgentsUpdater`, `OpenClawUpdater`
- policy: `load_policy`, `validate_vault_policy`
- audit: `AuditLog`, `verify_ledger_integrity`, `IdleLockTimer`
- rotation: `list_rotation_findings`, `rotate_key`
- recovery: `run_recovery_drill`
- export/import: `encrypt_export*`, `decrypt_export*`, trust/legacy policy evaluators
