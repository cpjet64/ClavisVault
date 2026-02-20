# ClavisVault Changelog

## [0.1.0] - 2026-02-19
### Added
- Full monorepo with core, desktop, server, relay, cli
- End-to-end encryption (Argon2id + ChaCha20Poly1305)
- Agents.md / OpenClaw auto-updater with SafeFileOps
- P2P encrypted tunnel (QUIC + Noise) with optional relay
- Tauri 2 modern UI + tray + auto-updater + alerts
- All polish features (autostart, idle lock, biometric, etc.)

### Security
- Zero plaintext on disk
- File backup before every write
- Relay cannot read traffic
