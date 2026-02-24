# ClavisVault 🗝️

**The secure, beautiful, zero-.env developer key vault.**

Store API keys once. Never commit them again. Auto-inject into agents.md / OpenClaw.  
Cross-platform (Windows/macOS/Linux). Rust + Tauri. End-to-end encrypted.

## Quick Start
1. Download from GitHub Releases
2. Run → set master password
3. Add your keys
4. Link your projects → agents.md files auto-update safely

Built with extreme security and testing standards.

## Advanced Features
- Vault schema v2 with key rotation metadata and migration from legacy vaults.
- Signed export manifest v2 with checksum and signature verification on import.
- Tamper-evident audit chain with integrity verification commands.
- Policy-as-code validation from `policy/secret-policy.toml`.
- Recovery drill reports (`recovery-drill`) for backup/decryptability validation.
- Remote trust policy metadata (`permissions`, session TTL, session revoke/repair state).

## CLI Highlights
- `clavis rotate-key --name KEY_NAME [--value NEW_SECRET]`
- `clavis policy check [--policy policy/secret-policy.toml]`
- `clavis audit verify [--ledger <path>]`
- `clavis recovery-drill [--export-path <file>] [--export-passphrase <pass>]`

See `AGENTS.md` and `docs/SPEC.md` for developers.

⭐ Star us if you love not scattering secrets!
