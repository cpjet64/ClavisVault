# ClavisVault SPEC (v1.0 — February 19 2026)

## Project Overview
ClavisVault (Latin “clavis” = key) is a small, cross-platform, Rust-native desktop application whose sole purpose is to securely store, manage, and apply developer environment variables and API keys.  
It completely eliminates the need to commit `.env` files or scatter keys across projects.

Core requirements (non-negotiable):
- Written in Rust 2024 edition, minimum rust-version = 1.93.1.
- Single large Cargo workspace monorepo.
- Build each crate independently (core first, then desktop, server, relay, cli).
- Zero network capability in the desktop app except for the controlled updater and the optional P2P tunnel (all other traffic is forbidden).
- Complete end-to-end encryption at rest and in transit.
- Master-password / security-key protected vault.
- Runs in background with system tray icon.
- Auto-updater that polls GitHub + separate critical alerts system.
- Agents.md and OpenClaw support with project linker and automatic safe updates.
- Server version (headless) with direct encrypted P2P tunnel (QUIC + Noise).
- Optional public relay (NAT hole-punching) for users who cannot do direct connections.
- Extreme testing: ≥95% coverage, fuzzing, file-safety guarantees, security invariants enforced in CI.

Project name (must be unused): ClavisVault  
GitHub: github.com/YOURUSERNAME/clavisvault

## 1. Monorepo Layout
clavisvault/
├── Cargo.toml                  # workspace
├── rust-toolchain.toml         # channel = "1.93.1"
├── .github/workflows/ci.yml
├── crates/
│   ├── core/                   # lib
│   ├── desktop/                # Tauri 2 binary
│   ├── server/                 # headless binary
│   ├── relay/                  # headless relay binary
│   └── cli/                    # optional clavis CLI
├── assets/                     # icon.png (1024×1024), icon.icns, icon.ico
├── docs/
│   ├── SPEC.md                 # this file
│   ├── alerts.md               # YAML frontmatter alerts
│   └── CHANGELOG.md    # repo root
├── relay-public/               # Docker + systemd for hosted relay
└── scripts/
    ├── build-all.sh
    └── release.sh

Root Cargo.toml (exact)
[workspace]
members = ["crates/*"]
resolver = "3"

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.93.1"
license = "MIT OR Apache-2.0"
repository = "https://github.com/YOURUSERNAME/clavisvault"

[workspace.dependencies]
# Core
chacha20poly1305 = { version = "0.10", features = ["std"] }
argon2 = { version = "0.5", features = ["std"] }
zeroize = "1.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rmp-serde = "1.3"
chrono = { version = "0.4", features = ["serde"] }
dirs = "6.0"
notify = { version = "8.0", features = ["macos_fsevent"] }
anyhow = "1.0"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tokio = { version = "1.43", features = ["full"] }

# Desktop / Tauri
tauri = "2"
tauri-plugin-updater = "2"
tauri-plugin-single-instance = "2"
tauri-plugin-shell = "2"
tauri-plugin-dialog = "2"
tauri-plugin-store = "2"
tauri-plugin-biometric = "2"          # 2026 version
tauri-plugin-clipboard = "2"

# Network / P2P
quinn = "0.11"
snow = "0.9"
stun = "0.7"

# Others
rand = "0.8"
base32 = "0.2"
sha2 = "0.10"

## 2. Core Crate (crates/core) — Pure Business Logic
Types
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyEntry {
    pub name: String,           // UPPER_SNAKE_CASE
    pub description: String,
    pub tags: Vec<String>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct VaultData {
    pub version: u32,           // 1
    pub salt: [u8; 16],
    pub keys: std::collections::HashMap<String, KeyEntry>,
}

pub struct EncryptedVault { /* path, ciphertext, header */ }

Encryption (must never be violated)
- Argon2id (time_cost=4, memory_cost=19456 KiB, parallelism=1)
- ChaCha20Poly1305, 12-byte random nonce per save
- Master key derived once per unlock session
- zeroize::Zeroize on every secret on drop
- Never write plaintext to disk

SafeFileOps trait (critical)
pub trait SafeFileOps {
    fn backup(&self, path: &Path) -> Result<Backup>;   // keeps ≤10 timestamped .bak
    fn restore(&self, backup: Backup) -> Result<()>;
    fn atomic_write(&self, path: &Path, data: &[u8]) -> Result<()>;
}
Every agents.md / openclaw.json operation: backup → parse → replace guarded section → atomic_write.

Agents.md Updater
Exact markers:
<!-- CLAVISVAULT-START -->
## ClavisVault Managed Keys
**Last updated:** 2026-02-19 10:45:12 UTC

### API Keys
- `OPENAI_API_KEY` – …
<!-- CLAVISVAULT-END -->
Only replace between markers. If absent, append at end.

OpenClaw Support
Deep-merge into ~/.openclaw/openclaw.json (or user path) under "clavisVault" key + JSONC comment block in env.

ProjectLinker
- Explicit files list
- Recursive folder watch (notify::RecommendedWatcher, 800 ms debounce)
- On any vault change → update all linked files
- Auto-add new **/agents.md discovered in watched folders

ShellInjector
- Generates sourceable hooks for bash/zsh/fish/pwsh
- clavis env-load command (prompts password or uses cached session token)

Platform trait
pub trait Platform {
    fn data_dir() -> PathBuf;
    fn config_dir() -> PathBuf;
    fn set_autostart(enabled: bool, minimized: bool) -> Result<()>;
    fn create_tray_icon(...) -> Result<()>;
}
Implementations for Windows, macOS, Linux.

Polish features in core
- AuditLog (every operation: unlock, copy, push, file update)
- EncryptedExport (AES-256 ZIP with separate passphrase)
- Idle auto-lock timer support
- Biometric unlock hook
- Rate-limit failed password attempts (exponential backoff, wipe after 10 fails with warning)

## 3. Desktop Crate (Tauri 2.x)
Modern glassmorphic UI (React 19 + TS + Tailwind + shadcn/ui + lucide-react + Zustand + TanStack Query).  
Dark mode default.

UI Tabs
- Vault: searchable table, add/edit modal (strength meter), groups, bulk export
- Agents / OpenClaw: linked files + watch folders, “Update Now”
- Remotes: toggle “Enable Server Sync” (default OFF). When ON → new menu bar “Remotes” with “Add New” and one button per server.  
  - Add New supports IP:port or hostname + pairing code + relay fingerprint
  - List shows server name, key count, last sync
  - Remove server = remote erase vault + remove locally
- Settings: master password change, idle auto-lock (10 min default), launch on startup + minimized, update channel, relay endpoint (public or custom), clear clipboard after 30 s, audit log viewer, theme/accent picker, global Cmd/Ctrl+K search, biometric toggle, wipe-after-10-fails warning

Tray
Right-click: Open | Lock Vault | Check Updates | Quit  
Status dot: green(unlocked)/yellow(locked)/red(error)

Auto-Updater
- tauri-plugin-updater + GitHub fallback
- Also fetches docs/alerts.md
- alerts.md format (YAML frontmatter per version):
  version: "0.1.5"
  critical: true
  message: "CRITICAL: CVE-2026-XXXX — update immediately"
- Critical alert → non-dismissible modal until updated.

Security
- Vault lives only in tauri::State<DecryptedVault>
- No plaintext over invoke except explicit single-key copy (auto-clear clipboard)

P2P Client
QUIC + Noise_XX handshake over direct UDP or relay. Relay only does signalling.

## 4. Server Crate (headless)
clavisvault-server [--data-dir /var/lib/clavisvault]

- First run: prints one-time 8-char base32 pairing code + checksum (5 min TTL)
- After pairing: stores ed25519-signed JWT (90 days)
- Own master password (clavisvault-server set-password)
- Only accepts full-vault push over the encrypted tunnel
- Overwrites local vault, returns SHA-256 ACK
- No edit/delete API — desktop is source of truth
- Runs as tokio daemon, ready for systemd/Docker

## 5. Relay Crate
Listens on UDP 51820 (QUIC).  
Only forwards packets starting with magic b"CLAVISRL" + version 1 + sender pubkey hash.  
Rate-limit 50 pkt/s per IP.  
Never decrypts or stores payload.  
Pure signalling + hole-punch helper.  
Public instance: relay.clavisvault.app:51820  
Self-host option fully supported.

Custom protocol (anti-abuse)
Every packet:  
[8] CLAVISRL | [1] version | [2] len | [32] sender_pubkey_hash | [payload]

## 6. Additional Polish (implemented in desktop + core)
- Launch on startup + launch minimized
- Idle auto-lock (configurable)
- Biometric unlock (where supported)
- Audit log viewer
- Encrypted vault export/import
- Global quick-search (Cmd/Ctrl+K)
- Clear clipboard after 30 s
- Theme + accent color picker
- Rate-limit password attempts + wipe warning
- Offline-first (only updater/relay need net)
- Single-instance enforcement

## 7. Testing Requirements (must pass before any release)
- cargo tarpaulin --lib ≥95% on core
- 10 000 encryption round-trips
- File-safety tests (backup/restore on every write, corrupt simulation)
- 50+ agents.md / openclaw fixtures
- Full P2P integration (direct + relay) with MITM simulation (must fail)
- Updater + alerts parsing with wiremock
- Matrix: Windows 11, macOS 15, Ubuntu 24.04
- cargo fuzz 24 h on parsers & crypto
- cargo audit, cargo deny, clippy -D warnings

## 8. Distribution & Release
- GitHub Releases with .dmg, .exe, .AppImage, server & relay binaries
- Docker images for relay & server
- alerts.md and CHANGELOG.md always in repo root

Security Invariants (audited in every CI run)
1. No plaintext ever written to disk.
2. Master key never persisted.
3. Every file touch is backed up first.
4. Only guarded sections in agents.md / openclaw.json are modified.
5. Relay cannot read any traffic.
6. Desktop has zero network except updater & P2P tunnel (firewall-friendly).

This SPEC is complete and exhaustive. Any implementation that deviates must be rejected.
