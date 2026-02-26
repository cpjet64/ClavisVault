# ClavisVault Docs Index

## Core References
- [SPEC.md](./SPEC.md): authoritative project requirements and invariants aligned to current code.
- [ARCHITECTURE.md](./ARCHITECTURE.md): workspace architecture, trust boundaries, and data/control flow.
- [API.md](./API.md): command surfaces (desktop Tauri commands, CLI, server, relay).
- [TOOLING.md](./TOOLING.md): quality gates, CI matrix, release tooling, and test strategy.
- [alerts.md](./alerts.md): critical alert feed format consumed by desktop update flow.

## Workspace Map
- `crates/core`: cryptography, vault types, safe file operations, managed file updaters, policy, audit, recovery, rotation, export/import.
- `crates/desktop`: React 19 UI + Tauri backend runtime and command host.
- `crates/server`: headless QUIC + Noise endpoint for authenticated remote vault push.
- `crates/relay`: UDP signaling relay with protocol validation and strict rate limits.
- `crates/cli`: local and automation command line interface for vault operations.

## Security-Critical Guarantees
- No plaintext vault content is written to disk by core write paths.
- File mutations use backup + atomic write patterns via `SafeFileOps`.
- Master key material is zeroized and session-scoped.
- Relay cannot decrypt payloads; it forwards protocol-validated datagrams only.
- Desktop networking is constrained to updater + explicit P2P/remote flows.
