# Tooling, Verification, and Release

## Local Command Recipes
`Justfile` defines standard developer and agent gates.

Primary gates:
- `just ci-fast`
  - `hygiene`
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo machete`
  - `cargo build --all-targets --all-features --locked`
  - `cargo nextest run --locked --retries 2`
- `just ci-deep`
  - `ci-fast`
  - `cargo nextest run --all-features --locked --retries 2`
  - `cargo llvm-cov nextest --all-features --no-report`
  - `cargo llvm-cov report --lcov --output-path lcov.info`
  - `cargo deny check bans licenses sources`
  - `cargo audit`
  - `python scripts/enforce_advisory_policy.py`
  - `RUSTDOCFLAGS=-D warnings cargo doc --no-deps --all-features`

## CI Workflow
`.github/workflows/ci.yml` jobs:
- `check`: OS matrix on `ubuntu-24.04`, `windows-2022`, `macos-15`.
- `coverage`: core coverage threshold enforcement (`clavisvault-core >=95%`).
- `audit`: `cargo deny` + advisory policy + `cargo audit`.
- `extreme`: extended smoke with fuzz tooling and scripted extreme tests.
- `desktop-gui-e2e`: Windows Playwright desktop flow tests.

## Frontend Toolchain
Desktop frontend (`crates/desktop`):
- build/dev: Vite + React + TypeScript.
- scripts include Playwright install and E2E run commands.
- CI builds frontend artifacts before Rust desktop tests.

## Security Policy Tooling
- advisory policy script: `scripts/enforce_advisory_policy.py`
- network policy checks for desktop: 
  - `scripts/check_desktop_network_policy.py`
  - `scripts/check_desktop_network_policy_test.py`

## Release Tooling
- `scripts/release.ps1` (Windows)
- `scripts/release.sh` (Unix-like)

Release scripts:
- build frontend,
- build workspace release binaries,
- package desktop bundle (`nsis` / `dmg` / `appimage`),
- stage outputs under `releases/<tag>/`.

## Verification Expectations for Documentation Changes
For this repo, documentation-only change sets still run full quality gates before integration:
1. `just ci-fast`
2. `just ci-deep`
3. local commit (no push)
