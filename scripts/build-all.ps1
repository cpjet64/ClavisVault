$ErrorActionPreference = 'Stop'

if (-not (Test-Path 'CHANGELOG.md')) {
    Write-Error 'missing CHANGELOG.md at repository root'
    exit 1
}

cargo check --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
