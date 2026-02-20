#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f CHANGELOG.md ]]; then
  echo "missing CHANGELOG.md at repository root"
  exit 1
fi

cargo check --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
