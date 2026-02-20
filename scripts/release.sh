#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ -z "${tag}" ]]; then
  echo "usage: $0 <tag>"
  exit 1
fi

cargo build --workspace --release

echo "Release artifacts ready for tag ${tag}."
