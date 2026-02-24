#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ -z "${tag}" ]]; then
  echo "usage: $0 <tag>"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

RELEASE_DIR="${ROOT_DIR}/releases/${tag}"
DESKTOP_DIR="${RELEASE_DIR}/desktop"
SERVER_DIR="${RELEASE_DIR}/server"
RELAY_DIR="${RELEASE_DIR}/relay"
mkdir -p "${DESKTOP_DIR}" "${SERVER_DIR}" "${RELAY_DIR}"

if ! command -v cargo >/dev/null 2>&1; then
  CARGO_HOME_CANDIDATES=(
    "${HOME}/.cargo/bin"
    "/c/Users/${USERNAME:-}/.cargo/bin"
    "/c/Users/${USER:-}/.cargo/bin"
  )

  for candidate in "${CARGO_HOME_CANDIDATES[@]}"; do
    if [[ -x "${candidate}/cargo" || -x "${candidate}/cargo.exe" ]]; then
      export PATH="${candidate}:${PATH}"
      break
    fi
  done
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to build frontend assets before packaging."
  exit 1
fi

ensure_cargo_subcommand() {
  local subcommand="$1"
  local package_name="$2"
  if ! cargo "${subcommand}" --help >/dev/null 2>&1; then
    cargo install "${package_name}" --locked
  fi
}

copy_bundle_artifacts() {
  local bundle="$1"
  local source_dir="${ROOT_DIR}/target/release/bundle/${bundle}"
  local target_dir="$DESKTOP_DIR"

  if [[ ! -d "${source_dir}" ]]; then
    echo "missing desktop bundle directory: ${source_dir}"
    exit 1
  fi

  shopt -s nullglob
  local source_files=("${source_dir}"/*)
  shopt -u nullglob
  if [[ ${#source_files[@]} -eq 0 ]]; then
    echo "no desktop artifacts produced in ${source_dir}"
    exit 1
  fi

  for artifact in "${source_files[@]}"; do
    cp "${artifact}" "${target_dir}/"
  done
}

ensure_cargo_subcommand "tauri" "tauri-cli"

echo "[1/4] build desktop frontend assets"
npm --prefix "${ROOT_DIR}/crates/desktop" ci
npm --prefix "${ROOT_DIR}/crates/desktop" run build

echo "[2/4] build workspace release binaries"
cargo build --workspace --release --locked
cp "${ROOT_DIR}/target/release/clavisvault-server" "${SERVER_DIR}/"
cp "${ROOT_DIR}/target/release/clavisvault-relay" "${RELAY_DIR}/"

echo "[3/4] package desktop bundle"
case "$(uname -s)" in
  Darwin*) BUNDLE="dmg" ;;
  MINGW*|MSYS*|CYGWIN*) BUNDLE="nsis" ;;
  *) BUNDLE="appimage" ;;
esac
cargo tauri build --bundles "${BUNDLE}" --locked --ci
copy_bundle_artifacts "${BUNDLE}"

echo "[4/4] release outputs written to ${RELEASE_DIR}"
echo "Release artifacts ready for tag ${tag}:"
echo "  - desktop: ${DESKTOP_DIR}"
echo "  - server binaries: ${SERVER_DIR}/clavisvault-server"
echo "  - relay binaries: ${RELAY_DIR}/clavisvault-relay"
