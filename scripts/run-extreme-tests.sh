#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
PYTHON_BIN="python3"
if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  PYTHON_BIN="python"
fi

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

ensure_cargo_subcommand() {
  local subcommand="$1"
  local package_name="$2"
  if ! cargo "${subcommand}" --help >/dev/null 2>&1; then
    cargo install "${package_name}" --locked
  fi
}

ensure_cargo_subcommand "tarpaulin" "cargo-tarpaulin"
ensure_cargo_subcommand "audit" "cargo-audit"
ensure_cargo_subcommand "deny" "cargo-deny"

if [[ ! -f CHANGELOG.md ]]; then
  echo "missing CHANGELOG.md at repository root"
  exit 1
fi

TAURI_TEST_REQUIRED="${CLAVIS_REQUIRE_TAURI_TESTS:-auto}"
if [[ "${TAURI_TEST_REQUIRED}" == "auto" ]]; then
  if [[ "${CI:-0}" == "1" ]]; then
    TAURI_TEST_REQUIRED="1"
  else
    TAURI_TEST_REQUIRED="1"
  fi
fi
case "${TAURI_TEST_REQUIRED,,}" in
  1|true|yes|on)
    TAURI_TEST_REQUIRED="1"
    ;;
  0|false|no|off)
    TAURI_TEST_REQUIRED="0"
    ;;
  *)
    echo "invalid CLAVIS_REQUIRE_TAURI_TESTS value: ${TAURI_TEST_REQUIRED}"
    echo "expected one of: 1/true/yes/on or 0/false/no/off"
    exit 1
    ;;
esac

if [[ "${TAURI_TEST_REQUIRED}" == "1" ]]; then
  WORKSPACE_ARGS=(--workspace)
else
  WORKSPACE_ARGS=(--workspace --exclude clavisvault-desktop-tauri)
  echo "TAURI tests are optional (CLAVIS_REQUIRE_TAURI_TESTS=0)."
  echo "Set CLAVIS_REQUIRE_TAURI_TESTS=1 (or unset) to enforce on all runs."
fi

echo "[1/10] cargo check --all"
cargo check "${WORKSPACE_ARGS[@]}" --all-features

echo "[2/10] root artifact checks"
test -f CHANGELOG.md
if [[ -f docs/CHANGELOG.md ]]; then
  echo "docs/CHANGELOG.md must not exist; changelog must remain at repository root"
  exit 1
fi
echo "[2/10.1] validate audit ignore policy"
"${PYTHON_BIN}" "${ROOT_DIR}/scripts/validate_audit_exceptions.py" --deny-toml "${ROOT_DIR}/deny.toml"
"${PYTHON_BIN}" "${ROOT_DIR}/scripts/validate_audit_exceptions_test.py"
cargo test -p clavisvault-cli tests::shell_session_exports_include_vault_path_and_token
cargo test -p clavisvault-cli tests::shell_portable_env_assignments
cargo test -p clavisvault-cli tests::session_token_rejects_legacy_plaintext_format
cargo test -p clavisvault-cli tests::shell_session_export_snippets_handle_shell_specific_quotes
cargo test -p clavisvault-core tests::updates_file_and_creates_backup

echo "[3/10] cargo clippy --all-targets --all-features -- -D warnings"
cargo clippy "${WORKSPACE_ARGS[@]}" --all-targets --all-features -- -D warnings

echo "[4/10] cargo test --all"
cargo test "${WORKSPACE_ARGS[@]}" --all-features

echo "[5/10] cargo test --manifest-path crates/desktop/src-tauri/Cargo.toml"
if [[ "$(uname -s)" == "Linux" ]]; then
  if ! command -v pkg-config >/dev/null 2>&1; then
    if [[ "${TAURI_TEST_REQUIRED}" == "1" ]]; then
      echo "desktop tauri smoke tests are required but GTK headers are missing (pkg-config not found)"
      exit 1
    fi
    echo "Skipping desktop-tauri tests on Linux: pkg-config not found."
    echo "Set CLAVIS_REQUIRE_TAURI_TESTS=1 to run (or install GTK dev packages)."
    TAURI_TESTS_AVAILABLE="0"
  elif ! pkg-config --exists glib-2.0 gio-2.0 gobject-2.0 gtk+-3.0 javascriptcoregtk-4.1 libsoup-3.0; then
    if [[ "${TAURI_TEST_REQUIRED}" == "1" ]]; then
      echo "desktop tauri smoke tests are required but GTK headers are missing"
      exit 1
    fi
    echo "Skipping desktop-tauri tests on Linux: GTK dependencies missing."
    echo "Set CLAVIS_REQUIRE_TAURI_TESTS=1 to run (or install GTK dev packages)."
    TAURI_TESTS_AVAILABLE="0"
  else
    TAURI_TESTS_AVAILABLE="1"
  fi
else
  TAURI_TESTS_AVAILABLE="1"
fi

if [[ "${TAURI_TESTS_AVAILABLE}" == "1" ]]; then
  if ! cargo test --manifest-path crates/desktop/src-tauri/Cargo.toml; then
    if [[ "${TAURI_TEST_REQUIRED}" == "1" ]]; then
      exit 1
    fi
    echo "WARNING: optional desktop tauri tests failed; use CLAVIS_REQUIRE_TAURI_TESTS=1 to fail hard."
  fi
elif [[ "${TAURI_TEST_REQUIRED}" != "1" ]]; then
  echo "Desktop tauri tests were optional and are currently unavailable on this platform."
else
  exit 1
fi

echo "[6/10] cargo tarpaulin (core >=95%)"
cargo tarpaulin --config tarpaulin.toml --package clavisvault-core --lib --fail-under 95

echo "[7/10] cargo audit"
cargo audit

echo "[8/10] cargo deny check"
cargo deny check

echo "[9/10] ensure nightly + cargo-fuzz"
ensure_cargo_subcommand "fuzz" "cargo-fuzz"

if ! rustup toolchain list | grep -q "^nightly"; then
  rustup toolchain install nightly --profile minimal
fi

echo "[10/10] fuzz smoke (core parsers + crypto invariants)"
pushd crates/core >/dev/null
cargo +nightly fuzz run vault_blob_parser -- -max_total_time=45 -verbosity=0 -print_final_stats=1
cargo +nightly fuzz run agents_guarded_section -- -max_total_time=60 -verbosity=0 -print_final_stats=1
cargo +nightly fuzz run vault_crypto_roundtrip -- -max_total_time=60 -verbosity=0 -print_final_stats=1
cargo +nightly fuzz run session_invariants -- -max_total_time=60 -verbosity=0 -print_final_stats=1
popd >/dev/null

echo "Extreme testing suite completed successfully."
