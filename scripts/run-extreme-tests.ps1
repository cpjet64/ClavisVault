$ErrorActionPreference = 'Stop'

$scriptPath = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$rootDir = Resolve-Path (Join-Path $scriptPath '..')
Set-Location $rootDir

$pythonBin = 'python3'
if (-not (Get-Command $pythonBin -ErrorAction SilentlyContinue)) {
    $pythonBin = 'python'
}

if ([string]::IsNullOrWhiteSpace($env:CLAVIS_EXTREME_FUZZ_SECONDS)) {
    if (-not [string]::IsNullOrWhiteSpace($env:CI)) {
        $CLAVIS_EXTREME_FUZZ_SECONDS = 60
    } else {
        $CLAVIS_EXTREME_FUZZ_SECONDS = 86400
    }
} else {
    try {
        $CLAVIS_EXTREME_FUZZ_SECONDS = [int]$env:CLAVIS_EXTREME_FUZZ_SECONDS
        if ($CLAVIS_EXTREME_FUZZ_SECONDS -lt 1) {
            throw
        }
    } catch {
        Write-Error 'CLAVIS_EXTREME_FUZZ_SECONDS must be a positive integer.'
        exit 1
    }
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $homeUser = $env:USERNAME
    if (-not $homeUser) {
        $homeUser = $env:USER
    }
    $cargoCandidates = @(
        (Join-Path $HOME '.cargo\bin'),
        (Join-Path (Join-Path 'C:\Users' $homeUser) '.cargo\bin')
    )

    foreach ($candidate in $cargoCandidates) {
        if (Test-Path (Join-Path $candidate 'cargo.exe')) {
            $env:PATH = "${candidate};$env:PATH"
            break
        }
    }
}

function Ensure-NodeTooling {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
        Write-Error 'npm is required to build desktop frontend assets before Rust gates.'
        exit 1
    }
}

function Build-DesktopFrontendAssets {
    Ensure-NodeTooling

    npm --prefix (Join-Path $rootDir 'crates/desktop') ci
    npm --prefix (Join-Path $rootDir 'crates/desktop') run build
}

function Ensure-CargoSubcommand {
    param(
        [Parameter(Mandatory = $true)] [string]$Subcommand,
        [Parameter(Mandatory = $true)] [string]$PackageName
    )

    $helpStatus = 0
    try {
        & cargo $Subcommand --help | Out-Null
    } catch {
        $helpStatus = 1
    }

    if ($helpStatus -ne 0) {
        cargo install $PackageName --locked
    }
}

function Invoke-CommandOrExit {
    param([Parameter(Mandatory = $true)] [string[]]$Command)
    & $Command[0] @($Command[1..($Command.Length - 1)])
}

Ensure-CargoSubcommand 'audit' 'cargo-audit'
Ensure-CargoSubcommand 'deny' 'cargo-deny'

Write-Output '[0/9] build desktop frontend assets'
Build-DesktopFrontendAssets

if (-not (Test-Path 'CHANGELOG.md')) {
    Write-Error 'missing CHANGELOG.md at repository root'
    exit 1
}

$tauriTestRequired = $env:CLAVIS_REQUIRE_TAURI_TESTS
if ([string]::IsNullOrWhiteSpace($tauriTestRequired)) {
    $tauriTestRequired = 'auto'
}

if ($tauriTestRequired -eq 'auto') {
    if ($env:CI -eq '1' -or -not [string]::IsNullOrWhiteSpace($env:CI)) {
        $tauriTestRequired = '1'
    } else {
        $tauriTestRequired = '1'
    }
}

switch ($tauriTestRequired.ToLowerInvariant()) {
    '1' { $tauriTestRequired = 1 }
    'true' { $tauriTestRequired = 1 }
    'yes' { $tauriTestRequired = 1 }
    'on' { $tauriTestRequired = 1 }
    '0' { $tauriTestRequired = 0 }
    'false' { $tauriTestRequired = 0 }
    'no' { $tauriTestRequired = 0 }
    'off' { $tauriTestRequired = 0 }
    default {
        Write-Error "invalid CLAVIS_REQUIRE_TAURI_TESTS value: $($env:CLAVIS_REQUIRE_TAURI_TESTS)"
        Write-Output 'expected one of: 1/true/yes/on or 0/false/no/off'
        exit 1
    }
}

$workspaceArgs = @('--workspace')
if ($tauriTestRequired -eq 0) {
    $workspaceArgs = @('--workspace', '--exclude', 'clavisvault-desktop-tauri')
    Write-Output 'TAURI tests are optional (CLAVIS_REQUIRE_TAURI_TESTS=0).'
    Write-Output 'Set CLAVIS_REQUIRE_TAURI_TESTS=1 (or unset) to enforce on all runs.'
}

Write-Output '[1/9] cargo check --all'
& cargo check @workspaceArgs --all-features

Write-Output '[2/9] root artifact checks'
Test-Path 'CHANGELOG.md' | Out-Null
if (Test-Path 'docs/CHANGELOG.md') {
    Write-Error 'docs/CHANGELOG.md must not exist; changelog must remain at repository root'
    exit 1
}

Write-Output '[2/9.1] advisory policy unit tests'
& $pythonBin (Join-Path $rootDir 'scripts/enforce_advisory_policy_test.py')
Write-Output '[2/10.2] desktop network policy regression tests'
& $pythonBin (Join-Path $rootDir 'scripts/check_desktop_network_policy_test.py')
& $pythonBin (Join-Path $rootDir 'scripts/check_desktop_network_policy.py')
& cargo test -p clavisvault-cli tests::shell_session_exports_include_vault_path_and_token
& cargo test -p clavisvault-cli tests::shell_portable_env_assignments
& cargo test -p clavisvault-cli tests::session_token_rejects_legacy_plaintext_format
& cargo test -p clavisvault-cli tests::shell_session_export_snippets_handle_shell_specific_quotes
& cargo test -p clavisvault-core tests::updates_file_and_creates_backup

Write-Output '[3/9] cargo clippy --all-targets --all-features -- -D warnings'
& cargo clippy @workspaceArgs --all-targets --all-features -- -D warnings

Write-Output '[4/9] cargo test --all'
& cargo test @workspaceArgs --all-features

Write-Output '[5/9] cargo test --manifest-path crates/desktop/src-tauri/Cargo.toml'
$tauriTestsAvailable = $true
if ($IsLinux) {
    if (-not (Get-Command pkg-config -ErrorAction SilentlyContinue)) {
        if ($tauriTestRequired -eq 1) {
            Write-Error 'desktop tauri smoke tests are required but GTK headers are missing (pkg-config not found)'
            exit 1
        }
        Write-Output 'Skipping desktop-tauri tests on Linux: pkg-config not found.'
        Write-Output 'Set CLAVIS_REQUIRE_TAURI_TESTS=1 to run (or install GTK dev packages).'
        $tauriTestsAvailable = $false
    } elseif (-not (pkg-config --exists glib-2.0 gio-2.0 gobject-2.0 gtk+-3.0 javascriptcoregtk-4.1 libsoup-3.0) ) {
        if ($tauriTestRequired -eq 1) {
            Write-Error 'desktop tauri smoke tests are required but GTK headers are missing'
            exit 1
        }
        Write-Output 'Skipping desktop-tauri tests on Linux: GTK dependencies missing.'
        Write-Output 'Set CLAVIS_REQUIRE_TAURI_TESTS=1 to run (or install GTK dev packages).'
        $tauriTestsAvailable = $false
    }
}

if ($tauriTestsAvailable) {
    & cargo test --manifest-path crates/desktop/src-tauri/Cargo.toml
    if ($LASTEXITCODE -ne 0) {
        if ($tauriTestRequired -eq 1) {
            exit $LASTEXITCODE
        }
        Write-Output 'WARNING: optional desktop tauri tests failed; use CLAVIS_REQUIRE_TAURI_TESTS=1 to fail hard.'
        $LASTEXITCODE = 0
    }
} elseif ($tauriTestRequired -ne 1) {
    Write-Output 'Desktop tauri tests were optional and are currently unavailable on this platform.'
} else {
    exit 1
}

Write-Output '[6/9] cargo deny check bans/licenses/sources'
& cargo deny check bans licenses sources

Write-Output '[7/9] enforce advisory policy'
& $pythonBin (Join-Path $rootDir 'scripts/enforce_advisory_policy.py')

Write-Output '[8/9] cargo audit'
& cargo audit

Write-Output '[9/9] ensure nightly + cargo-fuzz'
Ensure-CargoSubcommand 'fuzz' 'cargo-fuzz'

if (-not (rustup toolchain list | Select-String '^nightly')) {
    rustup toolchain install nightly --profile minimal
}

Write-Output "[9/9.1] fuzz smoke (core parsers + crypto invariants, $($CLAVIS_EXTREME_FUZZ_SECONDS)s each target)"
Push-Location (Join-Path $rootDir 'crates/core')
& cargo +nightly fuzz run vault_blob_parser -- "-max_total_time=$($CLAVIS_EXTREME_FUZZ_SECONDS)" -verbosity=0 -print_final_stats=1
& cargo +nightly fuzz run agents_guarded_section -- "-max_total_time=$($CLAVIS_EXTREME_FUZZ_SECONDS)" -verbosity=0 -print_final_stats=1
& cargo +nightly fuzz run vault_crypto_roundtrip -- "-max_total_time=$($CLAVIS_EXTREME_FUZZ_SECONDS)" -verbosity=0 -print_final_stats=1
& cargo +nightly fuzz run session_invariants -- "-max_total_time=$($CLAVIS_EXTREME_FUZZ_SECONDS)" -verbosity=0 -print_final_stats=1
Pop-Location

Write-Output 'Extreme testing suite completed successfully.'
