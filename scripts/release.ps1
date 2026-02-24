$ErrorActionPreference = 'Stop'

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Tag
)

if ([string]::IsNullOrWhiteSpace($Tag)) {
    Write-Error "usage: $($MyInvocation.MyCommand.Name) <tag>"
    exit 1
}

$rootDir = Resolve-Path (Split-Path -Parent $PSScriptRoot)
$tagDir = Join-Path (Join-Path $rootDir 'releases') $Tag
$desktopDir = Join-Path $tagDir 'desktop'
$serverDir = Join-Path $tagDir 'server'
$relayDir = Join-Path $tagDir 'relay'

New-Item -ItemType Directory -Path $desktopDir, $serverDir, $relayDir -Force | Out-Null

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

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Error 'npm is required to build desktop frontend assets before packaging.'
    exit 1
}

$binarySuffix = if ($IsWindows) { '.exe' } else { '' }

function Ensure-CargoSubcommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subcommand,
        [Parameter(Mandatory = $true)]
        [string]$PackageName
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

function Copy-BundleArtifacts {
    param([Parameter(Mandatory = $true)] [string]$Bundle)

    $bundleDir = Join-Path (Join-Path (Join-Path $rootDir 'target/release/bundle') $Bundle)
    if (-not (Test-Path $bundleDir)) {
        Write-Error "missing desktop bundle directory: $bundleDir"
        exit 1
    }

    $artifacts = Get-ChildItem -Path $bundleDir -File
    if (-not $artifacts -or $artifacts.Count -eq 0) {
        Write-Error "no desktop artifacts produced in $bundleDir"
        exit 1
    }

    foreach ($artifact in $artifacts) {
        Copy-Item $artifact.FullName (Join-Path $desktopDir $artifact.Name)
    }
}

Ensure-CargoSubcommand 'tauri' 'tauri-cli'

Write-Output '[1/4] build desktop frontend assets'
npm --prefix (Join-Path $rootDir 'crates/desktop') ci
npm --prefix (Join-Path $rootDir 'crates/desktop') run build

Write-Output '[2/4] build workspace release binaries'
cargo build --workspace --release
Copy-Item (Join-Path $rootDir ("target/release/clavisvault-server$binarySuffix")) (Join-Path $serverDir ("clavisvault-server$binarySuffix"))
Copy-Item (Join-Path $rootDir ("target/release/clavisvault-relay$binarySuffix")) (Join-Path $relayDir ("clavisvault-relay$binarySuffix"))

Write-Output '[3/4] package desktop bundle'
if ($IsWindows) {
    $bundle = 'nsis'
} elseif ($IsMacOS) {
    $bundle = 'dmg'
} else {
    $bundle = 'appimage'
}

cargo tauri build --bundles $bundle --locked --ci
Copy-BundleArtifacts $bundle

Write-Output '[4/4] release outputs written'
Write-Output "Release artifacts ready for tag $Tag:"
Write-Output "  - desktop: $desktopDir"
Write-Output "  - server binaries: $(Join-Path $serverDir ("clavisvault-server$binarySuffix"))"
Write-Output "  - relay binaries: $(Join-Path $relayDir ("clavisvault-relay$binarySuffix"))"
