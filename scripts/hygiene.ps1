$ErrorActionPreference = 'Stop'

Write-Output "=== Repo Hygiene Check ==="

$errors = 0

Write-Host -NoNewline "Large files (>10MB): "
$largeFiles = git ls-files | ForEach-Object {
    if (Test-Path $_) {
        $size = (Get-Item $_).Length
        if ($size -gt 10MB) {
            [PSCustomObject]@{
                File   = $_
                SizeMb = [int](($size / 1MB))
            }
        }
    }
}

if ($null -eq $largeFiles) {
    Write-Output "PASS"
} else {
    Write-Output "FAIL"
    $largeFiles | ForEach-Object {
        Write-Output "  $($_.File) ($($_.SizeMb)MB)"
    }
    $errors += 1
}

Write-Host -NoNewline "Merge conflict markers: "
$conflicts = git grep -l '<<<<<<< ' -- '*.rs' '*.toml' '*.json' '*.ts' '*.js' '*.py' '*.md' 2>$null
if ($LASTEXITCODE -eq 0 -and $conflicts) {
    Write-Output "FAIL — conflict markers found"
    $errors += 1
} else {
    Write-Output "PASS"
}

Write-Host -NoNewline "Required files: "
$missing = @()
foreach ($file in @('.gitignore')) {
    if (-not (Test-Path $file)) {
        $missing += $file
    }
}

if ($missing.Count -eq 0) {
    Write-Output "PASS"
} else {
    Write-Output "FAIL — missing:$($missing -join ' ')"
    $errors += 1
}

if ($errors -gt 0) {
    Write-Output "=== $errors hygiene issue(s) found ==="
    exit 1
}

Write-Output "=== All hygiene checks passed ==="
