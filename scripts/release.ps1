$ErrorActionPreference = 'Stop'

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Tag
)

if ([string]::IsNullOrWhiteSpace($Tag)) {
    Write-Error "usage: $($MyInvocation.MyCommand.Name) <tag>"
    exit 1
}

cargo build --workspace --release

Write-Output "Release artifacts ready for tag $Tag."
