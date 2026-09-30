<#
.SYNOPSIS
    Copies the built KernelGuard Windows package onto the live USB stick's KGDATA partition.

.DESCRIPTION
    The stick's data partition is plain FAT32, so it can be filled from Windows after the image is
    written.  This stages the driver, the monitor, the INF and the deploy script into
    <Drive>:\windows\ and writes a SHA256SUMS.txt beside them, so the files can be checked on the
    target machine before anything is installed.

    It does not install, sign or load anything.  On the target machine, run (elevated):
        <Drive>:\windows\Deploy-KernelGuard.ps1 -SkipBuild
    which needs test-signing mode or a properly signed driver.  This packaging step has been
    syntax-reviewed only; it has not been run on Windows.

.PARAMETER Drive
    Drive letter of the KGDATA partition, e.g. E

.PARAMETER Configuration
    Which build output to take: Debug (default) or Release.

.EXAMPLE
    .\Build-UsbPayload.ps1 -Drive E -Configuration Release
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z]$')]
    [string]$Drive,

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug'
)

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$out  = Join-Path $repo "windows\x64\$Configuration"
$root = "$($Drive.ToUpper()):\"

if (-not (Test-Path (Join-Path $root 'kgdata.marker'))) {
    throw "$root is not a KernelGuard live stick (no kgdata.marker on it)"
}

$dest = Join-Path $root 'windows'
New-Item -ItemType Directory -Force -Path $dest | Out-Null

$files = @(
    (Join-Path $out  'KernelGuard.sys'),
    (Join-Path $out  'KernelGuardMonitor.exe'),
    (Join-Path $repo 'windows\KernelGuard.inf'),
    (Join-Path $repo 'windows\scripts\Deploy-KernelGuard.ps1')
)
foreach ($f in $files) {
    if (-not (Test-Path $f)) { throw "missing $f (build the $Configuration configuration first)" }
    Copy-Item -LiteralPath $f -Destination $dest -Force
}

$sums = Get-ChildItem -LiteralPath $dest -File |
    Where-Object { $_.Name -ne 'SHA256SUMS.txt' } |
    ForEach-Object { '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLower(), $_.Name }
Set-Content -LiteralPath (Join-Path $dest 'SHA256SUMS.txt') -Value $sums -Encoding ascii

Write-Host "Staged $($files.Count) files in $dest"
$sums | ForEach-Object { Write-Host "  $_" }
