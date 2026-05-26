#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys and installs the KernelGuard kernel-mode driver.

.DESCRIPTION
    Builds (optionally), signs, registers, and loads the KernelGuard.sys
    WDM kernel driver plus the KernelGuardMonitor.exe user-mode monitor.
    Requires test-signing mode and an elevated PowerShell session.

.PARAMETER Configuration
    Build configuration: Debug (default) or Release.

.PARAMETER Action
    install   - Build (unless -SkipBuild), sign (unless -SkipSign), register, and start.
    uninstall - Stop, unregister, and remove the driver.
    status    - Show current service and monitor status.
    build     - Build only; do not install.

.PARAMETER SkipBuild
    Skip MSBuild and use whatever .sys / .exe already exist in the output directory.

.PARAMETER SkipSign
    Skip the signing phase (use if you manage signing externally).

.EXAMPLE
    .\Deploy-KernelGuard.ps1
    .\Deploy-KernelGuard.ps1 -Configuration Release
    .\Deploy-KernelGuard.ps1 -SkipBuild
    .\Deploy-KernelGuard.ps1 -Action uninstall
    .\Deploy-KernelGuard.ps1 -Action status
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [ValidateSet('install', 'uninstall', 'status', 'build')]
    [string]$Action = 'install',

    [switch]$SkipBuild,
    [switch]$SkipSign
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ─────────────────────────────────────────────────────────────────
$DriverName   = 'KernelGuard'
$MonitorName  = 'KernelGuardMonitor'
$SysFile      = "$DriverName.sys"
$MonitorExe   = "$MonitorName.exe"
$RepoRoot     = $PSScriptRoot
$OutDir       = Join-Path $RepoRoot "x64\$Configuration"
$SysSource    = Join-Path $OutDir $SysFile
$MonitorBin   = Join-Path $OutDir $MonitorExe
$SolutionDir  = "$RepoRoot\"
$MSBuild      = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe'
$DriverVcxproj  = Join-Path $RepoRoot "src\$DriverName.vcxproj"
$MonitorVcxproj = Join-Path $RepoRoot "usermode\$MonitorName.vcxproj"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Header([string]$msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}
function Write-Ok([string]$msg)   { Write-Host "  [OK]  $msg" -ForegroundColor Green  }
function Write-Warn([string]$msg) { Write-Host "  [!]   $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "  [ERR] $msg" -ForegroundColor Red    }

# ── Pre-flight checks ─────────────────────────────────────────────────────────
function Assert-TestSigningEnabled {
    $lines = bcdedit /enum '{current}' 2>&1
    if ($lines -match 'testsigning\s+Yes') { return }
    Write-Fail 'Test signing is NOT enabled.'
    Write-Host @'

  Enable it from an elevated prompt, then reboot:

      bcdedit /set testsigning on

'@ -ForegroundColor Yellow
    exit 1
}

function Assert-HvciDisabled {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
    $val = Get-ItemProperty $key -Name Enabled -ErrorAction SilentlyContinue
    if ($val -and $val.Enabled -eq 1) {
        Write-Fail 'Memory Integrity (HVCI) is ENABLED — it blocks all test-signed drivers.'
        Write-Host @'

  Disable it before loading a test-signed driver:
    1. Windows Security → Device Security → Core isolation
    2. Memory integrity → turn OFF
    3. Reboot, then re-run this script.

'@ -ForegroundColor Yellow
        exit 1
    }
    Write-Ok 'Memory Integrity (HVCI) is off — test-signed driver loading is allowed.'
}

# ── Signing ───────────────────────────────────────────────────────────────────
function Get-SignTool {
    foreach ($root in @('C:\Program Files (x86)\Windows Kits\10\bin',
                         'C:\Program Files\Windows Kits\10\bin')) {
        if (-not (Test-Path $root)) { continue }
        $hit = Get-ChildItem $root -Filter 'signtool.exe' -Recurse -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -match '\\x64\\' } |
               Sort-Object FullName -Descending |
               Select-Object -First 1 -ExpandProperty FullName
        if ($hit) { return $hit }
    }
    return $null
}

function Invoke-Sign {
    Write-Header 'Signing driver (test certificate)'

    $certSubject = "CN=$DriverName Test Signing"
    $cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Subject -eq $certSubject -and $_.HasPrivateKey } |
            Select-Object -First 1

    if (-not $cert) {
        Write-Host '  Creating self-signed test code-signing certificate...'
        $cert = New-SelfSignedCertificate `
            -Subject $certSubject `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -Type CodeSigningCert `
            -HashAlgorithm SHA256 `
            -KeyUsage DigitalSignature `
            -KeyLength 2048
        Write-Ok "Certificate created  thumbprint=$($cert.Thumbprint)"
    } else {
        Write-Ok "Reusing existing certificate  thumbprint=$($cert.Thumbprint)"
    }

    # Trust the cert machine-wide so the kernel loader accepts it in test-signing mode
    foreach ($storeName in @('Root', 'TrustedPublisher')) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                     $storeName, 'LocalMachine')
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
            $store.Add($cert)
            Write-Ok "Added to LocalMachine\$storeName"
        }
        $store.Close()
    }

    $signtool = Get-SignTool
    if (-not $signtool) {
        Write-Fail 'signtool.exe not found under Windows Kits. Install the Windows SDK or pass -SkipSign.'
        exit 1
    }
    Write-Host "  signtool: $signtool"

    & $signtool sign /v /s My /sha1 $cert.Thumbprint /fd sha256 $SysSource
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "signtool failed (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }

    $sig = Get-AuthenticodeSignature $SysSource
    if ($sig.Status -ne 'Valid') {
        Write-Fail "Post-sign verification: status=$($sig.Status)  $($sig.StatusMessage)"
        exit 1
    }
    Write-Ok "Driver signed and verified  signer=$($sig.SignerCertificate.Subject)"
}

# ── Build ─────────────────────────────────────────────────────────────────────
function Invoke-MSBuild([string]$vcxproj, [string]$label) {
    if (-not (Test-Path $vcxproj)) {
        Write-Fail "$label project not found: $vcxproj"
        exit 1
    }
    Write-Host "  Building $label ..."
    & $MSBuild $vcxproj `
        /p:Configuration=$Configuration `
        /p:Platform=x64 `
        /p:"SolutionDir=$SolutionDir" `
        /v:minimal `
        /nologo
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "$label build failed (exit $LASTEXITCODE)."
        exit $LASTEXITCODE
    }
}

function Invoke-Build {
    Write-Header "Building all projects ($Configuration|x64)"

    if (-not (Test-Path $MSBuild)) {
        Write-Fail "MSBuild not found at: $MSBuild"
        Write-Host '  Update $MSBuild in this script to match your VS installation.' -ForegroundColor Yellow
        exit 1
    }

    Invoke-MSBuild $DriverVcxproj  "$DriverName (driver)"
    Write-Ok "Driver built   → $SysSource"

    Invoke-MSBuild $MonitorVcxproj "$MonitorName (monitor)"
    Write-Ok "Monitor built  → $MonitorBin"
}

# ── Status ────────────────────────────────────────────────────────────────────
function Show-CodeIntegrityLog {
    Write-Host "`n  Last Code Integrity events:" -ForegroundColor Yellow
    try {
        Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 6 `
            -ErrorAction Stop |
        ForEach-Object {
            Write-Host "    $($_.TimeCreated)  Id=$($_.Id)  $($_.Message -replace '\s+',' ')"
        }
    } catch {
        Write-Warn "Could not read CodeIntegrity/Operational log: $_"
    }
}

function Show-Status {
    Write-Header 'Driver status'

    $svc = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($svc) {
        $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Yellow' }
        Write-Host "  Service : $($svc.Status)" -ForegroundColor $color
        $imgPath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverName" `
                       -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
        if ($imgPath) { Write-Host "  Binary  : $imgPath" -ForegroundColor DarkGray }
    } else {
        Write-Warn "Service '$DriverName' is not registered."
    }

    $monProc = Get-Process -Name $MonitorName -ErrorAction SilentlyContinue
    if ($monProc) {
        Write-Ok "Monitor running (PID $($monProc.Id))"
    } else {
        Write-Warn 'Monitor is not running.'
    }

    # Show installed binary signature
    $installed = "$env:SystemRoot\system32\drivers\$SysFile"
    if (Test-Path $installed) {
        $sig = Get-AuthenticodeSignature $installed
        $sigColor = if ($sig.Status -eq 'Valid') { 'Green' } else { 'Red' }
        Write-Host "  Signature: $($sig.Status)" -ForegroundColor $sigColor
    }
}

# ── Install ───────────────────────────────────────────────────────────────────
function Invoke-Install {
    Write-Header 'Installing driver'

    if (-not (Test-Path $SysSource)) {
        Write-Fail "Driver binary not found: $SysSource"
        Write-Host '  Run without -SkipBuild, or build first.' -ForegroundColor Yellow
        exit 1
    }

    # ── Step 1: stop any running monitor + service ────────────────────────────
    $monProc = Get-Process -Name $MonitorName -ErrorAction SilentlyContinue
    if ($monProc) {
        $monProc | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Ok 'Monitor stopped.'
    }

    $svc = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running') {
            Write-Warn 'Driver running — stopping before reinstall.'
            sc.exe stop $DriverName 2>&1 | Out-Null
            # Wait for the driver to fully unload (kernel frees device objects)
            $deadline = (Get-Date).AddSeconds(10)
            do {
                Start-Sleep -Milliseconds 500
                $svc = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
            } until (-not $svc -or $svc.Status -eq 'Stopped' -or (Get-Date) -gt $deadline)

            if ($svc -and $svc.Status -ne 'Stopped') {
                Write-Fail 'Driver did not stop in time. Reboot may be required.'
                exit 1
            }
            Write-Ok 'Driver stopped.'
        }
        sc.exe delete $DriverName 2>&1 | Out-Null
        Write-Ok 'Old service registration removed.'
    }

    # ── Step 2: copy signed binary to system32\drivers ────────────────────────
    $sysInstalled = "$env:SystemRoot\system32\drivers\$SysFile"
    Copy-Item $SysSource -Destination $sysInstalled -Force
    Write-Ok "Copied $SysFile → $sysInstalled"

    $sig = Get-AuthenticodeSignature $sysInstalled
    if ($sig.Status -ne 'Valid') {
        Write-Fail "Installed binary signature invalid: $($sig.Status)"
        exit 1
    }
    Write-Ok "Signature valid  signer=$($sig.SignerCertificate.Subject)"

    # ── Step 3: write service registry entries ────────────────────────────────
    # Direct registry write avoids sc.exe pending-deletion races.
    $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverName"
    New-Item -Path $svcKey -Force | Out-Null

    Set-ItemProperty -Path $svcKey -Name 'Type'         -Value 1  -Type DWord
    # StartType 1 = SERVICE_SYSTEM_START for production; change to 3 (DEMAND_START) for dev
    Set-ItemProperty -Path $svcKey -Name 'Start'        -Value 3  -Type DWord
    Set-ItemProperty -Path $svcKey -Name 'ErrorControl' -Value 1  -Type DWord
    Set-ItemProperty -Path $svcKey -Name 'ImagePath'    -Value "\SystemRoot\System32\drivers\$SysFile" `
                                                        -Type ExpandString
    Set-ItemProperty -Path $svcKey -Name 'DisplayName'  -Value 'Side-Channel Attack Detection & Mitigation Driver' `
                                                        -Type String
    Set-ItemProperty -Path $svcKey -Name 'Group'        -Value 'Extended Base' -Type String
    Write-Ok 'Service registry entries written.'

    # ── Step 4: start the driver via sc ───────────────────────────────────────
    # KernelGuard is a WDM kernel driver — sc start is the correct
    # loader. fltmc is only for minifilter drivers registered with Filter Manager.
    Write-Host '  Starting driver with sc ...'
    $scOut = sc.exe start $DriverName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "sc start failed:`n$scOut"
        Show-CodeIntegrityLog
        Write-Host @'

  Common causes:
    - Test signing not enabled  (bcdedit /set testsigning on + reboot)
    - Memory Integrity (HVCI) is on  (Windows Security → disable + reboot)
    - Driver binary is unsigned or the cert is not in TrustedPublisher
    - Driver DriverEntry returned an error status (check DbgView / WinDbg)

'@ -ForegroundColor Yellow
        exit 1
    }
    Write-Ok "Driver started.`n$scOut"

    Show-Status

    # ── Step 5: launch monitor ────────────────────────────────────────────────
    if (Test-Path $MonitorBin) {
        Write-Header 'Starting monitor'
        Start-Process $MonitorBin
        Write-Ok "KernelGuardMonitor launched — look for the tray icon."
    } else {
        Write-Warn "Monitor binary not found at $MonitorBin — build it with -Action build."
    }
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
function Invoke-Uninstall {
    Write-Header 'Uninstalling driver'

    # Stop monitor first so the shared memory section handle is released
    Get-Process -Name $MonitorName -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Ok 'Monitor stopped (if running).'

    $svc = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running') {
            sc.exe stop $DriverName 2>&1 | Out-Null
            $deadline = (Get-Date).AddSeconds(10)
            do {
                Start-Sleep -Milliseconds 500
                $svc = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
            } until (-not $svc -or $svc.Status -eq 'Stopped' -or (Get-Date) -gt $deadline)
            Write-Ok 'Driver stopped.'
        }
        sc.exe delete $DriverName 2>&1 | Out-Null
        Write-Ok 'Service deleted.'
    } else {
        Write-Warn "Service '$DriverName' was not registered — nothing to delete."
    }

    $sysInstalled = "$env:SystemRoot\system32\drivers\$SysFile"
    if (Test-Path $sysInstalled) {
        Remove-Item $sysInstalled -Force
        Write-Ok "Removed $sysInstalled"
    }

    Write-Ok 'Uninstall complete.'
}

# ── Entry point ───────────────────────────────────────────────────────────────
Write-Host "`nKernelGuard Deployment Script" -ForegroundColor White
Write-Host "Action: $Action  |  Configuration: $Configuration" -ForegroundColor DarkGray

switch ($Action) {
    'status' {
        Show-Status
    }
    'build' {
        Invoke-Build
    }
    'install' {
        Assert-TestSigningEnabled
        Assert-HvciDisabled
        if (-not $SkipBuild) { Invoke-Build }
        if (-not $SkipSign)  { Invoke-Sign  }
        Invoke-Install
    }
    'uninstall' {
        Invoke-Uninstall
    }
}
