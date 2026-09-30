#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$SysFile = "C:\Users\fake_\OneDrive\Escritorio\SideChannelKernelPreventor\x64\Debug\SideChannelPreventor.sys"
$MonExe  = "C:\Users\fake_\OneDrive\Escritorio\SideChannelKernelPreventor\x64\Debug\SideChannelMonitor.exe"
$SvcName = "SideChannelPreventor"

function Write-Step($msg) { Write-Host "`n[....] $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "[ OK ] $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "[FAIL] $msg" -ForegroundColor Red }

# ── 1. Test-signing ────────────────────────────────────────────────────────────
Write-Step "Checking test-signing mode..."
$tsLine = bcdedit /enum "{current}" | Select-String "testsigning"
if ($tsLine -match "Yes") {
    Write-OK "Test-signing is already ON."
} else {
    Write-Host "  Test-signing is OFF. Enabling now..." -ForegroundColor Yellow
    bcdedit /set testsigning on | Out-Null
    Write-Host @"

  *** Test-signing has been ENABLED. ***
  A reboot is required before the driver can be loaded.
  Re-run this script after rebooting.
"@ -ForegroundColor Yellow
    pause
    exit 0
}

# ── 2. Sign the driver ─────────────────────────────────────────────────────────
Write-Step "Locating signtool.exe..."
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe |
    Where-Object { $_.FullName -match "x64" } | Sort-Object FullName -Descending | Select-Object -First 1 -Expand FullName
if (-not $signtool) { Write-Err "signtool.exe not found - is the WDK installed?"; pause; exit 1 }
Write-OK "signtool: $signtool"

Write-Step "Creating / reusing test code-signing certificate (CN=ScpdTestSign)..."
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq 'CN=ScpdTestSign' -and $_.HasPrivateKey } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Subject 'CN=ScpdTestSign' -CertStoreLocation 'Cert:\CurrentUser\My' -Type CodeSigningCert -HashAlgorithm SHA256
    Write-OK "Certificate created: $($cert.Thumbprint)"
} else {
    Write-OK "Reusing existing certificate: $($cert.Thumbprint)"
}
foreach ($store in @('Root','TrustedPublisher')) {
    $st = [System.Security.Cryptography.X509Certificates.X509Store]::new($store,'LocalMachine')
    $st.Open('ReadWrite')
    if (-not ($st.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) { $st.Add($cert) }
    $st.Close()
}

Write-Step "Signing driver..."
& $signtool sign /v /s My /sha1 $cert.Thumbprint /fd sha256 $SysFile
if ($LASTEXITCODE -ne 0) { Write-Err "Signing failed."; pause; exit 1 }
Write-OK "Driver signed."

# ── 3. Install service ─────────────────────────────────────────────────────────
$SysInstall = "$env:SystemRoot\System32\drivers\SideChannelPreventor.sys"

Write-Step "Removing any existing service..."
try { sc.exe stop  $SvcName 2>$null | Out-Null } catch {}
try { sc.exe delete $SvcName 2>$null | Out-Null } catch {}
Start-Sleep -Milliseconds 800

Write-Step "Copying driver to System32\drivers..."
Copy-Item $SysFile $SysInstall -Force
Write-OK "Copied to $SysInstall"

Write-Step "Creating service..."
sc.exe create $SvcName type= kernel start= demand binPath= $SysInstall DisplayName= "Side-Channel Prevention Driver"
if ($LASTEXITCODE -ne 0) { Write-Err "sc create failed."; pause; exit 1 }
Write-OK "Service created."

# ── 4. Start driver ────────────────────────────────────────────────────────────
Write-Step "Starting driver..."
sc.exe start $SvcName
if ($LASTEXITCODE -ne 0) { Write-Err "sc start failed - check Event Viewer (System log) for details."; pause; exit 1 }
Write-OK "Driver loaded."

# ── 5. Launch monitor ─────────────────────────────────────────────────────────
Write-Step "Launching monitor..."
Start-Process $MonExe
Write-OK "Monitor launched."

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " Deployment complete!" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green
pause
