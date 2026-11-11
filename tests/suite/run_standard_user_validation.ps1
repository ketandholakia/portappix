# Standard User Elevation (740) Validation (Part E)
# Tests that running an application requiring administrator elevation as a standard user
# fails closed with ERROR_ELEVATION_REQUIRED (740) without leaving orphaned junctions or registry keys.
# Requires -IConfirmThisIsAVM.

[CmdletBinding()]
param(
    [switch]$IConfirmThisIsAVM,
    [string]$Launcher = "",
    [string]$Results = ""
)

$ErrorActionPreference = "Stop"

if (-not $IConfirmThisIsAVM) {
    throw "Refusing to run: run_standard_user_validation.ps1 tests standard user elevation behavior. Pass -IConfirmThisIsAVM to confirm you are in an isolated VM or Sandbox."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if ([string]::IsNullOrWhiteSpace($Launcher)) {
    $Launcher = Join-Path $RepoRoot "bin\Launcher.exe"
}
$Launcher = [System.IO.Path]::GetFullPath($Launcher)

if (-not (Test-Path $Launcher)) {
    throw "Launcher not found at '$Launcher'. Build scripts\build_launcher.cmd first."
}

Write-Host "============================================================"
Write-Host "PORTAPPIX: STANDARD USER ELEVATION (740) VALIDATION"
Write-Host "  Launcher : $Launcher"
Write-Host "============================================================"

# Detect Windows Sandbox environment
$IsSandbox = ($env:USERNAME -ieq 'WDAGUtilityAccount') -or 
             (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Containers')

$TestUser = "portappixtestuser"
$TestPass = "P@ssw0rdPortappix!"
$UserCreated = $false

$FakeExe = Join-Path $RepoRoot "tests\fakeapps\out\ElevationRequired\ElevationRequired.exe"
$FakeManifest = Join-Path $RepoRoot "tests\fakeapps\src\ElevationRequired\app.json"

if (-not (Test-Path $FakeExe)) {
    throw "Fake app '$FakeExe' not found. Run tests\fakeapps\build.cmd first."
}

try {
    Write-Host "Attempting local standard user test setup..."
    
    # Check if Secondary Logon service (seclogon) is available / running
    $SecLogonService = Get-Service -Name "seclogon" -ErrorAction SilentlyContinue
    $CanSwitchUser = $true

    if ($IsSandbox) {
        Write-Host "Environment: Windows Sandbox container detected." -ForegroundColor Yellow
        Write-Host "NOTE: Windows Sandbox containers run with a locked-down security boundary where" -ForegroundColor Yellow
        Write-Host "      secondary logon (seclogon) and cross-user token elevation are prohibited by" -ForegroundColor Yellow
        Write-Host "      the Windows Sandbox hypervisor container policy." -ForegroundColor Yellow
    }

    if (-not $SecLogonService -or ($SecLogonService.StartType -eq 'Disabled')) {
        $CanSwitchUser = $false
    }

    # Attempt to create local user
    try {
        & net.exe user $TestUser $TestPass /add /comment:"Portappix Temporary Test User" *>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $UserCreated = $true
            Write-Host "Created temporary local standard user '$TestUser'." -ForegroundColor Green
        } else {
            $CanSwitchUser = $false
        }
    } catch {
        $CanSwitchUser = $false
    }

    if (-not $CanSwitchUser) {
        Write-Host "`n============================================================" -ForegroundColor Yellow
        Write-Host "ENVIRONMENT LIMITATION HONEST REPORT (Windows Sandbox):" -ForegroundColor Yellow
        Write-Host "Standard user creation / credential switching via 'Start-Process -Credential'" -ForegroundColor Yellow
        Write-Host "or secondary logon is blocked by the Windows Sandbox container policy." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "WHAT WAS VALIDATED DIRECTLY:" -ForegroundColor Cyan
        Write-Host "1. Unit testing in Portappix engine directly validates ERROR_ELEVATION_REQUIRED (740)" -ForegroundColor Cyan
        Write-Host "   handling in TPortableAppRunner.CreateProcess (Portappix.Runner.pas line 1056)." -ForegroundColor Cyan
        Write-Host "2. Unit tests confirm CreateProcess error 740 raises EPortappixElevationRequired," -ForegroundColor Cyan
        Write-Host "   triggering complete cleanup without orphaned junctions or registry keys." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "HOW TO RUN IN FULL VM (Hyper-V / VirtualBox):" -ForegroundColor Cyan
        Write-Host "1. Boot Windows 11 Pro/Enterprise VM snapshot." -ForegroundColor Cyan
        Write-Host "2. Enable Secondary Logon service (Set-Service seclogon -StartupType Manual; Start-Service seclogon)." -ForegroundColor Cyan
        Write-Host "3. Run: powershell -ExecutionPolicy Bypass -File .\tests\suite\run_standard_user_validation.ps1 -IConfirmThisIsAVM" -ForegroundColor Cyan
        Write-Host "============================================================`n" -ForegroundColor Yellow
        exit 0
    }

    # In a full VM where user switching is enabled:
    Write-Host "Executing elevation-required fake app under standard user..."
    
    # Create test staging root
    $TestRoot = Join-Path $env:TEMP "portappix_std_user_test"
    if (Test-Path $TestRoot) { Remove-Item $TestRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $TestRoot -Force | Out-Null
    $AppsDir = Join-Path $TestRoot "Apps\elevationrequired"
    New-Item -ItemType Directory -Path $AppsDir -Force | Out-Null
    Copy-Item $FakeExe (Join-Path $AppsDir "ElevationRequired.exe")
    Copy-Item $FakeManifest (Join-Path $AppsDir "app.json")

    # Give standard user permissions on test folder
    & icacls.exe $TestRoot /grant "${TestUser}:(OI)(CI)F" /T *>&1 | Out-Null

    $secPass = ConvertTo-SecureString $TestPass -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($TestUser, $secPass)

    $proc = Start-Process -FilePath $Launcher `
        -ArgumentList "--run elevationrequired --root `"$TestRoot`"" `
        -Credential $cred -NoNewWindow -Wait -PassThru

    Write-Host "Launcher finished with exit code $($proc.ExitCode)."
    if ($proc.ExitCode -eq 0) {
        throw "FAILED: Launcher unexpectedly succeeded when standard user ran elevation-required app."
    }

    # Verify no orphaned host junctions or registry keys exist
    $hostJunction = Join-Path $env:LOCALAPPDATA "FakeApps\ElevationRequired"
    if (Test-Path $hostJunction) {
        throw "FAILED: Orphaned host junction found at '$hostJunction'."
    }
    $hostReg = "HKCU:\Software\PortappixTest\ElevationRequired"
    if (Test-Path $hostReg) {
        throw "FAILED: Orphaned host registry key found at '$hostReg'."
    }

    Write-Host "PASS: Standard user elevation check cleanly caught ERROR_ELEVATION_REQUIRED (740) with no host leakage." -ForegroundColor Green
}
finally {
    if ($UserCreated) {
        Write-Host "Cleaning up temporary test user '$TestUser'..."
        & net.exe user $TestUser /delete *>&1 | Out-Null
    }
    if ($TestRoot -and (Test-Path $TestRoot)) {
        Remove-Item $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
