# Self-update validation test suite for Windows Sandbox (Gate 3).
# Runs entirely with native Windows PowerShell and prebuilt test fixtures (no Python, no Git, no Delphi).
#
# Validates:
#   1. Loopback HTTP release feed serving with HttpListener
#   2. Launcher 1.0.0 update check against releases.json
#   3. Full update 1.0.0 -> 1.1.0 (swap, post-update confirmation, update_ok, Launcher.exe.old)
#   4. Second consecutive update 1.1.0 -> 1.2.0 (rotation of Launcher.exe.old)
#   5. Rollback watchdog (delete update_ok scenario)
#   6. Rollback watchdog for release crashing at start (1.3.0-fail)

[CmdletBinding()]
param(
    [string]$FixtureDir = "",
    [string]$WorkDir = "",
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($FixtureDir)) {
    $FixtureDir = Join-Path $PSScriptRoot "fixtures\selfupdate"
}
$FixtureDir = [System.IO.Path]::GetFullPath($FixtureDir)

if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path $env:TEMP "portappix_selfupdate_sandbox_test"
}
$WorkDir = [System.IO.Path]::GetFullPath($WorkDir)
if (-not (Test-Path $WorkDir)) {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
}

Write-Host "============================================================"
Write-Host "PORTAPPIX GATE 3: SELF-UPDATE SANDBOX VALIDATION"
Write-Host "  Fixture dir : $FixtureDir"
Write-Host "  Work dir    : $WorkDir"
Write-Host "  HTTP Port   : $Port"
Write-Host "============================================================"

if (-not (Test-Path (Join-Path $FixtureDir "1.0.0\Launcher.exe"))) {
    throw "Fixture directory $FixtureDir is missing 1.0.0\Launcher.exe. Run scripts\build_selfupdate_fixture.ps1 on the host first."
}

$FeedDir = Join-Path $FixtureDir "feed"
if (-not (Test-Path $FeedDir)) {
    throw "Fixture feed directory $FeedDir is missing."
}

# 1. Start background HTTP server using HttpListener
$ActiveFeedFile = Join-Path $env:TEMP "portappix_active_feed.txt"
Set-Content -Path $ActiveFeedFile -Value "releases-1.1.0.json" -NoNewline -Encoding utf8

$ServerScript = {
    param($FeedDir, $Port, $ActiveFeedFile)
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$Port/")
    try {
        $listener.Start()
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            $path = $request.Url.AbsolutePath.TrimStart('/')

            $activeFeedName = "releases-1.1.0.json"
            if (Test-Path $ActiveFeedFile) {
                $activeFeedName = (Get-Content $ActiveFeedFile -Raw).Trim()
            }

            $targetFile = $null
            if ($path -eq "releases.json") {
                $targetFile = Join-Path $FeedDir $activeFeedName
            } elseif ($path -eq "releases.json.sig") {
                $targetFile = Join-Path $FeedDir "$activeFeedName.sig"
            } else {
                $candidate = Join-Path $FeedDir $path
                if (Test-Path $candidate) {
                    $targetFile = $candidate
                }
            }

            if ($targetFile -and (Test-Path $targetFile)) {
                $bytes = [System.IO.File]::ReadAllBytes($targetFile)
                $response.StatusCode = 200
                $response.ContentLength64 = $bytes.Length
                $response.ContentType = "application/octet-stream"
                $response.OutputStream.Write($bytes, 0, $bytes.Length)
                $response.OutputStream.Close()
            } else {
                $response.StatusCode = 404
                $response.OutputStream.Close()
            }
        }
    } catch {
        # Normal shutdown
    } finally {
        $listener.Close()
    }
}

$ServerJob = Start-Job -ScriptBlock $ServerScript -ArgumentList $FeedDir, $Port, $ActiveFeedFile
Start-Sleep -Milliseconds 800

$Passed = 0
$Failed = 0

function Assert-Condition {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if ($Condition) {
        $Script:Passed++
        Write-Host "  [PASS] $Message" -ForegroundColor Green
    } else {
        $Script:Failed++
        Write-Host "  [FAIL] $Message" -ForegroundColor Red
        throw "Assertion failed: $Message"
    }
}

function Get-ExeVersion {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return "" }
    return [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path).FileVersion
}

try {
    # Verify HTTP listener is serving (poll with retry to allow background job startup)
    $ready = $false
    for ($i = 0; $i -lt 15; $i++) {
        try {
            $PingTest = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/releases.json" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($PingTest.StatusCode -eq 200) {
                $ready = $true
                break
            }
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    Assert-Condition $ready "HTTP loopback server is serving releases.json"

    # Step 1: Initialize working directory with 1.0.0
    Write-Host "`nStep 1: Setting up initial working directory with Launcher 1.0.0..."
    if (Test-Path $WorkDir) {
        Remove-Item $WorkDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    Copy-Item (Join-Path $FixtureDir "1.0.0\Launcher.exe") (Join-Path $WorkDir "Launcher.exe")
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.0.0.0") "Initial Launcher is version 1.0.0.0"

    # Step 2: Check updates
    Write-Host "`nStep 2: Testing update check against 1.1.0 release..."
    Set-Content -Path $ActiveFeedFile -Value "releases-1.1.0.json" -NoNewline -Encoding utf8
    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--check-updates http://127.0.0.1:$Port/releases.json --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Launcher --check-updates exited with code 0"

    # Step 3: Apply self-update 1.0.0 -> 1.1.0
    Write-Host "`nStep 3: Applying self-update 1.0.0 -> 1.1.0..."
    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--self-update http://127.0.0.1:$Port/releases.json --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Launcher --self-update exited with code 0"

    # Wait for spawned --post-update to complete
    $PostUpdateTimeout = 15
    $Elapsed = 0
    $UpdateOkPath = Join-Path $WorkDir "Cache\update_ok"
    while (-not (Test-Path $UpdateOkPath) -and ($Elapsed -lt $PostUpdateTimeout)) {
        Start-Sleep -Milliseconds 250
        $Elapsed += 0.25
    }

    Assert-Condition (Test-Path $UpdateOkPath) "Cache\update_ok marker was created by --post-update"
    $OkContent = Get-Content $UpdateOkPath -Raw
    Assert-Condition ($OkContent -match "1\.1\.0") "update_ok confirms update to 1.1.0"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.1.0.0") "Launcher.exe is now version 1.1.0.0"
    Assert-Condition (Test-Path (Join-Path $WorkDir "Launcher.exe.old")) "Launcher.exe.old backup copy exists"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe.old")) -eq "1.0.0.0") "Launcher.exe.old is the previous 1.0.0.0 version"

    # Step 4: Apply second consecutive self-update 1.1.0 -> 1.2.0
    Write-Host "`nStep 4: Applying second consecutive self-update 1.1.0 -> 1.2.0..."
    Set-Content -Path $ActiveFeedFile -Value "releases-1.2.0.json" -NoNewline -Encoding utf8

    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--self-update http://127.0.0.1:$Port/releases.json --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Second --self-update exited with code 0"

    # Wait for post-update
    Start-Sleep -Seconds 1
    $Elapsed = 0
    while ($Elapsed -lt $PostUpdateTimeout) {
        if (Test-Path $UpdateOkPath) {
            $OkContent = Get-Content $UpdateOkPath -Raw
            if ($OkContent -match "1\.2\.0") { break }
        }
        Start-Sleep -Milliseconds 250
        $Elapsed += 0.25
    }

    $OkContent = Get-Content $UpdateOkPath -Raw
    Assert-Condition ($OkContent -match "1\.2\.0") "Second update_ok confirms update to 1.2.0"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.2.0.0") "Launcher.exe is now version 1.2.0.0"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe.old")) -eq "1.1.0.0") "Launcher.exe.old was rotated and holds 1.1.0.0"

    # Step 5: Test rollback watchdog (delete update_ok scenario)
    Write-Host "`nStep 5: Testing rollback watchdog with deleted update_ok..."
    Remove-Item $UpdateOkPath -Force
    Assert-Condition (-not (Test-Path $UpdateOkPath)) "update_ok removed to simulate unconfirmed start"

    # Trigger rollback
    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--rollback --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Launcher --rollback exited with code 0"

    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.1.0.0") "Rollback restored Launcher.exe to version 1.1.0.0"
    $FailedFiles = Get-ChildItem -Path $WorkDir -Filter "Launcher.exe.failed_*"
    Assert-Condition ($FailedFiles.Count -ge 1) "Failing launcher was renamed to Launcher.exe.failed_*"

    # Step 6: Test failure case: release whose launcher crashes at start
    Write-Host "`nStep 6: Testing failure case with release crashing on startup..."
    # Re-confirm 1.1.0
    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--post-update --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru

    Set-Content -Path $ActiveFeedFile -Value "releases-1.3.0-fail.json" -NoNewline -Encoding utf8
    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--self-update http://127.0.0.1:$Port/releases.json --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Update to 1.3.0-fail staged and launched"

    # Allow spawned crashing launcher to attempt start and exit
    Start-Sleep -Seconds 2

    # update_ok must NOT exist because 1.3.0 crashed immediately on start
    Assert-Condition (-not (Test-Path $UpdateOkPath)) "update_ok was NOT created because 1.3.0 crashed on start"
    Assert-Condition (Test-Path (Join-Path $WorkDir "Launcher.exe.old")) "Launcher.exe.old is preserved"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe.old")) -eq "1.1.0.0") "Launcher.exe.old is the working 1.1.0.0"

    # Trigger rollback
    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--rollback --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Watchdog rollback executed cleanly"

    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.1.0.0") "Rollback watchdog restored working 1.1.0.0 launcher"

    Write-Host "`n============================================================"
    Write-Host "ALL SELF-UPDATE VALIDATION CHECKS PASSED: $Passed passed, 0 failed." -ForegroundColor Green
    Write-Host "============================================================"
    exit 0
}
finally {
    # Stop background server job
    if ($ServerJob) {
        Stop-Job $ServerJob -ErrorAction SilentlyContinue | Out-Null
        Remove-Job $ServerJob -Force -ErrorAction SilentlyContinue | Out-Null
    }
    Remove-Item $ActiveFeedFile -Force -ErrorAction SilentlyContinue
    Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
}
