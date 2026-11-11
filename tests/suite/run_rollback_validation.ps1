# Production Rollback Validation (Gate 4 / Rollback Validation)
# Tests the production rollback path using the release binary (bin\Launcher.exe).
# Requires -IConfirmThisIsAVM.

[CmdletBinding()]
param(
    [switch]$IConfirmThisIsAVM,
    [string]$Launcher = "",
    [string]$FixtureDir = "",
    [string]$WorkDir = "",
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"

if (-not $IConfirmThisIsAVM) {
    throw "Refusing to run: run_rollback_validation.ps1 manipulates executable files and loopback feeds. Pass -IConfirmThisIsAVM to confirm you are in an isolated VM or Sandbox."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if ([string]::IsNullOrWhiteSpace($Launcher)) {
    $Launcher = Join-Path $RepoRoot "bin\Launcher.exe"
}
$Launcher = [System.IO.Path]::GetFullPath($Launcher)

if (-not (Test-Path $Launcher)) {
    throw "Production launcher not found at '$Launcher'. Build scripts\build_launcher.cmd first."
}

# Verify the launcher is a PRODUCTION binary: must NOT contain test defines
$launcherBytes = [System.IO.File]::ReadAllText($Launcher, [System.Text.Encoding]::Unicode)
if ($launcherBytes.Contains("PORTAPPIX_TESTCRASH_MARKER") -or $launcherBytes.Contains("PORTAPPIX_TESTUPDATE_ACTIVE")) {
    throw "Refusing '$Launcher': it contains test define markers. Production rollback validation requires the release build."
}

if ([string]::IsNullOrWhiteSpace($FixtureDir)) {
    $FixtureDir = Join-Path $PSScriptRoot "fixtures\selfupdate"
}
$FixtureDir = [System.IO.Path]::GetFullPath($FixtureDir)

if (-not (Test-Path (Join-Path $FixtureDir "1.0.0\Launcher.exe"))) {
    throw "Fixture directory '$FixtureDir' is missing 1.0.0\Launcher.exe. Run scripts\build_selfupdate_fixture.ps1 on the host first."
}

$FeedDir = Join-Path $FixtureDir "feed"
if (-not (Test-Path $FeedDir)) {
    throw "Fixture feed directory '$FeedDir' is missing."
}

if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path $env:TEMP "portappix_rollback_validation"
}
$WorkDir = [System.IO.Path]::GetFullPath($WorkDir)

Write-Host "============================================================"
Write-Host "PORTAPPIX: PRODUCTION ROLLBACK VALIDATION"
Write-Host "  Launcher    : $Launcher (Verified Production Build)"
Write-Host "  Fixture dir : $FixtureDir"
Write-Host "  Work dir    : $WorkDir"
Write-Host "  HTTP Port   : $Port"
Write-Host "============================================================"

# Background HTTP server using HttpListener
$ActiveFeedFile = Join-Path $env:TEMP "portappix_rollback_feed.txt"
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
    # Check HTTP listener
    $ready = $false
    for ($i = 0; $i -lt 15; $i++) {
        try {
            $ping = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/releases.json" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($ping.StatusCode -eq 200) { $ready = $true; break }
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    Assert-Condition $ready "HTTP loopback server is serving releases"

    # =========================================================================
    # Case 1: Update 1.0.0 -> 1.1.0, remove update_ok, trigger production rollback
    # =========================================================================
    Write-Host "`nCase 1: Update 1.0.0 -> 1.1.0, simulate missing update_ok, execute rollback..."
    if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    Copy-Item (Join-Path $FixtureDir "1.0.0\Launcher.exe") (Join-Path $WorkDir "Launcher.exe")
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.0.0.0") "Initial installation is 1.0.0.0"

    # Apply self-update to 1.1.0
    Set-Content -Path $ActiveFeedFile -Value "releases-1.1.0.json" -NoNewline -Encoding utf8
    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--self-update http://127.0.0.1:$Port/releases.json --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Update 1.0.0 -> 1.1.0 staged"

    $UpdateOkPath = Join-Path $WorkDir "Cache\update_ok"
    $Elapsed = 0
    while (-not (Test-Path $UpdateOkPath) -and ($Elapsed -lt 15)) {
        Start-Sleep -Milliseconds 250
        $Elapsed += 0.25
    }
    Assert-Condition (Test-Path $UpdateOkPath) "update_ok created confirming 1.1.0 update"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.1.0.0") "Launcher is updated to 1.1.0.0"
    Assert-Condition (Test-Path (Join-Path $WorkDir "Launcher.exe.old")) "Launcher.exe.old exists (1.0.0.0)"

    # Remove update_ok to simulate unconfirmed update failure
    Remove-Item $UpdateOkPath -Force
    Assert-Condition (-not (Test-Path $UpdateOkPath)) "Cache\update_ok removed"

    # Run production launcher with --accept-rollback
    Write-Host "Running production Launcher.exe with --accept-rollback..."
    $p = Start-Process -FilePath $Launcher `
        -ArgumentList "--accept-rollback --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Production launcher --accept-rollback exited with code 0"

    # Verify 1.0.0 is restored and Launcher.exe.old is consumed
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.0.0.0") "Rollback restored 1.0.0.0 launcher"
    Assert-Condition (-not (Test-Path (Join-Path $WorkDir "Launcher.exe.old"))) "Launcher.exe.old was consumed"
    $failedBuilds = Get-ChildItem -Path $WorkDir -Filter "Launcher.exe.failed_*"
    Assert-Condition ($failedBuilds.Count -ge 1) "Failing 1.1.0 launcher retained as Launcher.exe.failed_*"

    # =========================================================================
    # Case 2: Update 1.1.0 -> 1.3.0-fail (crashes at startup), trigger rollback
    # =========================================================================
    Write-Host "`nCase 2: Update 1.1.0 -> 1.3.0-fail (startup crash), execute rollback..."
    # Re-apply 1.1.0 cleanly first
    Set-Content -Path $ActiveFeedFile -Value "releases-1.1.0.json" -NoNewline -Encoding utf8
    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--self-update http://127.0.0.1:$Port/releases.json --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    $Elapsed = 0
    while (-not (Test-Path $UpdateOkPath) -and ($Elapsed -lt 15)) {
        Start-Sleep -Milliseconds 250
        $Elapsed += 0.25
    }
    Assert-Condition (Test-Path $UpdateOkPath) "Installation re-staged at 1.1.0.0 with confirmed update_ok"

    # Update to 1.3.0-fail
    Set-Content -Path $ActiveFeedFile -Value "releases-1.3.0-fail.json" -NoNewline -Encoding utf8
    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--self-update http://127.0.0.1:$Port/releases.json --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Update to 1.3.0-fail staged"

    Start-Sleep -Seconds 2

    # Verify 1.3.0-fail crashed on start: update_ok was NOT created
    Assert-Condition (-not (Test-Path $UpdateOkPath)) "update_ok was NOT created because 1.3.0-fail crashed on startup"
    Assert-Condition (Test-Path (Join-Path $WorkDir "Launcher.exe.old")) "Launcher.exe.old is preserved"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe.old")) -eq "1.1.0.0") "Launcher.exe.old is working 1.1.0.0"

    # Run production launcher with --accept-rollback
    Write-Host "Running production Launcher.exe with --accept-rollback..."
    $p = Start-Process -FilePath $Launcher `
        -ArgumentList "--accept-rollback --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Production launcher --accept-rollback exited 0"

    # Verify working 1.1.0 is restored
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.1.0.0") "Rollback restored working 1.1.0.0 launcher"
    Assert-Condition (-not (Test-Path (Join-Path $WorkDir "Launcher.exe.old"))) "Launcher.exe.old was consumed"

    # =========================================================================
    # Case 3: Update 1.1.0 -> 1.2.0, verify old_launcher.json, tamper Launcher.exe.old
    # =========================================================================
    Write-Host "`nCase 3: Update 1.1.0 -> 1.2.0, verify old_launcher.json, tamper Launcher.exe.old..."
    Set-Content -Path $ActiveFeedFile -Value "releases-1.2.0.json" -NoNewline -Encoding utf8
    $p = Start-Process -FilePath (Join-Path $WorkDir "Launcher.exe") `
        -ArgumentList "--self-update http://127.0.0.1:$Port/releases.json --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Update 1.1.0 -> 1.2.0 staged"

    $Elapsed = 0
    while (-not (Test-Path $UpdateOkPath) -and ($Elapsed -lt 15)) {
        Start-Sleep -Milliseconds 250
        $Elapsed += 0.25
    }
    Assert-Condition (Test-Path $UpdateOkPath) "update_ok created confirming 1.2.0 update"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.2.0.0") "Launcher is updated to 1.2.0.0"
    Assert-Condition (Test-Path (Join-Path $WorkDir "Launcher.exe.old")) "Launcher.exe.old exists (1.1.0.0)"

    # Verify old_launcher.json was recorded and contains correct metadata
    $RecordFile = Join-Path $WorkDir "Cache\old_launcher.json"
    Assert-Condition (Test-Path $RecordFile) "Cache\old_launcher.json created during update swap"
    $recordJson = Get-Content $RecordFile -Raw | ConvertFrom-Json
    $expectedOldHash = (Get-FileHash -Path (Join-Path $WorkDir "Launcher.exe.old") -Algorithm SHA256).Hash.ToLower()
    $expectedOldSize = (Get-Item (Join-Path $WorkDir "Launcher.exe.old")).Length
    Assert-Condition ($recordJson.schema -eq 1) "old_launcher.json schema is 1"
    Assert-Condition ($recordJson.sha256.ToLower() -eq $expectedOldHash) "old_launcher.json matches Launcher.exe.old SHA-256"
    Assert-Condition ($recordJson.size -eq $expectedOldSize) "old_launcher.json matches Launcher.exe.old size"

    # Remove update_ok to simulate watchdog rollback state
    Remove-Item $UpdateOkPath -Force
    Assert-Condition (-not (Test-Path $UpdateOkPath)) "Cache\update_ok removed"

    # Case 3a: Size-tampered Launcher.exe.old (appended byte)
    Write-Host "Testing rollback refusal on size-tampered Launcher.exe.old..."
    [System.IO.File]::AppendAllText((Join-Path $WorkDir "Launcher.exe.old"), "X")
    $p = Start-Process -FilePath $Launcher `
        -ArgumentList "--accept-rollback --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -ne 0) "Production launcher --accept-rollback failed on size-tampered .old (exit code != 0)"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.2.0.0") "Failed rollback left Launcher.exe untouched at 1.2.0.0"
    Assert-Condition (Test-Path (Join-Path $WorkDir "Launcher.exe.old")) "Launcher.exe.old was not consumed after size mismatch"

    # Case 3b: Content-tampered Launcher.exe.old (same size, modified byte)
    Write-Host "Testing rollback refusal on content-tampered Launcher.exe.old (hash mismatch)..."
    Copy-Item (Join-Path $FixtureDir "1.1.0\Launcher.exe") (Join-Path $WorkDir "Launcher.exe.old") -Force
    $oldBytes = [System.IO.File]::ReadAllBytes((Join-Path $WorkDir "Launcher.exe.old"))
    $oldBytes[128] = [byte]($oldBytes[128] -bxor 0xFF)
    [System.IO.File]::WriteAllBytes((Join-Path $WorkDir "Launcher.exe.old"), $oldBytes)
    $p = Start-Process -FilePath $Launcher `
        -ArgumentList "--accept-rollback --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -ne 0) "Production launcher --accept-rollback failed on content-tampered .old (exit code != 0)"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.2.0.0") "Failed rollback left Launcher.exe untouched at 1.2.0.0"
    Assert-Condition (Test-Path (Join-Path $WorkDir "Launcher.exe.old")) "Launcher.exe.old was not consumed after hash mismatch"

    # =========================================================================
    # Case 4: Missing old_launcher.json refuses rollback
    # =========================================================================
    Write-Host "`nCase 4: Testing rollback refusal on missing old_launcher.json..."
    Copy-Item (Join-Path $FixtureDir "1.1.0\Launcher.exe") (Join-Path $WorkDir "Launcher.exe.old") -Force
    Remove-Item $RecordFile -Force
    Assert-Condition (-not (Test-Path $RecordFile)) "old_launcher.json removed"
    $p = Start-Process -FilePath $Launcher `
        -ArgumentList "--accept-rollback --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -ne 0) "Production launcher --accept-rollback failed on missing record (exit code != 0)"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.2.0.0") "Failed rollback left Launcher.exe untouched at 1.2.0.0"
    Assert-Condition (Test-Path (Join-Path $WorkDir "Launcher.exe.old")) "Launcher.exe.old was not consumed when record was missing"

    # =========================================================================
    # Case 5: Record from earlier update does not validate newer .old
    # =========================================================================
    Write-Host "`nCase 5: Testing rollback refusal on mismatched record from earlier version..."
    $earlierHash = (Get-FileHash -Path (Join-Path $FixtureDir "1.0.0\Launcher.exe") -Algorithm SHA256).Hash.ToLower()
    $earlierRecord = @{
        schema = 1
        sha256 = $earlierHash
        size = $expectedOldSize
        version = "1.0.0"
        time = (Get-Date -Format "o")
        recordedAt = (Get-Date -Format "o")
    } | ConvertTo-Json
    Set-Content -Path $RecordFile -Value $earlierRecord -Encoding utf8
    $p = Start-Process -FilePath $Launcher `
        -ArgumentList "--accept-rollback --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -ne 0) "Production launcher --accept-rollback failed on mismatched hash record (exit code != 0)"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.2.0.0") "Failed rollback left Launcher.exe untouched at 1.2.0.0"
    Assert-Condition (Test-Path (Join-Path $WorkDir "Launcher.exe.old")) "Launcher.exe.old was not consumed on earlier record mismatch"

    # =========================================================================
    # Case 6: Verified rollback succeeds with valid record
    # =========================================================================
    Write-Host "`nCase 6: Testing verified rollback success with matching authentic record..."
    $validRecord = @{
        schema = 1
        sha256 = $expectedOldHash
        size = $expectedOldSize
        version = "1.1.0"
        time = (Get-Date -Format "o")
        recordedAt = (Get-Date -Format "o")
    } | ConvertTo-Json
    Set-Content -Path $RecordFile -Value $validRecord -Encoding utf8
    $p = Start-Process -FilePath $Launcher `
        -ArgumentList "--accept-rollback --root `"$WorkDir`"" `
        -NoNewWindow -Wait -PassThru
    Assert-Condition ($p.ExitCode -eq 0) "Production launcher --accept-rollback succeeded with matching record"
    Assert-Condition ((Get-ExeVersion (Join-Path $WorkDir "Launcher.exe")) -eq "1.1.0.0") "Rollback restored authentic 1.1.0.0 launcher"
    Assert-Condition (-not (Test-Path (Join-Path $WorkDir "Launcher.exe.old"))) "Launcher.exe.old was consumed"
    Assert-Condition (-not (Test-Path $RecordFile)) "old_launcher.json was consumed on rollback"

    Write-Host "`n============================================================"
    Write-Host "ALL PRODUCTION ROLLBACK VALIDATION CHECKS PASSED: $Passed passed, 0 failed." -ForegroundColor Green
    Write-Host "============================================================"
    exit 0
}
finally {
    if ($ServerJob) {
        Stop-Job $ServerJob -ErrorAction SilentlyContinue | Out-Null
        Remove-Job $ServerJob -Force -ErrorAction SilentlyContinue | Out-Null
    }
    Remove-Item $ActiveFeedFile -Force -ErrorAction SilentlyContinue
    Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
}
