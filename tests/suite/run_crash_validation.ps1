<#
.SYNOPSIS
    Portappix Phase 4A crash-validation harness (TEST-MODE launcher only).

.DESCRIPTION
    Drives real process-termination crash tests against the TEST-MODE
    launcher (built with -DPORTAPPIX_TESTCRASH). For each configured
    checkpoint it:

      1. Creates a fresh disposable launcher root under the results dir.
      2. Installs the CrashAtCheckpoint fake application (declared by
         tests\suite\crashfixtures\crashatcheckpoint\app.json - a dedicated
         fixture directory, NOT tests\suite\apps, because the compatibility
         suite auto-discovers that folder and must not run the
         parent-killing app as an ordinary case) with a known-good
         fixture: an original junction at %LOCALAPPDATA%\FakeApps\
         CrashAtCheckpoint pointing at a dedicated fixture folder, plus an
         original HKCU\Software\PortappixTest\CrashAtCheckpoint\Stamp value.
      3. Launches the test-mode launcher with PORTAPPIX_CRASH_AT set to the
         checkpoint and waits for it to terminate (it terminates ITSELF via
         TerminateProcess(exit=1) at the armed checkpoint, or is terminated
         by the fake app's KillParent in the post-launch scenario).
      4. Verifies the crash actually happened: exit code 1, and the durable
         journal matches the armed checkpoint (state:<name> must persist the
         armed state; op:<n>:<status> must leave operations[n] durably in
         <status>; op:<n>:created must leave operations[n] pending without a
         persisted identity, because 'created' is never a persisted status).
      5. FAKE-APP SURVIVAL: in the post-launch scenario the fake app was
         running when the launcher died. Its .started marker must exist and
         its .done marker (written AFTER KillParent, i.e. after the launcher
         died) must exist - that pair proves the app outlived launcher
         termination. A launcher exit code alone is NOT accepted as proof of
         a successful crash test. In the pre-launch scenarios the checkpoint
         fires before LaunchProcess, so the app must NOT have started.
      6. Captures the journal, the launcher log and the filesystem/registry
         state at crash time into the per-case results folder.
      7. Runs recovery twice with fresh test-mode launcher processes
         (no PORTAPPIX_CRASH_AT): the first pass must restore the original
         junction and registry value and drain the transaction storage; the
         second pass must be idempotent (identical host snapshot after both)
         and must never delete an object whose ownership cannot be
         established - proven here by the original junction still resolving
         to the ORIGINAL target and all original fixture data still intact.

    >>> RUN IN AN ISOLATED VM / WINDOWS SANDBOX ONLY. <<<
    The launcher deliberately hijacks HKCU registry keys and NTFS paths and
    the fake app terminates its parent process. A bug writes to your host.
    This script is executed manually; nothing in the unit tests or release
    packaging ever calls it.

    NOTE: process termination is NOT hard power loss. Hard power-loss /
    forced-reset validation of the journal remains a separate outstanding
    item; equivalent outcomes here do not prove equivalent outcomes at
    power loss.

.EXAMPLE
    # Build the test-mode launcher first (release invariant: the production
    # launcher contains no crash mechanism):
    #   dcc64 -B -E.\bin -N0.\bin -U.\src src\Launcher.dpr -DPORTAPPIX_TESTCRASH
    # move its Launcher.exe to bin\LauncherTestCrash.exe (Win32/Win64), or
    # pass -Launcher explicitly to any -DPORTAPPIX_TESTCRASH artifact.
    # Then inside Windows Sandbox / a Hyper-V checkpoint:
    powershell -ExecutionPolicy Bypass -File tests\suite\run_crash_validation.ps1 `
        -IConfirmThisIsAVM -Results C:\PortappixCrashResults

.PARAMETER Launcher
    Path to the TEST-MODE launcher exe (built with -DPORTAPPIX_TESTCRASH).
    Defaults to <repo>\bin\LauncherTestCrash.exe. A production launcher (no
    test-crash marker bytes) is REFUSED.

.PARAMETER Results
    Output directory for results.json, the summary and per-case artifacts.
    Defaults to %TEMP%\portappix-crash-validation-<timestamp>.

.PARAMETER RootParents
    Optional parent directory for the disposable per-case launcher roots.
    Defaults to the results directory. Refused if it is a drive root, the
    Windows directory, the user profile, AppData, LocalAppData, ProgramData,
    the repository root, or inside any of them.

.PARAMETER Checkpoints
    PRE-LAUNCH checkpoints to test (default: the deterministic set for this
    manifest's operation order - one junction + one registry key maps to
    operations 0=junctionRemoveOld, 1=registryBackup, 2=junctionCreate).
    The checkpoint fires before the fake app is ever started, so these
    cases assert that the launcher died alone with the expected journal.

.PARAMETER PostLaunchCheckpoints
    Checkpoints armed but never reached before the app kills the launcher;
    the launcher dies UNDER THE RUNNING FAKE APP, which is the scenario
    where fake-app survival proof is mandatory. Default: state:cleaning.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [switch] $IConfirmThisIsAVM,

    [string] $Launcher = "",

    [string] $Results = "",

    [string] $RootParents = "",

    [string[]] $Checkpoints = @(
        'state:prepared', 'state:hostBackupComplete', 'state:hostStateChanging',
        'state:hostStateChanged', 'state:running',
        'op:0:pending', 'op:0:done', 'op:1:pending', 'op:1:done',
        'op:2:pending', 'op:2:created', 'op:2:done'),

    [string[]] $PostLaunchCheckpoints = @('state:cleaning'),

    [switch] $KeepRoots
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# VM-only boundary: refuse to run without the explicit confirmation switch.
# ---------------------------------------------------------------------------
if (-not $IConfirmThisIsAVM) {
    throw 'Refusing to run: this harness performs real process termination and host-path hijacking. Run it ONLY inside an isolated Windows VM/Windows Sandbox with -IConfirmThisIsAVM.'
}

$SuiteDir = Split-Path -Parent $PSCommandPath
$RepoDir  = Split-Path -Parent (Split-Path -Parent $SuiteDir)
$FakeExe  = Join-Path $RepoDir 'tests\fakeapps\out\CrashAtCheckpoint\CrashAtCheckpoint.exe'
$Manifest = Join-Path $RepoDir 'tests\suite\crashfixtures\crashatcheckpoint\app.json'
$Marker   = 'PORTAPPIX-TESTCRASH-BUILD-2026-11-10'
$EnvVar   = 'PORTAPPIX_CRASH_AT'
$AppId    = 'crashatcheckpoint'

# ---------------------------------------------------------------------------
# Safety: refuse unsafe launcher/results/root locations (principles reused
# from tests\suite\run_suite.ps1; the appdata roots stay watch-only).
# ---------------------------------------------------------------------------
function Test-UnsafePath {
    param([string] $Path, [string] $Purpose)
    if (-not $Path) { return $null }
    $full  = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $lower = $full.ToLower()
    if ($full -match '^[A-Za-z]:$') {
        return "refusing ${Purpose}: '$full' is a drive root."
    }
    $windows = $env:SystemRoot.TrimEnd('\')
    $repo    = $RepoDir.TrimEnd('\')
    # The OS-managed scratch area is the designated disposable location; it
    # happens to live under the user profile on Windows, so a %TEMP% subtree
    # is accepted while the profile/AppData roots themselves are not.
    $tempFull = ''
    if ($env:TEMP) { $tempFull = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd('\').ToLower() }
    $inTemp = $tempFull -and ($lower -eq $tempFull -or $lower.StartsWith($tempFull + '\'))

    # Never inside (and never containing) the Windows directory or the repo.
    foreach ($base in @($windows, $repo)) {
        if (-not $base) { continue }
        $baseLower = $base.TrimEnd('\').ToLower()
        if ($lower -eq $baseLower -or $lower.StartsWith($baseLower + '\')) {
            return "refusing ${Purpose}: '$full' is inside protected '$base'."
        }
        if ($baseLower.StartsWith($lower + '\')) {
            return "refusing ${Purpose}: '$full' would contain protected '$base'."
        }
    }
    if (-not $inTemp) {
        foreach ($base in @($env:USERPROFILE, $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData)) {
            if (-not $base) { continue }
            $baseLower = $base.TrimEnd('\').ToLower()
            if ($lower -eq $baseLower -or $lower.StartsWith($baseLower + '\')) {
                if ($Purpose -eq 'results' -and $lower.EndsWith('\portappixsuiteresults')) {
                    continue
                }
                return "refusing ${Purpose}: '$full' is inside protected '$base'."
            }
            if ($baseLower.StartsWith($lower + '\')) {
                return "refusing ${Purpose}: '$full' would contain protected '$base'."
            }
        }
    }
    return $null
}

$unsafe = Test-UnsafePath -Path $Results -Purpose 'results'
if ($unsafe) { throw $unsafe }
$unsafe = Test-UnsafePath -Path $RootParents -Purpose 'root parents'
if ($unsafe) { throw $unsafe }

# ---------------------------------------------------------------------------
# Launcher identification: must be the TEST-MODE artifact (marker + env var
# string must both be present, checked against the UTF-16LE bytes Delphi
# embeds). Production launchers are refused.
# ---------------------------------------------------------------------------
if (-not $Launcher) { $Launcher = Join-Path $RepoDir 'bin\LauncherTestCrash.exe' }
if (-not (Test-Path $Launcher)) {
    throw "Test-mode launcher not found at '$Launcher'. Build src\Launcher.dpr with -DPORTAPPIX_TESTCRASH first (see docs/audit/phase-4/PHASE_4A_REPORT.md)."
}
$launcherTextUTF16 = [System.IO.File]::ReadAllText($Launcher, [System.Text.Encoding]::Unicode)
$markerOk = $launcherTextUTF16.Contains($Marker)
$envOk    = $launcherTextUTF16.Contains($EnvVar)
if (-not ($markerOk -and $envOk)) {
    throw "Refusing '$Launcher': it is not a TEST-MODE launcher (marker present: $markerOk; '$EnvVar' bytes present: $envOk). A production launcher must never be driven by this harness."
}

If (-not $Results) { $Results = Join-Path ([System.IO.Path]::GetTempPath()) ("portappix-crash-validation-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
New-Item -ItemType Directory -Force -Path $Results | Out-Null
$Results = (Resolve-Path $Results).Path

if (-not (Test-Path $FakeExe)) {
    $candidate = Get-ChildItem -Recurse -File -Path (Join-Path $RepoDir 'tests\fakeapps\out') -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq 'CrashAtCheckpoint.exe' } | Select-Object -First 1
    if ($candidate) { $FakeExe = $candidate.FullName }
}
if (-not (Test-Path $FakeExe)) {
    throw "Fake app '$FakeExe' not found. Run tests\fakeapps\build.cmd first."
}
if (-not (Test-Path $Manifest)) {
    throw "Fake app manifest '$Manifest' not found."
}

$hostJunctionPoint = Join-Path $env:LOCALAPPDATA 'FakeApps\CrashAtCheckpoint'
$hostAppDataWrite  = Join-Path $env:APPDATA 'FakeApps'
$regKeyPath        = 'HKCU:\Software\PortappixTest\CrashAtCheckpoint'

Write-Host 'Portappix Phase 4A crash validation (VM only)'
Write-Host "  Launcher : $Launcher"
Write-Host "              marker verified : $markerOk ; env bytes verified : $envOk"
Write-Host "  Results  : $Results"
Write-Host '  NOTE     : process termination is NOT hard power loss.'
Write-Host ''

$script:Failures = 0
$script:PassedCount = 0
$caseRecords = New-Object System.Collections.Generic.List[object]

function New-CaseRoot {
    param([string] $CaseId)
    if ($RootParents) {
        $caseRoot = Join-Path $RootParents $CaseId
    } else {
        $caseRoot = Join-Path $Results (Join-Path 'roots' $CaseId)
    }
    if (Test-Path $caseRoot) { Remove-Item -Recurse -Force $caseRoot }
    New-Item -ItemType Directory -Force -Path $caseRoot | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $caseRoot 'Apps') | Out-Null
    $appDir = Join-Path $caseRoot (Join-Path 'Apps' $AppId)
    New-Item -ItemType Directory -Force -Path $appDir | Out-Null
    Copy-Item -LiteralPath $Manifest (Join-Path $appDir 'app.json') -Force
    Copy-Item -LiteralPath $FakeExe (Join-Path $appDir 'CrashAtCheckpoint.exe') -Force
    return $caseRoot
}

function Clear-AppMarkers {
    # The .started/.state/.done markers live next to the fake app; drop any
    # leftovers from previous cases so assertions reflect THIS case only.
    $dir = Split-Path -Parent $FakeExe
    foreach ($suffix in @('started.txt', 'state.txt', 'done.txt')) {
        $p = Join-Path $dir ("CrashAtCheckpoint." + $suffix)
        if (Test-Path $p) { Remove-Item -Force $p }
    }
}

function Install-CrashFixture {
    param([string] $CaseId, [string] $CaseRoot)
    $originalTarget = Join-Path $CaseRoot 'FixtureOrigin'
    New-Item -ItemType Directory -Force -Path $originalTarget | Out-Null
    Set-Content -LiteralPath (Join-Path $originalTarget 'original-data.txt') -Value "original fixture for $CaseId"
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $hostJunctionPoint) | Out-Null
    if (Test-Path $hostJunctionPoint) {
        Remove-Item -Recurse -Force $hostJunctionPoint
    }
    New-Item -ItemType Junction -Path $hostJunctionPoint -Target $originalTarget | Out-Null
    New-Item -Path $regKeyPath -Force | Out-Null
    Set-ItemProperty -Path $regKeyPath -Name 'Stamp' -Value "fixture-$caseId"
    return [PSCustomObject]@{ OriginalTarget = $originalTarget; HostPath = $hostJunctionPoint }
}

function Remove-CrashFixture {
    if (Test-Path $hostJunctionPoint) {
        Remove-Item -Recurse -Force $hostJunctionPoint -ErrorAction SilentlyContinue
    }
    if (Test-Path $regKeyPath) {
        Remove-Item -Recurse -Force $regKeyPath -ErrorAction SilentlyContinue
    }
}

function Get-HostStateSnapshot {
    param([string] $OriginalTarget)
    $files = New-Object System.Collections.Generic.List[string]
    foreach ($dir in @($hostJunctionPoint, $OriginalTarget, $hostAppDataWrite)) {
        if (Test-Path $dir) {
            Get-ChildItem -Recurse -Force -File $dir |
                ForEach-Object { $files.Add("$($_.FullName.ToLower())|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)") }
        }
    }
    $files.Sort()
    $junction = '(absent)'
    if (Test-Path $hostJunctionPoint) {
        $targetVal = (Get-Item $hostJunctionPoint -Force).Target
        if ($targetVal -is [System.Array]) {
            $junction = [string]($targetVal | Select-Object -First 1)
        } else {
            $junction = [string]$targetVal
        }
    }
    $stamp = $null
    if (Test-Path $regKeyPath) {
        $stamp = [string](Get-ItemProperty -Path $regKeyPath -Name Stamp).Stamp
    }
    return [PSCustomObject]@{
        Files = ($files -join "`n")
        JunctionTarget = $junction
        RegistryStamp = $stamp
    }
}

function Invoke-TestLauncher {
    param(
        [string] $CaseId,
        [string] $CaseRoot,
        [string[]] $Arguments,
        [string] $CrashAt = ''
    )
    $logFile = Join-Path $Results ("log-$CaseId-" + [guid]::NewGuid().ToString('N') + '.txt')
    $previous = $null
    if (Test-Path env:$EnvVar) { $previous = (Get-Item env:$EnvVar).Value }
    if ($CrashAt) { Set-Item -Path "env:$EnvVar" -Value $CrashAt }
    else { Remove-Item -Path "env:$EnvVar" -ErrorAction SilentlyContinue }
    try {
        $argLine = "--root `"$CaseRoot`" --log-file `"$logFile`" " + ($Arguments -join ' ')
        $proc = Start-Process -FilePath $Launcher -ArgumentList $argLine -Wait -PassThru -NoNewWindow
        return [PSCustomObject]@{ ExitCode = $proc.ExitCode; LogFile = $logFile }
    }
    finally {
        if ($null -ne $previous) { Set-Item -Path "env:$EnvVar" -Value $previous }
        else { Remove-Item -Path "env:$EnvVar" -ErrorAction SilentlyContinue }
    }
}

function Get-LatestJournal {
    param([string] $CaseRoot)
    $txRoot = Join-Path $CaseRoot 'Transactions'
    if (-not (Test-Path $txRoot)) { return $null }
    $dirs = @(Get-ChildItem $txRoot -Directory)
    if ($dirs.Count -eq 0) { return $null }
    return ($dirs | Sort-Object Name -Descending | Select-Object -First 1)
}

# ---------------------------------------------------------------------------
# Per-case execution and assertions.
# ---------------------------------------------------------------------------
function Run-CrashCase {
    param([string] $Checkpoint, [bool] $PostLaunch)

    $script:Checks = New-Object System.Collections.Generic.List[bool]
    function Check {
        param($Condition, [string] $Name)
        if ($Condition -isnot [bool]) {
            $script:Checks.Add($false) | Out-Null
            Write-Host "         unmatched assert (non-boolean condition): $Name"
            return
        }
        if ($Condition) { $script:Checks.Add($true) | Out-Null }
        else {
            $script:Checks.Add($false) | Out-Null
            Write-Host "         unmatched assert: $Name"
        }
    }

    $caseId = ($Checkpoint -replace '[:]', '_')
    if ($PostLaunch) { $caseId = $caseId + '-postlaunch' }
    $caseDir  = Join-Path $Results $caseId
    $detail   = New-Object System.Collections.Generic.List[string]
    New-Item -ItemType Directory -Force -Path $caseDir | Out-Null
    $caseRoot = ''
    Clear-AppMarkers

    try {
        $caseRoot = New-CaseRoot -CaseId $caseId
        $fixture = Install-CrashFixture -CaseId $caseId -CaseRoot $caseRoot
        $before = Get-HostStateSnapshot -OriginalTarget $fixture.OriginalTarget
        $before | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $caseDir 'host-before.txt')

        $run = Invoke-TestLauncher -CaseId $caseId -CaseRoot $caseRoot `
            -Arguments @('--run', $AppId, '--wait', '--accept-policy') `
            -CrashAt $Checkpoint

        # (5) Launcher terminates through the crash/kill path (exit code 1).
        Check ($run.ExitCode -eq 1) "launcher exited with the crash exit code 1 (got $($run.ExitCode))"

        # (4) The durable journal matches the armed checkpoint.
        $tx = Get-LatestJournal -CaseRoot $caseRoot
        Check ($null -ne $tx) "a transaction journal directory exists after the crash"
        if ($tx) {
            $journalFile = Join-Path $tx.FullName 'transaction.json'
            Check (Test-Path $journalFile) "transaction.json is present after the crash"
            if (Test-Path $journalFile) {
                Copy-Item -LiteralPath $journalFile (Join-Path $caseDir 'transaction.json') -Force
                $journal = Get-Content -LiteralPath $journalFile -Raw | ConvertFrom-Json
                if (-not $PostLaunch -and $Checkpoint -match '^state:(.+)$') {
                    Check ($journal.state -eq $Matches[1]) "journal state is '$($Matches[1])' (got '$($journal.state)')"
                }
                if ($Checkpoint -match '^op:(\d+):(pending|done|absent|failed|restored|created)$') {
                    $idx = [int]$Matches[1]
                    $expectedStatus = $Matches[2]
                    $opCount = @($journal.operations).Count
                    Check ($opCount -gt $idx) "operations[$idx] exists in the journal"
                    if ($opCount -gt $idx) {
                        $op = $journal.operations[$idx]
                        $opStatus = [string]$op.status
                        if ($expectedStatus -eq 'created') {
                            Check ($opStatus -eq 'pending') "operations[$idx] stays pending because 'created' is never a persisted status (got '$opStatus')"
                            Check ([string]::IsNullOrEmpty([string]$op.identity)) "operations[$idx] carries no persisted identity yet"
                        } else {
                            Check ($opStatus -eq $expectedStatus) "operations[$idx].status is '$expectedStatus' (got '$opStatus')"
                            if ($expectedStatus -eq 'done' -and $op.kind -eq 'junctionCreate') {
                                Check (-not [string]::IsNullOrEmpty([string]$op.identity)) "operations[$idx] carries a Phase 3 junction identity"
                            }
                        }
                    }
                }
                if ($PostLaunch) {
                    Check ($journal.state -eq 'running') "the post-launch crash left the journal in 'running' (got '$($journal.state)')"
                }
            }
        }

        # (5) Fake-app expectations (survival proof is MANDATORY post-launch).
        $appDir        = Join-Path $caseRoot (Join-Path 'Apps' $AppId)
        $startedMarker = Join-Path $appDir 'CrashAtCheckpoint.started.txt'
        $stateMarker   = Join-Path $appDir 'CrashAtCheckpoint.state.txt'
        $doneMarker    = Join-Path $appDir 'CrashAtCheckpoint.done.txt'
        if (-not $PostLaunch) {
            Check (-not (Test-Path $startedMarker)) "the fake app was NOT launched before the pre-launch crash"
        } else {
            Check (Test-Path $startedMarker) "the fake app WAS started"
            Check (Test-Path $stateMarker) "the fake app wrote its state marker"
            Check (Test-Path $doneMarker) "the fake app SURVIVED launcher termination (done marker written after KillParent)"
            foreach ($file in @($startedMarker, $stateMarker, $doneMarker)) {
                if (Test-Path $file) { Copy-Item -LiteralPath $file (Join-Path $caseDir (Split-Path -Leaf $file)) -Force }
            }
            $alive = @(Get-Process -Name 'CrashAtCheckpoint' -ErrorAction SilentlyContinue)
            if ($alive.Count -gt 0) {
                $detail.Add("fake-app PID(s) observed still alive after launcher death: $(($alive | ForEach-Object { $_.Id }) -join ',')")
            }
        }

        # (6) Capture filesystem + registry state after the crash, plus log.
        $crashState = Get-HostStateSnapshot -OriginalTarget $fixture.OriginalTarget
        $crashState | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $caseDir 'host-after-crash.txt')
        if ($run.LogFile -and (Test-Path $run.LogFile)) {
            Copy-Item -LiteralPath $run.LogFile (Join-Path $caseDir 'launcher.log') -Force
        }

        # (7) Recovery pass 1: restores and drains.
        $recover1 = Invoke-TestLauncher -CaseId $caseId -CaseRoot $caseRoot -Arguments @('--recover')
        Check ($recover1.ExitCode -eq 0) "recovery pass 1 exited 0 (got $($recover1.ExitCode))"
        if ($Checkpoint -eq 'op:2:created') {
            Check ($null -ne (Get-LatestJournal -CaseRoot $caseRoot)) "recovery preserved the unowned transaction for manual review"
        } else {
            Check ($null -eq (Get-LatestJournal -CaseRoot $caseRoot)) "recovery pass 1 drained the transaction storage"
        }
        $after1 = Get-HostStateSnapshot -OriginalTarget $fixture.OriginalTarget
        $after1 | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $caseDir 'host-after-recovery-1.txt')
        if ($Checkpoint -eq 'op:2:created') {
            Check ($after1.JunctionTarget -ne '(absent)') "recovery preserved the unowned junction untouched"
        } else {
            Check ($after1.JunctionTarget -eq $fixture.OriginalTarget) "recovery restored the original junction target (got '$($after1.JunctionTarget)')"
        }
        Check (Test-Path (Join-Path $fixture.OriginalTarget 'original-data.txt')) "recovery kept the original fixture data (no non-owned deletion)"
        Check ($after1.RegistryStamp -eq "fixture-$caseId") "recovery restored the original registry value (got '$($after1.RegistryStamp)')"

        # (7) Recovery pass 2: idempotent.
        $recover2 = Invoke-TestLauncher -CaseId $caseId -CaseRoot $caseRoot -Arguments @('--recover')
        Check ($recover2.ExitCode -eq 0) "recovery pass 2 exited 0 (got $($recover2.ExitCode))"
        $after2 = Get-HostStateSnapshot -OriginalTarget $fixture.OriginalTarget
        Check ($after2.Files -eq $after1.Files) "recovery pass 2 changed nothing (idempotent)"
        if ($Checkpoint -eq 'op:2:created') {
            Check ($after2.JunctionTarget -eq $after1.JunctionTarget) "recovery pass 2 left the unowned junction untouched"

            # Assertions for unowned junction UX:
            $reviewPath = Join-Path $caseRoot 'Transactions\needs_review.json'
            Check (Test-Path $reviewPath) "needs_review.json exists under Transactions"
            if (Test-Path $reviewPath) {
                $reviewItems = Get-Content -Raw $reviewPath | ConvertFrom-Json
                $appReview = @($reviewItems) | Where-Object { $_.appId -eq $AppId }
                Check (@($appReview).Count -gt 0) "needs_review.json contains entry for '$AppId'"
                if (@($appReview).Count -gt 0) {
                    Check ($appReview[0].junctionPath -eq $fixture.HostPath) "review item recorded the unowned junction path"
                }
            }

            # Next --run for this app is refused with exit code 6
            $nextRun = Invoke-TestLauncher -CaseId $caseId -CaseRoot $caseRoot -Arguments @('--run', $AppId)
            Check ($nextRun.ExitCode -eq 6) "next --run for $AppId exited with 6 (CliExitNeedsReview, got $($nextRun.ExitCode))"
            $nextRunLog = ""
            if ($nextRun.LogFile -and (Test-Path $nextRun.LogFile)) {
                $nextRunLog = Get-Content -Raw $nextRun.LogFile
            }
            Check ([bool]($nextRunLog -match 'manual review' -or $nextRunLog -match '--clear-review')) "next --run mentions manual review / clear-review"

            # Other apps are NOT blocked: set up appdatawriter and verify it runs cleanly
            $otherAppDir = Join-Path $caseRoot 'Apps\appdatawriter'
            if (-not (Test-Path $otherAppDir)) {
                New-Item -ItemType Directory -Force -Path $otherAppDir | Out-Null
                $adwExe = Join-Path $RepoDir 'tests\fakeapps\out\AppDataWriter\AppDataWriter.exe'
                $adwManifest = Join-Path $RepoDir 'tests\fakeapps\src\AppDataWriter\app.json'
                if ((Test-Path $adwExe) -and (Test-Path $adwManifest)) {
                    Copy-Item -LiteralPath $adwExe (Join-Path $otherAppDir 'AppDataWriter.exe') -Force
                    Copy-Item -LiteralPath $adwManifest (Join-Path $otherAppDir 'app.json') -Force
                }
            }
            if (Test-Path (Join-Path $otherAppDir 'app.json')) {
                $otherRun = Invoke-TestLauncher -CaseId $caseId -CaseRoot $caseRoot -Arguments @('--run', 'appdatawriter', '--accept-policy')
                Check ($otherRun.ExitCode -eq 0) "other app 'appdatawriter' is NOT blocked and exited 0 (got $($otherRun.ExitCode))"
            }

            # Verify --clear-review requires --force or --delete-unowned-junction while junction exists
            $clearNoFlags = Invoke-TestLauncher -CaseId $caseId -CaseRoot $caseRoot -Arguments @('--clear-review', $AppId)
            Check ($clearNoFlags.ExitCode -ne 0) "--clear-review without flags failed while junction exists (got $($clearNoFlags.ExitCode))"

            # Verify --clear-review --delete-unowned-junction clears the item and removes junction
            $clearWithDel = Invoke-TestLauncher -CaseId $caseId -CaseRoot $caseRoot -Arguments @('--clear-review', $AppId, '--delete-unowned-junction')
            Check ($clearWithDel.ExitCode -eq 0) "--clear-review --delete-unowned-junction succeeded (got $($clearWithDel.ExitCode))"
            Check (-not (Test-Path $fixture.HostPath)) "unowned junction was removed by --clear-review --delete-unowned-junction"
            $afterClear = Invoke-TestLauncher -CaseId $caseId -CaseRoot $caseRoot -Arguments @('--run', $AppId, '--accept-policy')
            Check ($afterClear.ExitCode -ne 6) "after clearing review, app is no longer blocked with exit code 6"
        } else {
            Check ($after2.JunctionTarget -eq $fixture.OriginalTarget) "recovery pass 2 left the junction restored"
        }
        Check ($after2.RegistryStamp -eq $after1.RegistryStamp) "recovery pass 2 left the registry unchanged"
    }
    catch {
        $script:Checks.Add($false) | Out-Null
        $detail.Add("EXCEPTION: $($_.Exception.Message)") | Out-Null
        $detail.Add("stack: $($_.InvocationInfo.PositionMessage)") | Out-Null
    }
    finally {
        Remove-CrashFixture
        if ($caseRoot -and -not $KeepRoots) {
            Remove-Item -Recurse -Force $caseRoot -ErrorAction SilentlyContinue
        }
    }

    $passed = $true
    foreach ($c in $script:Checks) { if (-not $c) { $passed = $false } }
    if ($passed) { $script:PassedCount++ } else { $script:Failures++ }
    $status = 'PASS'; if (-not $passed) { $status = 'FAIL' }
    Write-Host "  [$status] $caseId"
    if (-not $passed) {
        foreach ($line in $detail) { Write-Host "         $line" }
    }
    $caseRecords.Add([PSCustomObject]@{
        checkpoint  = $Checkpoint
        postLaunch  = $PostLaunch
        launcher    = $Launcher
        markerVerified = $markerOk
        passed      = $passed
        assertCount = $script:Checks.Count
        detail      = (($detail -join '; '))
    })
}

foreach ($ckpt in $Checkpoints) { Run-CrashCase -Checkpoint $ckpt -PostLaunch $false }
foreach ($ckpt in $PostLaunchCheckpoints) { Run-CrashCase -Checkpoint $ckpt -PostLaunch $true }

# ---------------------------------------------------------------------------
# Results document. This records real process termination ONLY; none of it
# is evidence about the hard power-loss scenario.
# ---------------------------------------------------------------------------
$resultsDoc = [PSCustomObject]@{
    tool            = 'portappix-run-crash-validation'
    mode            = 'real process termination (TerminateProcess / fake-app KillParent); NOT hard power loss'
    runnerEnvironment = 'must be an isolated VM/Windows Sandbox (enforced by -IConfirmThisIsAVM)'
    launcher        = $Launcher
    testModeMarkerVerified = $markerOk
    envVarBytesVerified    = $envOk
    fakeAppSurvivalProven  = ($caseRecords | Where-Object { $_.postLaunch -and $_.passed }).Count
    checkpointCount = ($Checkpoints.Count + $PostLaunchCheckpoints.Count)
    passed          = $script:PassedCount
    failed          = $script:Failures
    cases           = $caseRecords
    generatedAt     = (Get-Date -Format o)
}
$jsonPath = Join-Path $Results 'results.json'
$resultsDoc | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
Write-Host ''
Write-Host "Summary: $($resultsDoc.passed) passed, $($resultsDoc.failed) failed -> $jsonPath"
if ($script:Failures -gt 0) { exit 1 } else { exit 0 }
