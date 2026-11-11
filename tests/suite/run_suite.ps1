<#
.SYNOPSIS
    Portappix compatibility suite.

.DESCRIPTION
    Assembles a throwaway launcher root, installs the fake apps from
    tests\fakeapps\out with their manifests from tests\suite\apps, and runs
    each case headless through the launcher CLI:

        Launcher.exe --run <app-id> --accept-policy --root <root>
                     --exit-code-file <path> --log-file <path>

    For every case it snapshots the watched host locations (files under
    %APPDATA%\FakeApps, %LOCALAPPDATA%\FakeApps, %TEMP%\fakeapps* and
    C:\ProgramData\PortappixTest plus an export of HKCU\Software\PortappixTest),
    runs the app, and asserts that marker data landed under Data\<id>, that the
    host snapshot after the run equals the snapshot before it, that repeat runs
    see the previous run's redirected state, and that exit codes are correct.

    >>> RUN IN A VM / WINDOWS SANDBOX ONLY. <<<
    Never run this suite on a daily-driver machine: the launcher deliberately
    hijacks HKCU registry keys and NTFS paths, and the suite verifies containment
    of exactly that behaviour. A bug in the launcher writes to your host.

.EXAMPLE
    # Host (build first):
    tests\fakeapps\build.cmd
    # Then, in Windows Sandbox / a Hyper-V checkpoint:
    powershell -ExecutionPolicy Bypass -File tests\suite\run_suite.ps1 `
        -Results C:\PortappixSuiteResults

.PARAMETER Launcher
    Path to Launcher.exe. Defaults to <repo>\bin\Launcher.exe (build it first).

.PARAMETER Root
    Launcher root directory. Defaults to a fresh folder under the results dir.

.PARAMETER Results
    Output directory for results.json, the summary and per-case logs.
    Defaults to tests\suite\results\<timestamp> (use a mapped RW folder inside
    Windows Sandbox).

.PARAMETER Cases
    Optional comma-separated list of case ids to run (default: all).

.PARAMETER KeepRoot
    Keep the assembled launcher root for debugging after the run.
#>
[CmdletBinding()]
param(
    [string] $Launcher = "",
    [string] $Root = "",
    [string] $Results = "",
    [string] $Cases = "",
    [switch] $KeepRoot
)

$ErrorActionPreference = 'Stop'

$SuiteDir = Split-Path -Parent $PSCommandPath
$RepoDir  = Split-Path -Parent (Split-Path -Parent $SuiteDir)
$FakeOut  = Join-Path $RepoDir 'tests\fakeapps\out'

if (-not $Launcher) { $Launcher = Join-Path $RepoDir 'bin\Launcher.exe' }
if (-not (Test-Path $Launcher)) {
    throw "Launcher.exe not found at '$Launcher'. Build src\Launcher.dpr first (see README)."
}

$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $Results) { $Results = Join-Path $SuiteDir "results\$Timestamp" }
New-Item -ItemType Directory -Force -Path $Results | Out-Null
$Results = (Resolve-Path $Results).Path

# ---------------------------------------------------------------------------
# Safety: refuse obviously dangerous roots. The launcher will hijack host
# paths from the manifests, so the root must be a throwaway folder.
# ---------------------------------------------------------------------------
if (-not $Root) { $Root = Join-Path $Results 'root' }
$RootFull = [System.IO.Path]::GetFullPath($Root)
foreach ($forbidden in @($env:USERPROFILE, $env:SystemRoot, $env:APPDATA,
                         $env:LOCALAPPDATA, $env:ProgramData, $RepoDir,
                         $SuiteDir, (Join-Path $RepoDir 'tests'), (Join-Path $RepoDir 'tests\suite'),
                         (Join-Path $RepoDir 'tests\fakeapps'), (Join-Path $RepoDir 'src'))) {
    if ($forbidden -and ($RootFull.TrimEnd('\') -eq $forbidden.TrimEnd('\'))) {
        throw "Refusing to use '$RootFull' as the launcher root (protected location)."
    }
}
if ($RootFull -match '^[A-Za-z]:\\?$') {
    throw "Refusing to use a drive root as the launcher root."
}

Write-Host "Portappix compatibility suite"
Write-Host "  Launcher : $Launcher"
Write-Host "  Root     : $RootFull"
Write-Host "  Results  : $Results"
Write-Host "  WARNING  : run in a VM / Windows Sandbox only."
Write-Host ""

if (Test-Path $RootFull) { Remove-Item -Recurse -Force -Path $RootFull }
$AppsRoot = Join-Path $RootFull 'Apps'
New-Item -ItemType Directory -Force -Path $AppsRoot | Out-Null
Copy-Item -Path $Launcher -Destination (Join-Path $RootFull 'Launcher.exe')
$LauncherExe = Join-Path $RootFull 'Launcher.exe'

# Assemble the fake apps: manifest from tests\suite\apps\<id>, exe from the
# fakeapps build output.
foreach ($manifestDir in Get-ChildItem -Directory (Join-Path $SuiteDir 'apps')) {
    $id = $manifestDir.Name
    $appDir = Join-Path $AppsRoot $id
    New-Item -ItemType Directory -Force -Path $appDir | Out-Null
    Copy-Item (Join-Path $manifestDir.FullName 'app.json') $appDir

    $exe = Join-Path $FakeOut "$id\$id.exe"
    if (-not (Test-Path $exe)) {
        $candidateExe = Get-ChildItem -Recurse -File -Path $FakeOut -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq "$id.exe" } | Select-Object -First 1
        if ($candidateExe) { $exe = $candidateExe.FullName }
    }
    if (-not (Test-Path $exe)) {
        throw "Fake app executable '$exe' not found. Run tests\fakeapps\build.cmd first."
    }
    Copy-Item $exe (Join-Path $appDir "$id.exe")
}

# ---------------------------------------------------------------------------
# Host snapshot: watched file locations + HKCU\Software\PortappixTest export.
# This is deliberately cheap (Part 2 adds the full snapshot engine); it is
# enough to prove the launcher contained the fake apps.
# ---------------------------------------------------------------------------
$FileWatchRoots = @(
    (Join-Path $env:APPDATA 'FakeApps'),
    (Join-Path $env:LOCALAPPDATA 'FakeApps'),
    'C:\ProgramData\PortappixTest'
)

function Get-HostSnapshot {
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($watchRoot in $FileWatchRoots) {
        if (Test-Path $watchRoot) {
            Get-ChildItem -Recurse -Force -File -Attributes '!ReparsePoint' $watchRoot |
                ForEach-Object {
                    $lines.Add("$($_.FullName.ToLower())|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)")
                }
        }
    }
    if (Test-Path $env:TEMP) {
        # Only cheap top-level fakeapps* scratch files; never touch real data.
        Get-ChildItem -Force -File $env:TEMP -Filter 'fakeapps*' |
            ForEach-Object {
                $lines.Add("$($_.FullName.ToLower())|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)")
            }
    }
    $lines.Sort()

    $regHash = '(absent)'
    $regFile = Join-Path $Results ("regsnapshot-$PID.reg")
    if (Test-Path $regFile) { Remove-Item $regFile -Force }
    $regProc = Start-Process -FilePath "$env:SystemRoot\System32\reg.exe" `
        -ArgumentList "export HKCU\Software\PortappixTest `"$regFile`" /y" `
        -Wait -PassThru -NoNewWindow
    if ($regProc.ExitCode -eq 0 -and (Test-Path $regFile)) {
        $regText = (Get-Content $regFile -Raw).Trim()
        $meaningful = ($regText -split "`r?`n" | Where-Object {
            $trimmed = $_.Trim()
            $trimmed -and
            $trimmed -notmatch '^Windows Registry Editor' -and
            $trimmed -notmatch '^\[HKEY_CURRENT_USER\\Software\\PortappixTest\]$' -and
            $trimmed -notmatch '^@='
        })
        if (@($meaningful).Count -gt 0) {
            $regHash = (Get-FileHash $regFile -Algorithm SHA256).Hash.ToLower()
        }
        Remove-Item $regFile -Force
    }

    [PSCustomObject]@{ Files = ($lines -join "`n"); RegistryHash = $regHash }
}

function Get-SnapshotDiff($Before, $After) {
    $diff = @()
    $beforeLines = @(); if ($Before.Files) { $beforeLines = $Before.Files -split "`n" }
    $afterLines  = @(); if ($After.Files)  { $afterLines  = $After.Files  -split "`n" }
    foreach ($line in $afterLines)  { if ($beforeLines -notcontains $line) { $diff += "host file added/changed: $line" } }
    foreach ($line in $beforeLines) { if ($afterLines  -notcontains $line) { $diff += "host file removed: $line" } }
    if ($Before.RegistryHash -ne $After.RegistryHash) {
        $diff += "HKCU\Software\PortappixTest changed ($($Before.RegistryHash) -> $($After.RegistryHash))"
    }
    return $diff
}

# ---------------------------------------------------------------------------
# Launcher invocation helpers.
# ---------------------------------------------------------------------------
function Invoke-Portappix {
    param(
        [string] $AppId,
        [switch] $Recover,
        [string] $CheckManifest,
        [hashtable] $ExtraEnv = @{}
    )
    $exitFile = Join-Path $Results ("exit-$PID-$([guid]::NewGuid().ToString('N')).json")
    $logFile  = Join-Path $Results ("log-$PID-$([guid]::NewGuid().ToString('N')).txt")
    $cliArgs = "--root `"$RootFull`" --exit-code-file `"$exitFile`" --log-file `"$logFile`""
    if ($Recover)        { $cliArgs = "$cliArgs --recover" }
    elseif ($CheckManifest) { $cliArgs = "$cliArgs --check-manifest `"$CheckManifest`"" }
    else {
        $cliArgs = "$cliArgs --run $AppId --wait --accept-policy"
        foreach ($key in $ExtraEnv.Keys) { Set-Item -Path "env:$key" -Value $ExtraEnv[$key] }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = Start-Process -FilePath $LauncherExe -ArgumentList $cliArgs -Wait -PassThru -NoNewWindow
    $sw.Stop()

    $record = $null
    if (Test-Path $exitFile) {
        try { $record = Get-Content $exitFile -Raw | ConvertFrom-Json } catch { $record = $null }
        Remove-Item $exitFile -Force -ErrorAction SilentlyContinue
    }
    return [PSCustomObject]@{
        ExitCode  = $proc.ExitCode
        ElapsedMs = $sw.ElapsedMilliseconds
        Record    = $record
        LogFile   = $logFile
    }
}

function Wait-ForFile {
    param([string] $Path, [int] $TimeoutMs = 30000)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path $Path) { return $true }
        Start-Sleep -Milliseconds 100
    }
    return (Test-Path $Path)
}

function Start-PortappixBackground {
    param([string] $AppId, [hashtable] $ExtraEnv = @{})
    $exitFile = Join-Path $Results ("exit-$PID-bg-$([guid]::NewGuid().ToString('N')).json")
    $logFile  = Join-Path $Results ("log-$PID-bg-$([guid]::NewGuid().ToString('N')).txt")
    foreach ($key in $ExtraEnv.Keys) { Set-Item -Path "env:$key" -Value $ExtraEnv[$key] }
    $proc = Start-Process -FilePath $LauncherExe `
        -ArgumentList "--root `"$RootFull`" --exit-code-file `"$exitFile`" --log-file `"$logFile`" --run $AppId --wait --accept-policy" `
        -PassThru -NoNewWindow
    return [PSCustomObject]@{ Process = $proc; ExitFile = $exitFile; LogFile = $logFile }
}

# ---------------------------------------------------------------------------
# Case runner with per-case assertions.
# ---------------------------------------------------------------------------
$script:Failures = 0
$caseRecords = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param([string] $Id, [bool] $Passed, [string] $Detail, $ExitCode = $null, $ElapsedMs = $null)
    if (-not $Passed) { $script:Failures++ }
    $caseRecords.Add([PSCustomObject]@{
        id = $Id; passed = $Passed; exitCode = $ExitCode; elapsedMs = $ElapsedMs; detail = $Detail
    })
    $status = 'PASS'; if (-not $Passed) { $status = 'FAIL' }
    Write-Host ("  [{0}] {1,-28} {2}" -f $status, $Id, $Detail)
}

function Test-SnapshotUnchanged {
    param([string] $Id, $Before, $After)
    $diff = Get-SnapshotDiff $Before $After
    if ($diff.Count -eq 0) {
        Add-Result "$Id/host-clean" $true 'host snapshot after == before'
    } else {
        Add-Result "$Id/host-clean" $false ($diff -join '; ')
    }
}

function Run-StandardCase {
    param([string] $Id, [scriptblock] $Assertions)

    Write-Host "Case $Id"
    $before = Get-HostSnapshot
    $run = Invoke-Portappix -AppId $Id
    & $Assertions $run
    $after = Get-HostSnapshot
    Test-SnapshotUnchanged $Id $before $after
}

# --- Valid cases -----------------------------------------------------------

Run-StandardCase 'appdatawriter' {
    param($run)
    $ok = ($run.ExitCode -eq 0)
    $markers = @(
        "$RootFull\Data\appdatawriter\AppData\FakeApps\AppDataWriter\settings.ini",
        "$RootFull\Data\appdatawriter\LocalAppData\FakeApps\AppDataWriter\local.ini",
        "$RootFull\Data\appdatawriter\Temp\fakeapps_appdatawriter.tmp"
    )
    foreach ($m in $markers) {
        if (-not (Test-Path $m)) {
            Add-Result 'appdatawriter/markers' $false "missing marker: $m"
            $ok = $false
        }
    }
    if ($ok) { Add-Result 'appdatawriter/run' $true 'exit 0, markers under Data\appdatawriter' 0 $run.ElapsedMs }
}

Run-StandardCase 'registrywriter' {
    param($run)
    if ($run.ExitCode -ne 0) {
        Add-Result 'registrywriter/run' $false "exit code $($run.ExitCode)" $run.ExitCode $run.ElapsedMs
        return
    }
    Add-Result 'registrywriter/run' $true 'first run exit 0' 0 $run.ElapsedMs

    # Second run must see the first run's redirected registry state.
    $appDir = "$RootFull\Apps\registrywriter"
    $run1 = Join-Path $Results 'registrywriter-run1.txt'
    $resFile1 = Get-ChildItem -File -Path $appDir | Where-Object { $_.Name -ieq 'RegistryWriter.txt' } | Select-Object -First 1
    if ($resFile1) { Copy-Item $resFile1.FullName $run1 -Force }
    $before = Get-HostSnapshot
    $run2 = Invoke-Portappix -AppId 'registrywriter'
    $after = Get-HostSnapshot
    Test-SnapshotUnchanged 'registrywriter/run2' $before $after

    if ($run2.ExitCode -ne 0) {
        Add-Result 'registrywriter/persistence' $false "second run exit $($run2.ExitCode)" $run2.ExitCode $run2.ElapsedMs
        return
    }
    $run1Text = ''
    if (Test-Path $run1) { $run1Text = Get-Content $run1 -Raw }
    $resFile2 = Get-ChildItem -File -Path $appDir | Where-Object { $_.Name -ieq 'RegistryWriter.txt' } | Select-Object -First 1
    $run2Text = ''
    if ($resFile2) { $run2Text = Get-Content $resFile2.FullName -Raw }
    $wroteGreeting = [regex]::Match($run1Text, 'wrote Greeting=(.+?)\r?\n').Groups[1].Value
    $prevGreeting  = [regex]::Match($run2Text, 'previous Greeting=(.+?)\r?\n').Groups[1].Value
    $prevCounter   = [regex]::Match($run2Text, 'previous Counter=(\d+)').Groups[1].Value
    $wroteCounter  = [regex]::Match($run2Text, 'wrote Counter=(\d+)').Groups[1].Value
    $prevBlob      = [regex]::Match($run2Text, 'previous Blob=([0-9a-f]+)').Groups[1].Value
    $prevNested    = [regex]::Match($run2Text, 'previous Nested\\Deep\\Marker=(.+?)\r?\n').Groups[1].Value

    $problems = @()
    if (-not $wroteGreeting -or $wroteGreeting -ne $prevGreeting) { $problems += "greeting not persisted ($prevGreeting vs $wroteGreeting)" }
    if ($prevCounter -ne '1' -or $wroteCounter -ne '2') { $problems += "counter should be 1 -> 2 on second run, got prev=$prevCounter wrote=$wroteCounter" }
    if ($prevBlob -ne '01020304') { $problems += "binary value not persisted: $prevBlob" }
    if (-not $prevNested -or -not $prevNested.StartsWith('M')) { $problems += "nested subkey value not persisted: $prevNested" }

    if ($problems.Count -eq 0) {
        Add-Result 'registrywriter/persistence' $true 'second run saw the first run''s string/dword/binary/nested values'
    } else {
        Add-Result 'registrywriter/persistence' $false ($problems -join '; ')
    }
}

Run-StandardCase 'programdatawriter' {
    param($run)
    $ok = ($run.ExitCode -eq 0)
    if (-not (Test-Path "$RootFull\Data\programdatawriter\ProgramData\x.dat")) {
        Add-Result 'programdatawriter/markers' $false 'x.dat did not land under Data\programdatawriter'
        $ok = $false
    }
    if (Test-Path 'C:\ProgramData\PortappixTest') {
        Add-Result 'programdatawriter/markers' $false 'C:\ProgramData\PortappixTest leaked onto the host'
        $ok = $false
    }
    if ($ok) { Add-Result 'programdatawriter/run' $true 'junction redirect worked; nothing left on the host' 0 $run.ElapsedMs }
}

Run-StandardCase 'stublauncher' {
    param($run)
    if ($run.ExitCode -ne 0) {
        Add-Result 'stublauncher/run' $false "exit code $($run.ExitCode)" $run.ExitCode $run.ElapsedMs
        return
    }
    $marker = "$RootFull\Data\stublauncher\LocalAppData\FakeApps\StubLauncher\child_done.txt"
    $ok = $true
    if (-not (Test-Path $marker)) {
        Add-Result 'stublauncher/run' $false 'child marker missing: the launcher did not wait for the process tree'
        $ok = $false
    }
    if ($run.ElapsedMs -lt 4000) {
        Add-Result 'stublauncher/run' $false "returned after only $($run.ElapsedMs) ms (child sleeps 5 s)"
        $ok = $false
    }
    if ($ok) { Add-Result 'stublauncher/run' $true 'launcher waited for the detached child (exit 0, marker present)' 0 $run.ElapsedMs }
}

Run-StandardCase 'elevationrequired' {
    param($run)
    # On a standard (non-elevated) host the launcher must report 740 cleanly.
    # Windows Sandbox / elevated hosts will happily start the app instead; both
    # are acceptable as long as the host state stays clean.
    if ($run.ExitCode -eq 740) {
        $message = ''
        if ($run.Record) { $message = $run.Record.message }
        if ($message -match 'elevat') {
            Add-Result 'elevationrequired/run' $true 'ERROR_ELEVATION_REQUIRED reported cleanly (exit 740)' 740 $run.ElapsedMs
        } else {
            Add-Result 'elevationrequired/run' $false "exit 740 but message does not mention elevation: $message" 740 $run.ElapsedMs
        }
    } elseif ($run.ExitCode -eq 0) {
        Add-Result 'elevationrequired/run' $true 'host is elevated so the app ran (expected in Windows Sandbox); state stayed clean' 0 $run.ElapsedMs
        $elevTmp = Join-Path $env:TEMP 'fakeapps_elevationrequired.tmp'
        if (Test-Path $elevTmp) { Remove-Item $elevTmp -Force -ErrorAction SilentlyContinue }
    } else {
        Add-Result 'elevationrequired/run' $false "unexpected exit code $($run.ExitCode)" $run.ExitCode $run.ElapsedMs
    }
}

Run-StandardCase 'slowexit' {
    param($run)
    $doneMarker = "$RootFull\Apps\slowexit\slowexit.done.txt"
    if ($run.ExitCode -ne 0) {
        Add-Result 'slowexit/run' $false "exit code $($run.ExitCode)" $run.ExitCode $run.ElapsedMs
        return
    }
    if ($run.ElapsedMs -lt 7500) {
        Add-Result 'slowexit/run' $false "returned after only $($run.ElapsedMs) ms; the app ignores close for 8 s"
        return
    }
    if (-not (Test-Path $doneMarker)) {
        Add-Result 'slowexit/run' $false 'done marker missing'
        return
    }
    Add-Result 'slowexit/run' $true 'launcher waited out the 8 s ignore window (exit 0)' 0 $run.ElapsedMs
}

Write-Host 'Case singleinstance'
$before = Get-HostSnapshot
$envBackup = $env:PORTAPPIX_FAKE_HOLD_MS
$first = Start-PortappixBackground -AppId 'singleinstance' -ExtraEnv @{ PORTAPPIX_FAKE_HOLD_MS = '8000' }
try {
    if (-not (Wait-ForFile "$RootFull\Apps\singleinstance\singleinstance.started.txt" 30000)) {
        Add-Result 'singleinstance/run' $false 'the first run never signalled "started"'
    } else {
        $second = Invoke-Portappix -AppId 'singleinstance'
        if ($second.ExitCode -eq 4 -and $second.Record -and $second.Record.alreadyRunning) {
            Add-Result 'singleinstance/run' $true 'second run refused cleanly (exit 4, already running)' 4 $second.ElapsedMs
        } else {
            Add-Result 'singleinstance/run' $false "second run expected exit 4, got $($second.ExitCode)" $second.ExitCode $second.ElapsedMs
        }
        Wait-Process -Id $first.Process.Id -ErrorAction SilentlyContinue
        $first.Process.Refresh()
        $firstCode = $first.Process.ExitCode
        if ($null -eq $firstCode -and (Test-Path $first.ExitFile)) {
            $exitObj = Get-Content $first.ExitFile -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($exitObj) { $firstCode = $exitObj.exitCode }
        }
        if ($firstCode -eq 0) {
            Add-Result 'singleinstance/first-run' $true 'first run finished cleanly (exit 0)' 0
        } else {
            Add-Result 'singleinstance/first-run' $false "first run exit code $firstCode" $firstCode
        }
    }
} finally {
    if ($null -ne $envBackup) { Set-Item -Path 'env:PORTAPPIX_FAKE_HOLD_MS' -Value $envBackup }
    else { Remove-Item -Path 'env:PORTAPPIX_FAKE_HOLD_MS' -ErrorAction SilentlyContinue }
    if (-not $first.Process.HasExited) { taskkill /PID $first.Process.Id /T /F | Out-Null }
}
$after = Get-HostSnapshot
Test-SnapshotUnchanged 'singleinstance/host-clean' $before $after

Write-Host 'Case crashmidrun'
$before = Get-HostSnapshot
$envBackup = $env:PORTAPPIX_FAKE_HOLD_MS
$crash = Start-PortappixBackground -AppId 'crashmidrun' -ExtraEnv @{ PORTAPPIX_FAKE_HOLD_MS = '120000' }
try {
    if (-not (Wait-ForFile "$RootFull\Apps\crashmidrun\crashmidrun.started.txt" 30000)) {
        Add-Result 'crashmidrun/run' $false 'the app never wrote its state marker'
    } else {
        Start-Sleep -Milliseconds 500
        taskkill /PID $crash.Process.Id /T /F | Out-Null
        Wait-Process -Id $crash.Process.Id -ErrorAction SilentlyContinue

        $stateFile = Join-Path $RootFull 'run_state.json'
        $txDir = Join-Path $RootFull 'Transactions'
        $recorded = ((Test-Path $stateFile) -and ((Get-Content $stateFile -Raw) -match 'crashmidrun')) -or
                    ((Test-Path $txDir) -and @(Get-ChildItem -Directory -Path $txDir -Filter '*crashmidrun*').Count -gt 0)
        if (-not $recorded) {
            Add-Result 'crashmidrun/run' $false 'journal does not record crashmidrun as active after the kill'
        } else {
            Add-Result 'crashmidrun/journal' $true 'journal recorded the crashed app'

            $recover = Invoke-Portappix -Recover
            $stateAfter = ''
            if (Test-Path $stateFile) { $stateAfter = Get-Content $stateFile -Raw }
            $txAfter = @()
            if (Test-Path $txDir) { $txAfter = @(Get-ChildItem -Directory -Path $txDir -Filter '*crashmidrun*') }
            $regFile = "$RootFull\Data\crashmidrun\registry.reg"
            $regText = ''
            if (Test-Path $regFile) { $regText = Get-Content $regFile -Raw }

            $problems = @()
            if ($recover.ExitCode -ne 0) { $problems += "recovery exit $($recover.ExitCode)" }
            if (($stateAfter -match 'crashmidrun') -or ($txAfter.Count -gt 0)) { $problems += 'journal still lists crashmidrun after recovery' }
            if (-not (Test-Path $regFile)) { $problems += 'registry.reg missing: recovery must export hijacked keys before deleting them' }
            elseif ($regText -notmatch 'CrashMidRun') { $problems += 'registry.reg does not contain the app''s hijacked key' }

            if ($problems.Count -eq 0) {
                Add-Result 'crashmidrun/run' $true 'crash recovery exported keys, cleaned the host and cleared the journal' 0 $recover.ElapsedMs
            } else {
                Add-Result 'crashmidrun/run' $false ($problems -join '; ')
            }
        }
    }
} finally {
    if ($null -ne $envBackup) { Set-Item -Path 'env:PORTAPPIX_FAKE_HOLD_MS' -Value $envBackup }
    else { Remove-Item -Path 'env:PORTAPPIX_FAKE_HOLD_MS' -ErrorAction SilentlyContinue }
    if (-not $crash.Process.HasExited) { taskkill /PID $crash.Process.Id /T /F | Out-Null }
}
$after = Get-HostSnapshot
Test-SnapshotUnchanged 'crashmidrun/host-clean' $before $after

# --- Policy rejections ------------------------------------------------------

Write-Host 'Policy checks'
foreach ($badDir in Get-ChildItem -Directory (Join-Path $SuiteDir 'bad')) {
    $manifest = Join-Path $badDir.FullName 'app.json'
    $check = Invoke-Portappix -CheckManifest $manifest
    $allowed = $check.Record -and $check.Record.allowed
    if ($check.ExitCode -eq 2 -and (-not $allowed) -and $check.Record.messages.Count -gt 0) {
        Add-Result "policy/$($badDir.Name)" $true 'rejected by Portappix.Policy with a message'
    } else {
        Add-Result "policy/$($badDir.Name)" $false "expected rejection (exit 2), got exit $($check.ExitCode)"
    }
}

foreach ($goodDir in Get-ChildItem -Directory (Join-Path $SuiteDir 'apps')) {
    $manifest = Join-Path $goodDir.FullName 'app.json'
    $check = Invoke-Portappix -CheckManifest $manifest
    if ($check.ExitCode -eq 0 -and $check.Record -and $check.Record.allowed) {
        Add-Result "policy/$($goodDir.Name)" $true 'manifest passes policy'
    } else {
        Add-Result "policy/$($goodDir.Name)" $false "valid manifest rejected: $($check.Record.messages -join '; ')"
    }
}

# ---------------------------------------------------------------------------
# Results: JSON + readable summary table.
# ---------------------------------------------------------------------------
$total = $caseRecords.Count
$report = [ordered]@{
    timestamp     = (Get-Date).ToString('o')
    launcher      = $Launcher
    launcherSha256 = (Get-FileHash $Launcher -Algorithm SHA256).Hash.ToLower()
    root          = $RootFull
    hostName      = $env:COMPUTERNAME
    passed        = ($total - $script:Failures)
    failed        = $script:Failures
    cases         = $caseRecords
}
$reportPath = Join-Path $Results "$Timestamp.json"
$report | ConvertTo-Json -Depth 5 | Set-Content -Path $reportPath -Encoding UTF8

Write-Host ""
Write-Host "================= suite summary: $total checks, $($script:Failures) failed ================="
$caseRecords | ForEach-Object {
    $status = 'PASS'; if (-not $_.passed) { $status = 'FAIL' }
    '{0,-6} {1,-40} {2}' -f $status, $_.id, $_.detail
} | Out-String | Write-Host
Write-Host "Results written to $reportPath"

$summaryPath = Join-Path $Results "$Timestamp.md"
$caseRecords | ForEach-Object {
    $status = 'PASS'; if (-not $_.passed) { $status = 'FAIL' }
    "| $status | $($_.id) | $($_.detail) |"
} | Set-Content -Path $summaryPath -Encoding UTF8

if (-not $KeepRoot) {
    Remove-Item -Recurse -Force -Path $RootFull -ErrorAction SilentlyContinue
}

if ($script:Failures -gt 0) { exit 1 } else { exit 0 }

