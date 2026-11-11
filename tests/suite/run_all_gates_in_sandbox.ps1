# Automated sequential runner for all three Portappix validation gates in Windows Sandbox.
$ErrorActionPreference = 'Continue'

Set-Location C:\users\WDAGUtilityAccount\Desktop\portappix
$ResultsDir = "C:\users\WDAGUtilityAccount\Desktop\PortappixSuiteResults"
Set-Content -Path (Join-Path $ResultsDir "sandbox_started.txt") -Value "STARTED $(Get-Date -Format 'o')" -Encoding utf8

Write-Host "Portappix Windows Sandbox Automated Validation Starting..." -ForegroundColor Green
Write-Host "Results destination: $ResultsDir"
Write-Host ""

# Gate 2: Compatibility Suite
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "GATE 2: COMPATIBILITY SUITE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$gate2Log = Join-Path $ResultsDir "gate2_suite.log"
try {
    powershell -ExecutionPolicy Bypass -File .\tests\suite\run_suite.ps1 -Results $ResultsDir -Launcher .\bin\Launcher.exe *>&1 | Tee-Object -FilePath $gate2Log
} catch {
    Write-Host "Gate 2 encountered error: $_" -ForegroundColor Red
}

# Gate 1: Crash Recovery Harness
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "GATE 1: CRASH HARNESS" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$gate1Log = Join-Path $ResultsDir "gate1_crash.log"
try {
    powershell -ExecutionPolicy Bypass -File .\tests\suite\run_crash_validation.ps1 -IConfirmThisIsAVM -Results $ResultsDir *>&1 | Tee-Object -FilePath $gate1Log
} catch {
    Write-Host "Gate 1 encountered error: $_" -ForegroundColor Red
}

# Gate 3: Self-Update & Watchdog Rollback
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "GATE 3: SELF-UPDATE & WATCHDOG ROLLBACK" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$gate3Log = Join-Path $ResultsDir "gate3_selfupdate.log"
try {
    powershell -ExecutionPolicy Bypass -File .\tests\suite\run_selfupdate_validation.ps1 -FixtureDir .\tests\suite\fixtures\selfupdate *>&1 | Tee-Object -FilePath $gate3Log
} catch {
    Write-Host "Gate 3 encountered error: $_" -ForegroundColor Red
}

# Mark completion
$doneFile = Join-Path $ResultsDir "all_gates_complete.txt"
Set-Content -Path $doneFile -Value "COMPLETED $(Get-Date -Format 'o')" -Encoding utf8
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "ALL THREE GATES HAVE COMPLETED EXECUTION" -ForegroundColor Green
Write-Host "Results saved to: $ResultsDir" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
