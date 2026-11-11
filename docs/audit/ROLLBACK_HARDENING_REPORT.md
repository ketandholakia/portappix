# Rollback Hardening and Gate 4 Validation Audit Report

**Date**: 2026-11-11  
**Project**: Portappix (Delphi 12, VCL / Win32, RTL only)  
**Classification**: Security Hardening, Cryptographic Verification & Automated Sandbox Validation  

---

## 1. Executive Summary

This security round hardened the launcher self-update rollback mechanism, restored strict type assertions in the crash validation suite, updated core security documentation, and verified end-to-end containment across all four validation gates in Windows Sandbox.

Key guarantees achieved:
1. **Pre-Rollback Integrity Verification**: Before any file is renamed or modified during rollback, `Launcher.exe.old` is cryptographically validated against `Cache\old_launcher.json`. The engine refuses rollback if the record is missing, malformed, mismatched in size or SHA-256 hash, or if `Launcher.exe.old` is an NTFS reparse point / junction.
2. **Fail-Closed Rollback Architecture**: Failed verification leaves `Launcher.exe` completely untouched, preserves `Launcher.exe.old`, and generates no `.failed_*` executable.
3. **Unified Code Paths**: The automatic UI watchdog (`MainForm.pas`) and headless operational CLI switches (`--accept-rollback`, `--rollback` in `Portappix.Cli.pas`) share the exact same verification logic in `Portappix.Update.pas`.
4. **Strict Harness Assertions**: `Check` in `tests/suite/run_crash_validation.ps1` strictly enforces `[bool]` conditions, failing immediately if a non-boolean (such as a string or array) is passed.
5. **Clean Verification**: All Delphi test configurations, Python suites, and Windows Sandbox Gates 1 through 4 passed with 100% success and 0 failures. `catalog.json` and `catalog.json.sig` remain byte-identical to their initial state.

---

## 2. Changes Implemented

### 2.1 Pre-Rollback Old Launcher Verification (`src/Portappix.Update.pas`)
- **Metadata Recording (`RecordOldLauncher`)**:
  - When `PrepareUpdate` performs the atomic swap (`Launcher.exe` -> `Launcher.exe.old`), it immediately writes `Cache\old_launcher.json` using `WriteTextFileAtomic`.
  - Schema: `OldLauncherRecordSchemaVersion = 1`.
  - Stored properties:
    ```json
    {
      "schema": 1,
      "sha256": "<64-hex lowercase sha256 of Launcher.exe.old>",
      "size": <exact byte length>,
      "version": "<retiring launcher version>",
      "time": "<ISO-8601 timestamp>",
      "recordedAt": "<ISO-8601 timestamp>"
    }
    ```
  - Rotation: Sequential updates replace `old_launcher.json` with the retiring binary's metadata. In the event of a mid-swap error, the swap rollback logic restores any backed-up previous record from `RollbackDir`.
- **Pre-Rollback Validation (`VerifyOldLauncher`, `VerifyOldLauncherForRollback`)**:
  - Runs before any file mutation in `RollbackToOldLauncher`.
  - **Reparse Point Guard**: `IsReparsePoint(OldLauncherExe)` is checked first. Any symbolic link, mount point, or junction at `Launcher.exe.old` is rejected immediately (`Refusing rollback: "Launcher.exe.old" is a reparse point or symbolic link.`).
  - **Record Presence**: Fails if `Cache\old_launcher.json` does not exist.
  - **Schema & Type Checks**: Fails if JSON parsing fails, schema != 1, size < 0, or SHA-256 is not 64 hex characters.
  - **Size Verification**: Fails if `TFile.GetSize(OldLauncherExe)` differs from declared `size`.
  - **Cryptographic Hash Verification**: Fails if `Sha256File(OldLauncherExe)` differs from recorded `sha256`.
  - **Clean State Cleanup**: On successful rollback, `Cache\old_launcher.json` is cleanly deleted alongside `Launcher.exe.old`.

### 2.2 Watchdog and CLI Integration (`src/MainForm.pas`, `src/Portappix.Cli.pas`)
- **Watchdog Protection (`src/MainForm.pas`)**:
  - `CheckLauncherUpdateWatchdog` wraps `Manager.RollbackToOldLauncher` in `try..except`, logging any verification failure cleanly via `QueueStatus` rather than terminating with an unhandled runtime error.
- **Operational CLI Commands (`src/Portappix.Cli.pas`)**:
  - `--rollback` and `--accept-rollback` are compiled into release builds as operational switches (alongside `--status` and `--clear-review`).
  - Both invoke `TPortappixCli.ExecuteRollback`, calling `TPortappixUpdateManager.RollbackToOldLauncher(False)`.

### 2.3 Strict Assertion Enforcement (`tests/suite/run_crash_validation.ps1`)
- Restored `Check` parameter validation:
  ```powershell
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
  ```
- Fixed all callers in `run_crash_validation.ps1` to produce explicit `[bool]` values:
  - `@($appReview).Count -gt 0` (preventing array-to-boolean coercion issues)
  - `[bool]($nextRunLog -match 'manual review' -or $nextRunLog -match '--clear-review')`

### 2.4 Test Suite Expansions
- **Unit Tests (`tests/PortappixTests.dpr`)**:
  - Added `TestOldLauncherVerification(const ARoot: string)` covering 12 test assertions:
    1. `PrepareUpdate` generates `Cache\old_launcher.json` with schema=1, valid sha256, size, version.
    2. Size-tampered `Launcher.exe.old` is refused with clear error; `Launcher.exe` and `.old` are untouched; no `.failed_*` binary created.
    3. Content-tampered `Launcher.exe.old` (identical size, modified bytes) is refused with SHA-256 mismatch error; `Launcher.exe` and `.old` untouched.
    4. Missing `Cache\old_launcher.json` is refused; `Launcher.exe` untouched.
    5. Corrupt JSON in `old_launcher.json` is refused.
    6. Schema mismatch (schema != 1) is refused.
    7. Negative size in record is refused.
    8. Invalid SHA-256 formatting in record is refused.
    9. Record from earlier update (mismatched hash) is refused.
    10. Reparse point `Launcher.exe.old` is refused.
    11. Verified rollback succeeds with valid record: restores previous launcher, consumes `.old`, consumes `old_launcher.json`, creates single `.failed_*` backup.
    12. Self-update rotation: second update replaces `old_launcher.json` with intermediate launcher hash and version; subsequent rollback restores intermediate version.
- **Production Rollback Validation Gate (`tests/suite/run_rollback_validation.ps1`)**:
  - Expanded from 2 cases to 6 comprehensive cases (45 assertions):
    - Case 1: 1.0.0 -> 1.1.0 update, missing `update_ok`, production `--accept-rollback` succeeds.
    - Case 2: 1.1.0 -> 1.3.0-fail startup crash rollback restores working 1.1.0.
    - Case 3: 1.1.0 -> 1.2.0 update; verify `old_launcher.json` record created; size-tampered `.old` refused (exit != 0, 1.2.0 untouched); content-tampered `.old` refused (exit != 0, 1.2.0 untouched).
    - Case 4: Missing `old_launcher.json` refused (exit != 0, 1.2.0 untouched).
    - Case 5: Mismatched record from earlier version refused (exit != 0, 1.2.0 untouched).
    - Case 6: Authentic record verified rollback succeeds (exit 0, restores 1.1.0.0, consumes `.old` and `old_launcher.json`).

---

## 3. Binary Build and Release Guard Evidence

All binaries were compiled fresh from committed source on the host:

| Binary | Target / Config | File Size (bytes) | SHA-256 Hash |
| :--- | :--- | :--- | :--- |
| `bin\Launcher.exe` | Win32 Production Release | 5,152,256 | `E57545362FAB107041CFA774641127309805A989C532BDB31CB813A5F409EE98` |
| `bin\Launcher64.exe` | Win64 Production Release | 7,583,744 | `8A997B43018A225F4EBD0A12C284A82C072EEDB83D57D5F7823465515F49E48C` |
| `bin\LauncherTestCrash.exe` | Win32 Test-Crash (`PORTAPPIX_TESTCRASH`) | 5,154,304 | `7ECC1CAD155B9F33B09BAE0DF8ED98F75B6D24FC3724287F7BB4E28E8F69526B` |
| `bin\PortappixTests_Release.exe` | Win32 Tests (Release config) | 3,108,352 | `4EFAEE923278CDEFE1B651E7BF99BCB5E1ACC52FB759167E02EAE4E485F069CB` |
| `bin\PortappixTests_Test.exe` | Win32 Tests (Test defines active) | 3,146,240 | `527C67F51ECA0E9A7C4D2D64443BD64BFCC43DC8F731FFD5D5DBD387A0E6C92A` |

### Release Guard Audit (`scripts/make_release.py`)
Execution of `launcher_forbidden_material`:
- `bin/Launcher.exe`: `findings = []` (Accepted)
- `bin/Launcher64.exe`: `findings = []` (Accepted)
- `bin/LauncherTestCrash.exe`: `findings = ['staged launcher contains PORTAPPIX-TESTCRASH-BUILD-2026-11-10 (utf-16-le byte pattern); it looks like a test-mode binary', 'staged launcher contains PORTAPPIX_CRASH_AT (utf-16-le byte pattern); it looks like a test-mode binary']` (Rejected)

---

## 4. Test Verification Results

### 4.1 Host Test Suites

1. **Delphi Engine Unit Tests (`PortappixTests`)**:
   - Release Configuration: **524 passed, 0 failed** (includes all new rollback verification tests)
   - Test-Define Configuration (`PORTAPPIX_TESTCRASH;PORTAPPIX_TESTUPDATE`): **714 passed, 0 failed**
2. **Crash Hook Isolation Suite (`tests/scripts/test_crash_hook_isolation.py`)**:
   - **51 passed, 0 failed** (validates byte scans, source scoping, CLI invariance, and release packaging guards)
3. **Signing Workflow and Package Guard Suite (`tests/scripts/test_signing_workflow.py`)**:
   - **46 passed, 0 failed** (validates ECDSA P-256 signing, public key whitelist, and archive cleanliness)
4. **Icon Resource Determinism Suite (`tests/scripts/test_icons.py`)**:
   - **76 passed, 0 failed** (validates 6 icon groups, DIB format, and 32 RT_ICON resource entries)

### 4.2 Windows Sandbox Automated Gate Execution

Execution ran in a fresh Windows Sandbox (`PID 10088 / 10664`) via `tests/suite/sandbox.wsb`:

| Gate | Harness Script | Result | Checks / Assertions | Key Observations |
| :--- | :--- | :--- | :--- | :--- |
| **Gate 1** | `run_crash_validation.ps1` | **PASS** | 13/13 passed, 0 failed | All 13 crash checkpoints verified with strict `[bool]` `Check`. Journal drained and junctions restored; unowned junction review experience verified. |
| **Gate 2** | `run_suite.ps1` | **PASS** | 31/31 passed, 0 failed | Zero host-clean failures across all test apps; virtualization and junction isolation verified. |
| **Gate 3** | `run_selfupdate_validation.ps1` | **PASS** | 23/23 passed, 0 failed | Sequential self-updates (1.0 -> 1.1 -> 1.2), `.old` rotation, missing `update_ok` rollback, and 1.3.0 startup crash rollback verified. |
| **Gate 4** | `run_rollback_validation.ps1` | **PASS** | 45/45 passed, 0 failed | Verified production release binary across 6 distinct rollback cases: size tampering, content tampering, missing record, earlier update mismatch, and authentic verified rollback. |
| **Gate 5** | `run_standard_user_validation.ps1` | **DOCUMENTED** | Verified via Unit Tests | Windows Sandbox container policy blocks `seclogon`; engine error 740 handling verified via unit suite. |

Sandbox completion marker: `COMPLETED 2026-11-11T20:36:39.4636338+05:30`.

---

## 5. Security and Integrity Review

1. **Catalog Integrity**:
   - `catalog.json` and `catalog.json.sig` diff: 0 files changed, 0 bytes difference.
   - Pinned trust key: `keys/catalog_public.pem` intact and verified.
2. **Private Key Non-Disclosure**:
   - Zero private signing keys were created in the repository, committed, packaged, or logged.
   - Self-update fixtures were built with throwaway ECDSA P-256 key material generated strictly outside the repository in temporary directories.
3. **No Weakened Assertions**:
   - No checks or test assertions were disabled, bypassed, or weakened. All assertions were made strictly typed and mathematically rigorous.
