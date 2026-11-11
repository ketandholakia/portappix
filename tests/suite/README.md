# Portappix compatibility suite

A repeatable compatibility suite for a clean Windows VM / Windows Sandbox. It
installs small **fake apps** into a throwaway launcher root and verifies the
Level 2 virtualization guarantees end to end.

> ## ⚠️ Never run this on a daily-driver machine
>
> The launcher deliberately hijacks `HKCU\Software` keys and NTFS paths, and
> this suite verifies exactly that behaviour. A launcher bug writes to your
> **host**. Run the suite in Windows Sandbox (`.wsb` file provided) or in a
> Hyper-V VM with a checkpoint you can roll back. The suite snapshots the
> watched host locations before and after every case and fails loudly when
> anything leaks, but that safety net is only meaningful on a clean machine.

## What the fake apps test

| Case | Behaviour under test |
| --- | --- |
| `appdatawriter` | `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`/`TMP` env overrides; markers must land under `Data\<id>`. |
| `registrywriter` | Hijack of `HKCU\Software\PortappixTest\RegistryWriter` (string, dword, binary, nested subkeys); **second run must see the first run's values**. |
| `programdatawriter` | Junction `%PROGRAMDATA%\PortappixTest` → `Data\<id>\ProgramData`; host path must not leak. |
| `stublauncher` | Launcher exits immediately after spawning a child that lives 5 s; the runner must wait for the **whole job-object process tree**. |
| `elevationrequired` | `requireAdministrator` manifest; launcher must report `ERROR_ELEVATION_REQUIRED` (740) cleanly and leave no host state. On elevated hosts (Windows Sandbox) the app simply runs. |
| `crashmidrun` | Kills the launcher mid-run (or is killed); journal recovery must export hijacked keys before deleting them, restore junctions and clear `run_state.json`. |
| `singleinstance` | Second `--run` while the app is running must be refused cleanly (exit code 4). |
| `slowexit` | Ignores close requests for 8 s; the launcher must wait patiently and return exit code 0. |

Three intentionally **bad manifests** live in `tests\suite\bad\` and must be
rejected by `Portappix.Policy` (registry key outside the allow-list, junction
into `Documents`, environment `PATH` hijack).

## 1. Build (on the host, before starting the sandbox)

A clean Windows Sandbox only contains native Windows utilities (`powershell.exe`, `cmd.exe`, `reg.exe`) and lacks Python, Git, and Delphi. All build steps and fixture preparations must be executed on the **HOST** beforehand:

```bat
:: 1. The launcher (both bitnesses, see README "Build")
scripts\build_launcher.cmd all

:: 2. The fake apps (Win32 output is what the suite uses)
tests\fakeapps\build.cmd

:: 3. Gate 3 self-update test fixtures (generates throwaway key and signed feeds)
powershell -ExecutionPolicy Bypass -File scripts\build_selfupdate_fixture.ps1
```

`tests\fakeapps\build.cmd` compiles every fake app with `dcc32` into `tests\fakeapps\out\<name>\`.
`scripts\build_selfupdate_fixture.ps1` builds versioned launchers (1.0.0, 1.1.0, 1.2.0, 1.3.0-fail) and signed release packages into `tests\suite\fixtures\selfupdate\`.

## 2. Run in Windows Sandbox

1. Edit `tests\suite\sandbox.wsb`: set `<HostFolder>` paths to your local repo checkout and an empty results folder on the host.
2. Double-click `tests\suite\sandbox.wsb`.
3. In the sandbox console, the repository is mapped read-only at `C:\users\WDAGUtilityAccount\Desktop\portappix`.

Every test script inside the sandbox uses **only native Windows PowerShell** and prebuilt binaries:

### Gate 1: Transactional Crash Recovery Harness
```powershell
Set-Location C:\users\WDAGUtilityAccount\Desktop\portappix
powershell -ExecutionPolicy Bypass -File .\tests\suite\run_crash_validation.ps1 `
    -Results C:\users\WDAGUtilityAccount\Desktop\PortappixSuiteResults
```

### Gate 2: Compatibility Suite (Fake Apps)
```powershell
Set-Location C:\users\WDAGUtilityAccount\Desktop\portappix
powershell -ExecutionPolicy Bypass -File .\tests\suite\run_suite.ps1 `
    -Results C:\users\WDAGUtilityAccount\Desktop\PortappixSuiteResults `
    -Launcher .\bin\Launcher.exe
```

### Gate 3: Two Consecutive Self-Updates & Rollback Watchdog
```powershell
Set-Location C:\users\WDAGUtilityAccount\Desktop\portappix
powershell -ExecutionPolicy Bypass -File .\tests\suite\run_selfupdate_validation.ps1 `
    -FixtureDir .\tests\suite\fixtures\selfupdate
```

### Gate 4: Production Rollback Validation
```powershell
Set-Location C:\users\WDAGUtilityAccount\Desktop\portappix
powershell -ExecutionPolicy Bypass -File .\tests\suite\run_rollback_validation.ps1 `
    -IConfirmThisIsAVM `
    -Launcher .\bin\Launcher.exe `
    -FixtureDir .\tests\suite\fixtures\selfupdate
```
Validates the non-interactive production rollback path using the release binary (`bin\Launcher.exe --accept-rollback`):
- Case 1: Update 1.0.0 -> 1.1.0, simulate missing `Cache\update_ok`, verify rollback restores 1.0.0 and consumes `Launcher.exe.old`.
- Case 2: Update 1.1.0 -> 1.3.0-fail (startup crash), verify rollback restores working 1.1.0.

### Gate 5: Standard User Elevation Validation
```powershell
Set-Location C:\users\WDAGUtilityAccount\Desktop\portappix
powershell -ExecutionPolicy Bypass -File .\tests\suite\run_standard_user_validation.ps1 `
    -IConfirmThisIsAVM `
    -Launcher .\bin\Launcher.exe
```
In a full VM with secondary logon (`seclogon`) enabled, creates a temporary standard user and validates that `ElevationRequired.exe` fails closed with `ERROR_ELEVATION_REQUIRED` (740) without leaving orphaned junctions or registry keys. Inside Windows Sandbox containers (where secondary logon is restricted by hypervisor container policy), cleanly detects and reports this environment limitation.

## 3. Run in Hyper-V VM / any clean Windows machine

```powershell
# In the VM, after copying the repo and building the host steps above:
powershell -ExecutionPolicy Bypass -File tests\suite\run_suite.ps1 `
    -Results C:\PortappixSuiteResults
```

Options: `-Cases appdatawriter,registrywriter` runs a subset; `-KeepRoot`
keeps the assembled launcher root for debugging; `-Root` and `-Launcher`
override the default locations.

The suite **never touches user data outside the watched test locations** and
refuses launcher roots that point at your profile, `Windows`, `ProgramData`
or the repository itself.

## 3. Interpreting failures

The script writes `results\<timestamp>.json` (machine-readable, includes the
launcher SHA-256) and `results\<timestamp>.md` (summary table) and prints the
same table. Every check has an id of the form `<case>/<assertion>`:

- `*/host-clean` — the host snapshot changed during the run. This is the
  **worst kind of failure**: the launcher leaked files or registry keys onto
  the host. Check the per-case log file in the results folder, and roll the VM
  back / reset the sandbox.
- `registrywriter/persistence` — the second run did not see the first run's
  redirected registry state; the hijack/export/import round-trip is broken.
- `stublauncher/run` — the launcher returned before the 5 s child exited; the
  job-object process-tree wait is broken.
- `crashmidrun/*` — crash journal recovery did not export keys before
  deleting them, left the junction in place, or did not clear
  `run_state.json`.
- `singleinstance/run` — the per-app mutex was not honoured on the second run.
- `slowexit/run` — the launcher gave up on (or killed) an app that was slow to
  exit.
- `elevationrequired/run` — on a **non-elevated** host this must be exit 740
  with a clear message; on an elevated host the app runs and the check accepts
  exit 0. Anything else is a failure.
- `policy/*` — a bad manifest was accepted or a valid one rejected. Compare
  the `messages` array in the check-manifest record with the Portappix policy
  documentation in the README.

## 4. Real apps

Before every release, also walk the manual list in
[`real_apps.md`](real_apps.md) with 20 real portable apps. Nothing is
downloaded automatically; you fetch installers yourself and drive them through
the launcher by hand.
