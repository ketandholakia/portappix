# Portappix — Phase 0 Build & Test Baseline

Date: 2026-11-09. All numbers below are from actual executions on this machine.

## 1. Delphi environment

| Item | Value |
| --- | --- |
| IDE / release | Delphi 12 Athens — BDS `23.0` (`C:\Program Files (x86)\Embarcadero\Studio\23.0`) |
| Compiler version | **36.0** (`Embarcadero Delphi for Win32/Win64 compiler version 36.0`) |
| Win32 compiler | `C:\Program Files (x86)\Embarcadero\Studio\23.0\bin\dcc32.EXE` — available |
| Win64 compiler | `C:\Program Files (x86)\Embarcadero\Studio\23.0\bin\dcc64.exe` — available |
| `rsvars.bat` | Present (`bin\rsvars.bat`); defines `BDS`, `BDSINCLUDE`, `BDSCOMMONDIR`, `PATH` additions |
| Registry keys | `HKLM\SOFTWARE\WOW6432Node\Embarcadero\BDS\23.0` and `HKCU\SOFTWARE\Embarcadero\BDS\23.0` present |
| Third-party packages | **None required** — every `uses` clause across `src/` and `tests/` references only `System.*`, `Winapi.*`, `Vcl.*` (+ local `Portappix.*` units). Confirmed by scanning all 21 source files. |
| Delphi configuration | Not modified (Phase 0 constraint). |

## 2. Project configurations

### `src/Portappix.dproj` (launcher)

- Default config **Debug**, default platform **Win32**, `TargetedPlatforms=3` (Win32 + Win64).
- `DCC_UnitSearchPath`: `.` (project folder sits next to the sources) + inherited defaults.
- `DCC_DcuOutput` / `DCC_ExeOutput`: `$(Platform)\$(Config)`.
- Config **Debug**: `DCC_Define=DEBUG`, `DCC_Optimize=false`, `DCC_GenerateStackFrames=true`,
  `DCC_DebugInformation=2`.
- Config **Release**: `DCC_Define=RELEASE`, `DCC_Optimize=true`, `DCC_DebugInformation=0`.
- Conditional defines in source: none beyond the standard `DEBUG`/`RELEASE` (no `{$IFDEF ...}`
  feature gates found in the engine units).

### `tests/PortappixTests.dproj`

- Default Debug / Win32; `DCC_UnitSearchPath` includes `..\src`; outputs to `$(Platform)\$(Config)`
  (Win32/Debug etc.). No Win64-specific group beyond the generic platform handling; Win64 builds
  via the same project/command line.

## 3. Build baseline (actual results)

Phase 0 constraint: existing build artifacts were preserved, so builds ran from a **temp output
directory** (`%LOCALAPPDATA%\Temp\portappix-phase0-build\…`) using `-E.` (exe output) and `-N0.`
(DCU output). These flags only redirect output locations; no compiler semantics, defines, or
optimization settings were changed. The commands otherwise follow the documented build path
(`README.md` §Build): project sources referenced by absolute path, unit search path via `-U`.

| # | Target | Compiler | Command (effective) | Result | Warnings | Errors |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Launcher Win32 | dcc32 36.0 | `dcc32 -B -E. -N0. -U<repo>\src <repo>\src\Launcher.dpr` | **Success** — 10,414 lines, 0.69 s, 3,317,516 B code | 1 | 0 |
| 2 | Launcher Win64 | dcc64 36.0 | `dcc64 -B -E. -N0. -U<repo>\src <repo>\src\Launcher.dpr` | **Success** — 10,414 lines, 2.52 s, 4,971,320 B code | 1 | 0 |
| 3 | Tests Win32 | dcc32 36.0 | `dcc32 -B -E. -N0. -U<repo>\src <repo>\tests\PortappixTests.dpr` | **Success** — 8,725 lines, 0.52 s, 2,022,444 B code | 1 | 0 |
| 4 | Tests Win64 | dcc64 36.0 | `dcc64 -B -E. -N0. -U<repo>\src <repo>\tests\PortappixTests.dpr` | **Success** — 8,725 lines, 1.28 s, 2,970,348 B code | 1 | 0 |

The single warning in every build:

```
C:\...\src\Portappix.Junction.pas(49) Warning: W1002 Symbol 'FILE_FLAG_OPEN_REPARSE_POINT' is specific to a platform
```

This matches the known-warning list in `RELEASE_CHECKLIST.md` step 1 ("No new compiler
hints/errors introduced (`-Q` output clean except the known W1002)") — **no new warnings or
errors**. Note: the first Win32 attempt without `-E` aborted with `F2039 Could not create output
file …\src\Launcher.exe` because the default output path would have overwritten the existing
`src/Launcher.exe` artifact — redirected, not "fixed"; recorded for transparency.

Untested in Phase 0: MSBuild/IDE builds of the Debug/Release `.dproj` configurations (the
command-line path above carries no `DEBUG`/`RELEASE` define). Recommended for Phase 1 CI.

## 4. Test baseline (actual results)

### Unit tests — `tests/PortappixTests.dpr`

- Framework: **hand-rolled console assertion helper** (no DUnitX / no third-party framework —
  the project brief says "DUnitX-compatible"; the actual code is a simple `PASS:`/`FAIL:` printer;
  recorded as a discrepancy, not a defect). 19 top-level `Test*` procedures covering: manifest
  parsing/tokens, policy allow/deny, catalog parsing + atomic swap + https/kind validation,
  zip-slip rejection + subfolder extraction, SHA-256 reference, journal save/recover/corrupt
  quarantine, export-before-delete ordering with an injected registry fake, trace engine
  (noise filter, snapshot caps, diff, suggestions, report files — probe-injected, never launches
  processes), semver, dataVersion, pending-update queue, `.prev` rollback, downgrade protection,
  settings persistence, and the self-update swap/confirm/rollback state machine.

**Execution results (freshly built binaries from the temp build dir):**

| Target | Result | Exit code |
| --- | --- | --- |
| Win32 `PortappixTests.exe` | **167 passed, 0 failed** | 0 |
| Win64 `PortappixTests.exe` | **167 passed, 0 failed** | 0 |

Per the README's design, these tests never touch the host registry or user profile (injected
fakes + temp directories) — safe to run outside a VM, which is why they were executed.

### Compatibility suite — `tests/suite/run_suite.ps1`

**NOT RUN (deliberate).** The suite deliberately hijacks `HKCU\Software\PortappixTest`,
junctions `%PROGRAMDATA%\PortappixTest`, writes `%APPDATA%\FakeApps` etc., and its own header
states ">>> RUN IN A VM / WINDOWS SANDBOX ONLY <<<" (`run_suite.ps1:20-23`). Running it would
violate the Phase 0 "no destructive host registry/junction tests" constraint. Status recorded as
**not-run: environment limitation (requires clean VM/Windows Sandbox)**. Its structure was
reviewed instead (see PRESERVED_CHANGES.md).

### Not executed (tooling)

- `scripts/validate_catalog.py` — downloads every catalog package from vendor URLs (network +
  third-party binaries); out of read-only scope.
- `scripts/sign_catalog.py` / `tools/build_catalog.py` signing paths — touch the private key;
  not executed (no key rotation, no catalog regeneration).
- `tools/build_recipe.py --lint-only` — CI-only lint; not executed to keep the host untouched.

## 5. Environment limitations summary

1. Compatibility suite, real-app checklist (`tests/suite/real_apps.md`), and trace-mode-on-real-app
   checks require a VM/Windows Sandbox — not available/allowed in this phase → **not-run**.
2. Catalog validation pipeline requires network downloads of vendor binaries → **not-run**.
3. Signing operations require the private key → **not-run** by design.
4. IDE (MSBuild) Debug/Release configurations not exercised; command-line builds (documented
   path) verified instead.
5. Python version on this host: 3.11 (per `scripts/__pycache__/sign_catalog.cpython-311.pyc`
   artifact); `cryptography`, `jsonschema`, `requests` assumed installed previously — dependency
   installation is prohibited in Phase 0, so tooling was not re-verified.

## 6. Generated artifact inventory (all preserved, none deleted)

| Location | Files | Total size | Notes |
| --- | --- | --- | --- |
| `bin/` | 2 | 5,442,560 B | Prebuilt `Launcher.exe` + `PortappixTests.exe` (local builds, git-ignored) |
| `src/Win32/Debug/` | 16 | 4,664,261 B | IDE/DCU output, git-ignored |
| `src/Win32/Release/` | 16 | 4,609,166 B | IDE/DCU output, git-ignored |
| `tests/Win32/Debug/` | 12 | 2,788,839 B | Test build output, git-ignored |
| `tests/Win32/Release/` | 12 | 2,771,758 B | Test build output, git-ignored |
| `tests/fakeapps/out/` | 8 | 8,135,168 B | Win32 fake apps (suite needs these) |
| `tests/fakeapps/out64/` | 8 | 13,340,672 B | Win64 fake apps |
| `dist/` | 6 | 5,089,387 B | `everything/fastfetch/tcpview` `.package.zip` + `.build.json` (recipe build outputs) |
| `portappix.zip` (root) | 1 | 10,801,195 B | Full-repo snapshot zip — **contains `keys/` and `.git/`** (see SECURITY_INVENTORY PH0-SEC-01) |
| `src/Launcher.exe`, `src/*.dcu`, `src/Portappix.res` | — | `src/Launcher.exe` 6,002,688 B | Stray build outputs at `src/` root, git-ignored |
| `scripts/__pycache__/` | 2 | 36,438 B | Python bytecode cache |
| `__history/` (root) | 0 | 0 B | Empty IDE history dir |
| `catalog.json` / `catalog.json.sig` (root) | 2 | 17 B / 64 B | **Tracked** files: signed empty catalog stub (`{"apps": []}`) + raw 64-byte signature |
| `keys/catalog_signing_key.pem` | 1 | 241 B | Private key — git-ignored; **contents never read or printed during Phase 0** |

Fake-app source set (tracked): `CrashMidRun`, `SlowExit`, `RegistryWriter`, `AppDataWriter`,
`ProgramDataWriter`, `SingleInstance`, `StubLauncher`, `ElevationRequired` (each a small console
`.dpr` under `tests/fakeapps/src/`, built by `tests/fakeapps/build.cmd` into `out[64]/`; outputs
land in `tests\fakeapps\out\<name>\` — never committed).
