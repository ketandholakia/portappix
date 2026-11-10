# Portappix — Phase 0 Baseline Report

Date: 2026-11-09
Phase: 0 (Repository Baseline & Preservation) — read-only inspection + audit documentation only.

## 1. Project summary

Portappix is a portable Windows application launcher using "Level 2 virtualization":
it redirects environment variables, HKCU registry keys and NTFS junction paths around a
launched application, waits for the whole process tree via a job object, then exports and
restores host state. Distribution is a single `Launcher.exe` plus `Apps\` folders and a
signed JSON catalog.

- Language/platform: Delphi 12 (Object Pascal), VCL, Win32 + Win64, Windows 10/11.
- Dependencies: standard RTL/VCL + Win32 API only (CNG `bcrypt.dll` for signatures).
  No third-party components (confirmed by inspecting all `uses` clauses).
- Catalog security: ECDSA P-256 signature over SHA-256 of exact catalog bytes
  (raw 64-byte `r||s`), verified with Windows CNG; packages verified by SHA-256 + size.
- Python tooling (catalog validation, signing, recipe building) and a hand-rolled
  assertion-based test console (not DUnitX).

## 2. Repository HEAD and branch

| Item | Value |
| --- | --- |
| Branch | `main` |
| HEAD | `c4bce225d55c1b13ff9a88a9b8bc0d1fef1df180` |
| HEAD subject | "Part 4: known-app recipes - 25 pinned recipes, recipe tooling, catalog provenance" |
| HEAD author / date | Ketan Dholakia <ketandholakia@users.noreply.github.com>, 2026-11-09 17:44:14 +0530 |
| Remote | `origin` → `https://github.com/ketandholakia/portappix.git` (fetch & push) |
| Remote main | `origin/main` at `52fabc9` ("Fix Delphi identifier and API usage errors found by dcc32") |
| Ahead/behind | local `main` is **ahead of `origin/main` by 7 commits**, not behind |

The 7 unpushed commits (`git log origin/main..HEAD --oneline`, newest first):

1. `c4bce22` Part 4: known-app recipes - 25 pinned recipes, recipe tooling, catalog provenance
2. `c71851e` Part 3b: launcher self-update - signed releases.json, swap, watchdog
3. `bb0e8bc` Part 3a: safe app updates - semver, downgrade protection, pending queue, rollback
4. `f108a43` Part 2: trace reports - what did this app touch
5. `b403334` Add the compatibility suite: fake apps, manifests, runner script, sandbox config
6. `16f2886` Document how to run the unit tests (both bitnesses) and ignore local zips
7. `e1d1192` Fix remaining compile issues and persist the catalog URL setting

Cumulative diff vs `origin/main`: 74 files changed, +8,937 / −122.

## 3. Git working tree status

| Check | Result |
| --- | --- |
| `git status --short` | empty (no output) |
| `git status` | "nothing to commit, working tree clean" |
| `git diff --stat` / `git diff --name-only` | empty — no unstaged modifications |
| `git diff --cached --stat` | empty — nothing staged |
| Untracked files (`git ls-files --others --exclude-standard`) | none |

**The working tree is clean.** There are no uncommitted developer modifications to
classify. Everything that exists on disk outside Git tracking is a *git-ignored local
artifact* (build outputs, signing material, release zips) — inventoried in
[BUILD_TEST_BASELINE.md](BUILD_TEST_BASELINE.md) and [PRESERVED_CHANGES.md](PRESERVED_CHANGES.md).

### Note on `tests/suite/run_suite.ps1`

The Phase 0 instructions referenced an "existing `tests/suite/run_suite.ps1` modification".
Verification: `git log --follow -- tests/suite/run_suite.ps1` shows the file was **added in
commit `b403334`** and has exactly one commit in its history; `git diff origin/main..HEAD --
stat -- tests/suite/run_suite.ps1` shows +538 (the initial add) and `git status` shows **no
uncommitted modification of this file**. The committed version (538 lines) is the state the
instruction refers to; it was not read-modified or overwritten in any way during Phase 0.

## 4. Preserved state

- No production source file, test, script, recipe, schema, catalog, or key was modified,
  regenerated, moved, or deleted during Phase 0.
- All 7 unpushed commits remain intact; nothing was reset, stashed, checked out over, or
  rebased. Nothing was committed or pushed.
- All git-ignored local artifacts (including `keys/`, `dist/`, `portappix.zip`, `bin/`,
  `*.dcu`, `__pycache__`, IDE leftovers) remain untouched on disk.
- Phase 0 builds and test runs were executed with output redirected to a temp directory
  outside the repository so that existing build artifacts (e.g. `src/Win32/Debug/*`,
  `bin/*`, `tests/Win32/*`) were not overwritten.

## 5. Architecture overview (summary)

Full detail in [ARCHITECTURE_INVENTORY.md](ARCHITECTURE_INVENTORY.md).

- Entry point: `src/Launcher.dpr` — headless CLI mode (`Portappix.Cli`) when the first
  argument starts with `--`; otherwise VCL tray/dashboard app with a single-instance mutex.
- Engine units (`Portappix.*`) are VCL-free; UI lives in `MainForm` + `Portappix.TrayUI`.
- `TPortableAppRunner.Run` is the execution engine: policy gate → data dirs → env block →
  junctions → registry backup/delete/import → journal `AddActiveApp` → launch (suspended +
  job object) → export/delete/restore → journal `RemoveActiveApp`.
- `TPortappixJournal` (`run_state.json`) is the crash journal; `RecoverPendingCleanups`
  exports hijacked keys *before* deleting them, restores `_host_backup` directories, and
  removes junctions for recorded apps that are not running.
- `TPortappixPackageManager` handles download (https only) → SHA-256/size verify →
  cap-checked extraction → manifest/policy validation → atomic swap with `.prev` rollback
  and a pending-update queue.
- `TPortappixCatalog` downloads/verifies the signed catalog; `TPortappixUpdate` implements
  the signed `releases.json` launcher self-update with a swap/confirm/watchdog state machine.

## 6. Build configuration and results

Detail in [BUILD_TEST_BASELINE.md](BUILD_TEST_BASELINE.md). Summary:

- Delphi 12 Athens (BDS 23.0), compiler version **36.0**, `dcc32` and `dcc64` both
  available. Default project config Debug / Win32; both Debug and Release configs defined;
  `TargetedPlatforms=3` (Win32 + Win64).
- Four baseline builds succeeded: launcher Win32/Win64, tests Win32/Win64 — each with
  exactly one warning (the known W1002 in `Portappix.Junction.pas:49`).

## 7. Test baseline

- `tests/PortappixTests.dpr` — console assertion helper (**not DUnitX**; no third-party
  framework). 19 top-level test procedures; **167 checks passed, 0 failed** on both Win32
  and Win64, exit code 0. Executed from freshly built binaries in a temp directory.
- `tests/suite/run_suite.ps1` (compatibility suite, 8 fake apps + 3 bad manifests) was
  **NOT RUN**: it deliberately hijacks `HKCU\Software\PortappixTest`, `%PROGRAMDATA%\PortappixTest`
  and `%APPDATA%\FakeApps` paths and is documented as VM/Windows-Sandbox-only. Running it on
  this host would violate the Phase 0 "no destructive host tests" constraint.

## 8. Known limitations of this baseline

| Limitation | Impact |
| --- | --- |
| Compatibility suite not executed | End-to-end virtualization guarantees (junction/registry hijack, crash recovery, job-object wait) are unverified on this host by design; covered only by unit-level fakes. |
| Manual real-app checklist (`tests/suite/real_apps.md`) not executed | Out of scope for a host-safety read-only phase. |
| Debug/Release IDE configurations not exercised via MSBuild | Command-line `dcc32`/`dcc64` builds (the documented build path) were used; they carry no `DEBUG`/`RELEASE` defines. IDE config builds remain untested in Phase 0. |
| No Delphi license/packaging checks (e.g. `Setup`-style deployment) | None present in the repo; nothing to verify. |
| `AGENTS.md` and `TESTING.md` do not exist | Recorded as absent; README + RELEASE_CHECKLIST serve as the process docs. |
| Python tooling not executed | `validate_catalog.py` downloads every package (network + vendor binaries) — outside read-only scope; `sign_catalog.py` touches the signing key — not executed. |
| Root `catalog.json` is an empty stub (`{"apps": []}`) with a live 64-byte signature | The catalog content pipeline (recipes → `tools/build_catalog.py`) has not produced a populated committed catalog yet; recorded as a baseline fact. |

## 9. Phase 0 status

**PASS** — baseline documented, working tree clean and preserved, builds and safe tests
executed and recorded, all host-destructive and key-touching operations deliberately
skipped, and all audit documents written without modifying production files. See
[PHASE_0_EXIT_CHECKLIST.md](PHASE_0_EXIT_CHECKLIST.md) for the item-by-item status and
[SECURITY_INVENTORY.md](SECURITY_INVENTORY.md) for the findings that motivate Phase 1.
