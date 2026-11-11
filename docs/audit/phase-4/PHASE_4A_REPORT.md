# Portappix — Phase 4A Report: Test-Only Crash Injection, Build Isolation and Release Protection

**Phase:** 4A (compile-time-isolated crash injection + release artifact protection)
**Status:** IMPLEMENTED AND VERIFIED on the development workstation ·
**VM/Sandbox crash validation: NOT RUN** (harness prepared and statically inspected only)
**Date:** 2026-11-10
**Scope:** Phase 4A only. Phase 4B (download caps), 4C (zip hardening) and 4D (`reg.exe` timeout) were **not** started.

---

## 1. Preflight repository state

Verified before any edit (and re-verified at the end, see §13):

| Item | Approved baseline | Observed at preflight |
|---|---|---|
| Repository root | `C:\Users\Admin\Documents\github\portappix` | identical (the brief referenced `D:\ketan\github\portappix`; the difference was documented, never "corrected") |
| Branch | `main` | `main` |
| HEAD | `c4bce225d55c1b13ff9a88a9b8bc0d1fef1df180` | identical |
| Upstream | `origin/main` | `origin/main` |
| Ahead / behind | 7 / 0 | 7 / 0 |
| Staged changes | 0 | 0 |
| Working-tree entries | 15 modified + 7 untracked | 15 modified + 7 untracked (22 porcelain entries) |
| Stashes | 0 | 0 |
| Toolchain | `dcc32` / `dcc64` | `C:\Program Files (x86)\Embarcadero\Studio\23.0\bin\` |

Phase 1–3 changes were present and untouched: `src/Portappix.Transactions.pas`,
`src/Portappix.Junction.pas`, `src/Portappix.Runner.pas`, `src/Portappix.State.pas`,
`src/Portappix.Signature.pas`, `src/Portappix.Common.pas`, `docs/audit/phase-1..3/`,
`scripts/package_guard.py`, `scripts/generate_signing_key.py`, `keys/catalog_public.pem`,
`tests/fakeapps/src/CrashAtCheckpoint/`, `tests/scripts/`.

`PORTAPPIX_TESTCRASH` appeared nowhere in `src/` before this phase.

---

## 2. Files changed

Modified:

| Path | Change |
|---|---|
| `src/Portappix.Transactions.pas` | Crash globals, `PortappixTestCrashMarker` and `SetCrashPointFromString` moved behind `{$IFDEF PORTAPPIX_TESTCRASH}`; `CheckCrashPoint` implementation split into the real test-mode version and an empty production no-op; the interface declaration of `CheckCrashPoint` and all five checkpoint call sites are unchanged. |
| `src/Launcher.dpr` | Test-mode-only uses clause (`System.SysUtils`, `Portappix.Transactions`), the `ArmTestCrashPoint` environment reader and the `[testcrash]` arming/warning messages, all behind `{$IFDEF PORTAPPIX_TESTCRASH}`; the call is the first statement of the program block, before CLI/UI initialization. |
| `scripts/make_release.py` | New `launcher_forbidden_material()` fail-closed inspection plus the staging guard integration (see §6). |
| `tests/PortappixTests.dpr` | Three new regression tests (`TestCrashPointGrammar`, `TestCrashCheckpointCoverage`, `TestCrashPointNoOpWithEmpty`) and their registration; all inside `{$IFDEF PORTAPPIX_TESTCRASH}` so the suite still compiles without the define. |
| `docs/security/JOURNAL_TRANSACTION_AND_RECOVERY.md` | §10 rewritten: compile-time isolation, grammar, call sites, evidence classes, VM harness status. |
| `docs/security/JUNCTION_PRESERVATION_AND_RESTORATION.md` | Crash-evidence wording corrected; explicit statement that unit simulation, real termination and hard power loss are different evidence classes. |

Added:

| Path | Purpose |
|---|---|
| `tests/scripts/test_crash_hook_isolation.py` | Binary-isolation, source-scan, production-CLI and release-guard tests (see §8). |
| `tests/suite/run_crash_validation.ps1` | VM-only real-process-termination harness (see §10). |
| `tests/suite/crashfixtures/crashatcheckpoint/app.json` | Manifest for the fake app used by the crash harness. Deliberately **not** under `tests/suite/apps/`: that folder is auto-discovered by the compatibility suite (which must not run the parent-killing app as an ordinary case), and `.gitignore`'s `Apps/` rule would hide the file from Git. |
| `docs/audit/phase-4/PHASE_4A_REPORT.md` | This report. |

Build artifacts were produced only in fresh `%TEMP%` directories outside the repository
(`p4a-prod-w32/w64`, `p4a-test-w32/w64`, `p4a-tests-w32/w64`, stamp `20261110-113746`).
One ignored build output was added inside the repository by convention:
`tests/fakeapps/out/CrashAtCheckpoint/CrashAtCheckpoint.exe` (fake-app build output; the
`tests/fakeapps/out` tree is ignored and was already present).

---

## 3. Compile-time isolation design

```
src/Portappix.Transactions.pas
  interface
    {$IFDEF PORTAPPIX_TESTCRASH}
      var PortappixCrashPoint: string = '';
          PortappixCrashHook: TProc<string> = nil;
      const PortappixTestCrashMarker = 'PORTAPPIX-TESTCRASH-BUILD-2026-11-10';
      function SetCrashPointFromString(const AValue: string): Boolean;
    {$ENDIF}
    procedure CheckCrashPoint(const APoint: string);   // declared unconditionally
  implementation
    {$IFDEF PORTAPPIX_TESTCRASH}
      function SetCrashPointFromString(...): Boolean;   // strict grammar parser
      procedure CheckCrashPoint(...);                   // real behaviour
    {$ELSE}
      procedure CheckCrashPoint(...); begin end;        // empty no-op
    {$ENDIF}
```

- **Without** the define: the two crash variables do not exist, `SetCrashPointFromString`
  does not exist, `CheckCrashPoint` is an empty no-op, and there is no environment reader
  anywhere in the program.
- **With** the define: the previous behaviour is preserved (same globals, same hook
  override, same `TerminateProcess(GetCurrentProcess, 1)`), plus the new parser.
- Call sites were **not** moved: `state:<name>` (after the state was persisted),
  `op:<n>:pending` (after the intent was persisted), `op:<n>:<status>` (after the status
  was persisted), `op:<n>:done` (after a created junction's tag **and** identity were
  persisted) and `op:<n>:created` (inside `Runner.CreateJunctionJournaled`, between the
  junction's creation and the persistence of its identity).
- `src/Launcher.dpr` arms the checkpoint before any CLI/UI initialization. A valid
  identifier produces a `[testcrash] PORTAPPIX-TESTCRASH-BUILD-2026-11-10: checkpoint "…"
  armed; …` message; an invalid identifier produces a warning and arms **nothing**.
  No new CLI switch was introduced and no CLI/GUI behavior changed.
- Grammar (case-sensitive, no whitespace anywhere):
  `state:<canonical state name>` where the name is one of `preparing`, `prepared`,
  `hostBackupComplete`, `hostStateChanging`, `hostStateChanged`, `running`, `cleaning`,
  `completed`, `recoveryRequired`; and `op:<non-negative index>:<status>` where the
  status is one of `pending`, `done`, `absent`, `failed`, `restored`, `created`.
  Unknown states/statuses, negative or non-numeric indices, empty/whitespace-only values,
  malformed separators and extra components are rejected and never arm a checkpoint.
  Leading-zero indices are accepted and can never collide with the canonical decimal
  identifiers (the runtime comparison is an exact match).

---

## 4. Production / test artifact separation

Four launcher artifacts were built from the same source into separate fresh directories:

| Build | Define | Command | Output |
|---|---|---|---|
| Production Win32 | none | `dcc32 -B -E<dir> -N0<dir> -U<repo>\src <repo>\src\Launcher.dpr` | `<dir>\Launcher.exe` |
| Production Win64 | none | `dcc64 -B -E<dir> -N0<dir> -U<repo>\src <repo>\src\Launcher.dpr` | `<dir>\Launcher.exe` |
| Test-mode Win32 | `PORTAPPIX_TESTCRASH` | `dcc32 -B -DPORTAPPIX_TESTCRASH -E<dir> -N0<dir> -U<repo>\src <repo>\src\Launcher.dpr` | `<dir>\Launcher.exe` |
| Test-mode Win64 | `PORTAPPIX_TESTCRASH` | `dcc64 -B -DPORTAPPIX_TESTCRASH -E<dir> -N0<dir> -U<repo>\src <repo>\src\Launcher.dpr` | `<dir>\Launcher.exe` |

No repository build output was reused or overwritten. The Delphi test project was
compiled with `-DPORTAPPIX_TESTCRASH` (Win32 and Win64) so the existing crash-hook unit
tests remain available.

---

## 5. Byte-scan results

Matching rule (documented, case-sensitive): the exact needle bytes are searched for in
both plausible representations — the **UTF-16LE** form Delphi uses for string literals and
the plain **UTF-8/ASCII** form. A missing, unreadable or inconclusive scan is a failure.

| Artifact | `PORTAPPIX-CRASH-AT`-style env var `PORTAPPIX_CRASH_AT` | Marker `PORTAPPIX-TESTCRASH-BUILD-2026-11-10` | Verdict |
|---|---|---|---|
| Production Win32 (`Launcher.exe`, 4,301,824 B) | **absent** | **absent** | PASS |
| Production Win64 (`Launcher.exe`, 6,695,424 B) | **absent** | **absent** | PASS |
| Test-mode Win32 (`Launcher.exe`, 4,303,872 B) | **present** | **present** | PASS |
| Test-mode Win64 (`Launcher.exe`, 6,699,520 B) | **present** | **present** | PASS |

The strings are present in the test-mode binaries in their UTF-16LE form only (ASCII
search alone reports false negatives — this was found during development and is now
handled by the shared helper).

---

## 6. Release packaging guard

Integration point: `scripts/make_release.py`, immediately after the staging launcher is
identified (`--source` + `Launcher.exe` present) and **before** `out/` is created, before
zipping, before signing and before any publication. The existing package guard
(`package_guard.check_archive`) is untouched and still runs.

Behaviour:

- Inspects the **actual staged** `Launcher.exe` (never a development binary).
- Rejects the launcher when it contains `PORTAPPIX-TESTCRASH-BUILD-2026-11-10` or
  `PORTAPPIX_CRASH_AT` (UTF-16LE and UTF-8 byte patterns).
- **Fails closed** when the launcher is missing (existing staging check), empty, unreadable
  (I/O error) or the inspection itself fails.
- Never modifies the launcher; prints a clear, actionable error naming the detected
  string and the rebuild command.

---

## 7. Delphi test results

| Suite | Build | Result |
|---|---|---|
| `tests/PortappixTests.dpr` Win32 (`-DPORTAPPIX_TESTCRASH`) | `dcc32 -B -DPORTAPPIX_TESTCRASH …` | **506 passed / 0 failed** (exit code 0) |
| `tests/PortappixTests.dpr` Win64 (`-DPORTAPPIX_TESTCRASH`) | `dcc64 -B -DPORTAPPIX_TESTCRASH …` | **506 passed / 0 failed** (exit code 0) |

New tests (all passing on both bitnesses):

- `TestCrashPointGrammar` — 16 valid identifiers accepted and armed verbatim; 26
  malformed/unknown/wrong-case/whitespace/out-of-range identifiers rejected, each leaving
  the armed checkpoint untouched.
- `TestCrashCheckpointCoverage` — the full state chain `prepared → … → completed`, plus
  `state:recoveryRequired`; `op:0:pending` after the intent persist; `op:1:done` only
  after the status **and** the Phase 3 junction identity were persisted; the negative
  assertions that `op:1:pending` does not match an armed `op:1:done` and that the
  transaction APIs never fire `op:N:created`; and the `op:0:failed` / `op:0:absent` /
  `op:0:restored` boundaries. Every fired checkpoint is cross-checked against the
  journal file on disk, which proves the checkpoint fires **after** the durable persist.
- `TestCrashPointNoOpWithEmpty` — empty, whitespace-only and tab-only values are rejected
  and an empty armed checkpoint never triggers the hook.

Pre-existing assertions were preserved (no existing test was rewritten or weakened).
The only compiler warning in the test project is the pre-existing
`tests/PortappixTests.dpr(2933) W1012` (fake-ops constant `$80000029` on Win32) plus the
two known `W1002` platform warnings in `src/Portappix.Junction.pas`.

---

## 8. Python test results

| Suite | Result |
|---|---|
| `tests/scripts/test_signing_workflow.py` (existing baseline) | **24 passed / 0 failed** |
| `tests/scripts/test_crash_hook_isolation.py` (new) | **40 passed / 0 failed** (it also re-runs the baseline suite, which reported 24/0 inside it) |

Coverage of the new module:

1. Production Win32 binary contains neither string (UTF-16LE and UTF-8 byte search).
2. Production Win64 binary contains neither string.
3. Test-mode Win32 binary contains both.
4. Test-mode Win64 binary contains both.
5. Source scan: every **code** reference to `PORTAPPIX_CRASH_AT` in
   `src/Portappix.Transactions.pas` and `src/Launcher.dpr` lies inside an active
   `{$IFDEF PORTAPPIX_TESTCRASH}` region (0 exposed references), with a vacuous-scan guard
   proving the needle really occurs in the file.
6. Production CLI behavior unchanged with `PORTAPPIX_CRASH_AT` set: the same harmless
   `--check-manifest` run (fixture `tests/suite/apps/stublauncher/app.json`) with no
   variable, with a valid-looking checkpoint and with a garbage value produced identical
   exit codes (0 / 0 / 0) and identical stdout/stderr.
7. Release guard: production-like launcher accepted; marker rejected; env-var string
   rejected; both rejected (two findings); empty launcher rejected; unreadable launcher
   rejected; a full `make_release.py` run with a production-like launcher still produces
   the zip plus signed `releases.json`/`releases.json.sig`; a marker-carrying staged
   launcher is refused with no zip and no `releases.json` written; a staging folder
   without `Launcher.exe` is still rejected.
8. The existing signing/package suite still passes (24/24).

---

## 9. Build results for all four launchers

All builds used fresh `%TEMP%` directories (stamp `20261110-113746`) and `-B` (full
rebuild). Compiler logs are kept next to each artifact.

| Build | Compiler | Exit | Notes |
|---|---|---|---|
| Production Win32 | `dcc32 -B` | 0 | 13,382 lines; only the two known `W1002` warnings |
| Production Win64 | `dcc64 -B` | 0 | 13,382 lines; only the two known `W1002` warnings |
| Test-mode Win32 | `dcc32 -B -DPORTAPPIX_TESTCRASH` | 0 | 13,382 lines; only the two known `W1002` warnings |
| Test-mode Win64 | `dcc64 -B -DPORTAPPIX_TESTCRASH` | 0 | 13,382 lines; only the two known `W1002` warnings |
| Tests Win32 | `dcc32 -B -DPORTAPPIX_TESTCRASH` | 0 | 14,502 lines; run result 506/0 |
| Tests Win64 | `dcc64 -B -DPORTAPPIX_TESTCRASH` | 0 | 14,502 lines; run result 506/0 |

No build was performed with the define absent for the test project, and no production
build was produced with the define present — that separation is the phase's central
invariant and was verified by byte scan (§5).

**Note (later change, icons):** the launcher additionally links the tracked icon
resource `src\PortappixIcons.res` (application icon + the five notification-area
icons; see the README *Icons* section and `scripts\build_launcher.cmd`). The build
commands above are unchanged — the resource file is tracked, so a clean checkout
builds with the icons — and the crash-hook byte-scan results are unaffected by it.
The icon pipeline has its own regression suite, `tests/scripts/test_icons.py`.

---

## 10. VM / Sandbox validation results

**NOT RUN.** No isolated VM or Windows Sandbox was available in this environment, and the
harness was **not** executed on the development workstation (running it here would
terminate processes and hijack host paths).

What was done instead — *preparation and static inspection only*:

- `tests/suite/run_crash_validation.ps1` was written and parses cleanly
  (PowerShell AST parse: 0 errors).
- Its refusal paths were exercised on the workstation (each refuses **before** any
  process is launched, so no destructive behaviour was triggered):
  - without `-IConfirmThisIsAVM` → refused (mandatory parameter);
  - with the switch but a **production** launcher → refused
    (*"it is not a TEST-MODE launcher (marker present: False; 'PORTAPPIX_CRASH_AT' bytes
    present: False)"*);
  - with the switch and an unsafe results directory inside `%LOCALAPPDATA%` → refused
    (*"is inside protected 'C:\Users\Admin'"*);
  - with the switch and a drive root (`C:\`) → refused (*"is a drive root"*).
- The path guard was additionally unit-tested in isolation (extracted from the script via
  the PowerShell AST): `%TEMP%` subtrees are accepted as disposable scratch space, while
  `%LOCALAPPDATA%`, `%APPDATA%`, `%ProgramData%`, the user profile, `C:\Users`, `C:\`,
  `C:\Windows\...`, the repository root and any path inside them — plus a traversal that
  escapes `%TEMP%` back into `%LOCALAPPDATA%` — are refused.
- The harness design (per checkpoint): fresh disposable root, CrashAtCheckpoint fake app
  installed, launcher terminated by the crash path (exit code 1), **mandatory fake-app
  survival proof** via the `.started`/`.done` marker pair (the `.done` marker is written
  *after* `KillParent`, i.e. after the launcher died), journal and filesystem/registry
  capture, then two recovery passes asserting restoration and idempotency, with the
  original junction target and fixture data required to survive (no deletion of
  un-sourceable objects).

**Therefore the Phase 4A VM validation gate is NOT marked PASS.** The following remain
unproven until the harness is executed in an approved VM:

- real process termination at each checkpoint against a real OS;
- fake-application survival under launcher termination;
- two-pass recovery idempotency at OS level.

---

## 11. Tests not executed

| Item | Status | Reason |
|---|---|---|
| `tests/suite/run_crash_validation.ps1` (full run) | **NOT RUN** | VM/Sandbox only; not available here, and forbidden on the developer workstation |
| `tests/suite/run_suite.ps1` (compatibility suite) | **NOT RUN** | Pre-existing VM-only suite, unchanged by this phase |
| Hard power-loss / forced-reset validation | **NOT RUN** | Out of scope of Phase 4A; explicitly outstanding (see §12) |
| `op:0:failed` / `op:0:absent` / `op:0:restored` as **real** process terminations | **NOT RUN** | These are recovery-phase boundaries; they are covered by unit tests only. The VM harness exercises them only if an operator adds them to `-Checkpoints` |
| `state:preparing` / `state:completed` as real terminations | **NOT RUN** | Not reachable as armable boundaries in the current runner sequence (the initial state is written at creation without a checkpoint, and `completed` is written during finalization); covered by unit tests for the transition rules |

---

## 12. Remaining risks and limitations

1. **Hard power loss is unvalidated.** `TerminateProcess` is a clean-ish process
   termination, not a sudden power cut: the OS still flushes and closes handles. The
   journal's durability under an abrupt power loss (or a forced reset) remains an
   outstanding validation item. Unit simulation, real process termination and hard power
   loss are three different evidence classes and must not be treated as equivalent.
2. **The VM gate is open.** Phase 4A is implemented and unit-verified, but the
   real-process-termination validation gate is NOT PASS until the harness runs in an
   approved VM/Sandbox.
3. **Byte-scan based identification is a heuristic.** It proves that the two known
   strings are present/absent; a future test-mode build that used different strings
   would need the marker constant updated in three places
   (`Portappix.Transactions.pas`, `scripts/make_release.py`,
   `tests/scripts/test_crash_hook_isolation.py`). The marker is versioned
   (`PORTAPPIX-TESTCRASH-BUILD-2026-11-10`) so a stale build is detectable.
4. **The release guard inspects only the staged `Launcher.exe`.** A release pipeline that
   ships a differently named launcher binary would bypass the check; the pipeline
   convention (staging folder with `Launcher.exe` at its root) is assumed.
5. **The source scan in the Python test is a static approximation** of the compiler's
   conditional-compilation semantics (nested `$IFDEF`/`$ELSE`/`$ENDIF` are tracked,
   unknown conditions are treated conservatively as inactive). It complements — and does
   not replace — the binary byte scan, which is the authoritative check.
6. **The `op:<n>:created` checkpoint can only be produced by the runner**, so the
   transaction-level test asserts its *absence* there; the positive case is covered by
   the pre-existing `TestJunctionCrashBeforeIdentityPersisted` and, once the VM harness
   runs, by `op:<n>:created` in `-Checkpoints`.
7. **`make_release.py` still requires a real private key** for a complete release run;
   the new tests use a synthetic key generated inside a temporary directory. No private
   key was read, copied or exposed during this phase.
8. **The fake-app marker files are written next to the fake app** in the per-case app
   directory, so a stale marker from a previous case could mask a missing start; the
   harness deletes the markers before every case to avoid that.

---

## 13. Git preservation confirmation

Final state (identical to the approved baseline, with the Phase 4A edits added on top):

| Item | Value |
|---|---|
| Branch | `main` (never switched) |
| HEAD | `c4bce225d55c1b13ff9a88a9b8bc0d1fef1df180` (unchanged) |
| Upstream | `origin/main` |
| Ahead / behind | 7 / 0 |
| Staged changes | 0 (nothing staged) |
| Commits created | 0 (nothing committed) |
| Pushes | 0 (nothing pushed) |
| Pulls / rebases | 0 |
| Stashes | 0 |
| Modified paths | 16 = the pre-existing 15 + `scripts/make_release.py` |
| Untracked paths | 22 files (the pre-existing 7 top-level paths plus the Phase 4A additions: `docs/audit/phase-4/PHASE_4A_REPORT.md`, `tests/scripts/test_crash_hook_isolation.py`, `tests/suite/run_crash_validation.ps1`, `tests/suite/crashfixtures/crashatcheckpoint/app.json`) |
| Ignored artifacts | preserved (123 ignored paths, including the fake-app build output tree; the count is one lower than before only because the new fixture manifest was moved out of the ignored `Apps/` pattern into `tests/suite/crashfixtures/`) |
| Unpushed commits | `c4bce22, c71851e, bb0e8bc, f108a43, b403334, 16f2886, e1d1192` — all intact |

Explicit confirmations:

- **No staging, no commits, no pushes, no branch changes, no resets, no cleans, no
  stashes, no rebases.** Every Phase 4A change exists only as working-tree state.
- **All prior work preserved**: the seven unpushed commits, the 15 pre-existing modified
  paths, the 7 pre-existing untracked paths and every ignored artifact are intact.
- **No destructive test was run on the developer workstation**: the only harness
  invocations were its refusal paths (no process was started, no host path was touched).
- **No private key was read, copied, printed or exposed**; the release-guard tests
  generate a synthetic ECDSA P-256 key inside a temporary directory, and the repository's
  `keys/catalog_public.pem` (public key only) was never modified.
- **Phase 4B, 4C and 4D were not started.**

---

## 14. Acceptance criteria status

| # | Criterion | Status |
|---|---|---|
| 1 | Production build has no active crash-hook implementation | **PASS** (byte scan + source scan) |
| 2 | Production build contains neither prohibited marker string | **PASS** (both bitnesses) |
| 3 | Test-mode build recognizes valid checkpoint identifiers | **PASS** (16 valid identifiers, both bitnesses) |
| 4 | Invalid checkpoint identifiers are ignored | **PASS** (26 rejected identifiers, armed value untouched) |
| 5 | Existing Phase 2/3 recovery behavior unchanged | **PASS** (506/0 on both bitnesses, no existing test modified) |
| 6 | Phase 3 identity ownership remains mandatory for new transactions | **PASS** (`op:1:done` test asserts the persisted identity) |
| 7 | Legacy Phase 2 fallback remains intact | **PASS** (pre-existing legacy tests still pass) |
| 8 | Delphi Win32 and Win64 suites pass with the test define | **PASS** (506/0 and 506/0) |
| 9 | All four launcher builds succeed | **PASS** |
| 10 | Python signing/package baseline passes | **PASS** (24/24) |
| 11 | New binary-isolation tests pass | **PASS** (40/40) |
| 12 | Release staging guard rejects test-mode artifacts | **PASS** |
| 13 | Release staging guard fails closed on unreadable/missing artifacts | **PASS** |
| 14 | VM harness verifies fake-app survival, journal durability and two-pass recovery idempotency | **NOT RUN** — harness prepared and statically inspected; requires an approved VM |
| 15 | Documentation accurately reports all evidence and limitations | **PASS** (this report + the two security documents) |
| 16 | Existing working-tree changes and seven unpushed commits remain preserved | **PASS** (§13) |

**Overall: Phase 4A is implemented and verified on the development workstation, with the
VM/Sandbox validation gate still OPEN.** Phase 4B/4C/4D remain untouched pending owner
review.

---

## 15. Security Hardening Updates (Post-Phase 4A)

On 2026-11-11, three security issues identified during review were remediated:

1. **Issue 1: `--allow-insecure-release-urls` compile-time isolation**
   - The `--allow-insecure-release-urls` CLI switch in `src/Portappix.Cli.pas`, the `AllowInsecureReleaseUrls` variable in `src/Portappix.Update.pas`, and its check in `IsPermittedReleaseUrl` are wrapped inside `{$IFDEF PORTAPPIX_TESTUPDATE}`.
   - In normal release builds, the flag does not exist, the switch is rejected as an unknown argument, and all plain `http://` URLs (including loopback) are rejected.
   - In `PORTAPPIX_TESTUPDATE` builds, only loopback `http://` (`127.0.0.1` and `localhost`) is accepted by default; non-loopback HTTP (such as `http://127.0.0.1.evil.com/`) is rejected unless the switch is explicitly passed.
   - `scripts/make_release.py` release staging guard was extended to reject any launcher containing the literal byte string `allow-insecure-release-urls` (both UTF-8 and UTF-16LE).

2. **Issue 2: Package extraction zip-bomb and memory exhaustion protection**
   - Added constant `MaxZipEntryBytes = 512 MB` to `src/Portappix.PackageManager.pas`.
   - Before reading any entry, its declared `UncompressedSize` is checked against `MaxZipEntryBytes` and rejected if exceeded.
   - Implemented streaming chunk-based extraction (64 KB buffers) with running per-entry and total byte counters aborting immediately if caps are exceeded.
   - Deletes partially written files on abort and cross-checks declared vs actual written bytes (`actual <> declared` aborts and fails).
   - Entire destination directory is deleted on failure, leaving no half-extracted app or partial files behind.

3. **Issue 3: `Cache\pending_updates.json` untrusted metadata elimination**
   - Redesigned `pending_updates.json` to schema 2, storing only `id` and `version` as hints.
   - At apply time (`ApplyPendingUpdates`), the signed catalog is verified via CNG (`Catalog.SignatureVerified`). If unverifiable, nothing is applied and the queue is preserved intact.
   - All update metadata (`url`, `sha256`, `size`, `kind`) is drawn exclusively from the verified catalog entry, completely ignoring any values in `pending_updates.json`.
   - Unknown app IDs and apps whose catalog version is no newer than installed are dropped (with skip logging).
   - Atomic replacement via `WriteTextFileAtomic` and 64 KB file size cap (`MaxPendingUpdatesBytes`).
   - Old format (schema 1) auto-migrates safely by extracting only `id`s and rewriting to schema 2.

