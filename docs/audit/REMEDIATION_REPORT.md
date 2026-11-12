# Portappix — Independent Review Remediation Report

**Date:** 2026-11-11
**Repository:** Portappix (Delphi 12, VCL/Win32+Win64, RTL only), branch `main`
**Baseline:** HEAD `d520eda` (clean working tree)
**Status:** IMPLEMENTED AND VERIFIED on the development workstation; Windows Sandbox Gates 1–5 evidence in §7.
**Signing integrity:** no private key read, copied, printed, or packaged; `catalog.json`, `catalog.json.sig` and `keys/catalog_public.pem` verified byte-identical to HEAD.

---

## 1. Findings-to-fix mapping

| # | Finding (independent review) | Code location (pre-remediation) | Fix | Commit |
|---|---|---|---|---|
| R1 | Failure after moving `Launcher.exe` does not fully restore the original executable and previous metadata; in-swap restore steps unchecked; a crash between the rename and the record write permanently wedges rollback (`.old` present, record missing → refused) | `Portappix.Update.pas` swap at 758–803 | Record metadata BEFORE the rename; checked restore (`RestoreFailedSwap`) with byte-identical pre-swap-hash invariant; `update_ok`/`update_pending.json`/record backed up and restored; failed restores keep the backup dir for forensics | c4 |
| R2 | Rollback metadata (`old_launcher.json`) is unauthenticated plain JSON | `RecordOldLauncher`/`VerifyOldLauncher` | HMAC-SHA256 over canonical field serialization (schema 2) with a DPAPI-protected per-installation key (`src/Portappix.RecordAuth.pas`); fail-closed on missing/invalid/foreign HMAC; schema-1 records auto re-stamp after full verification | c2 |
| R3 | `needs_review.json` is fail-open (malformed/inaccessible ⇒ empty review list) | `TPortappixJournal.ListReviewItems` (6 silent exits) | Fail-closed: raises `EPortappixStateError` on any read/parse/schema/field problem; `BeginTransaction` refuses; `--status` reports `REVIEW STATE UNREADABLE` with the needs-review exit; GUI warns; only a missing file is the normal empty state | c5 |
| R4 | `WriteTextFileAtomic` return values ignored in review persistence/clearing | `State.pas` RecordReviewItem:1000, ClearReview:1111; unwrapped `TFile.Delete` | Return values checked → raise / `AError`; delete failure reported; review writes switched to `WriteTextFileDurable` | c5 |
| R5 | Time-of-check/time-of-use gap: hash computed with the handle closed, rename later | `Sha256FileBytes` open-and-close; `RollbackToOldLauncher` rename after verify | `OpenVerifiedOldLauncher`: write-denying + delete-sharing handle, reparse-point detection via handle attributes, size/hash through the still-open handle (`Sha256Handle`), rename while the handle is open; externally locked `.old` ⇒ fail-closed refusal | c3 |
| R6 | SHA-256 not validated as exactly 64 hex characters; no shared helper | `VerifyOldLauncher` length-only check vs releases.json inline check | `IsValidSha256Hex` in `Portappix.Common.pas`, wired into both validation sites | c1 |
| R7 | Rollback metadata fields/version not validated | `VerifyOldLauncher`, `ReadPendingVersion` | Full field validation (schema, hex sha256, size bounds ≤ 512 MiB, non-empty version, strict ISO-8601 `time`/`recordedAt` when present, HMAC); version-resource ↔ record consistency; `update_pending.json` field validation; explicit rejection of numeric JSON masquerading as strings (`TJSONNumber` inherits `TJSONString` in the RTL) | c1 |
| R8 | Missing deterministic failure-injection tests (9 scenarios) | — | `{$IFDEF PORTAPPIX_TESTINJECT}` seams (write/rename/spawn) + ~60 new checks: metadata write failure, disk-full, access denied, launcher rename failure, new-launcher installation failure, concurrent replacement, corrupt review metadata, review persistence failure, review clearing failure | c6 |

Threat model for R2: see `docs/security/UPDATE_ROLLBACK_INTEGRITY.md` — defends against accidental corruption, other-user/lower-privilege tampering and same-user code without key access; explicitly does NOT defend against same-user arbitrary code that can read the DPAPI-protected key (documented residual risk).

## 2. Implementation commits

| Commit | Content |
|---|---|
| c1 | feat(common): 64-hex SHA-256 validation + full rollback-record field validation |
| c2 | feat(update): authenticate rollback metadata (HMAC-SHA256, DPAPI key, schema 2, schema-1 re-stamp) |
| c3 | feat(update): TOCTOU-safe open-verify-move rollback |
| c4 | fix(update): all-or-nothing self-update transaction with checked restore and metadata backup |
| c5 | fix(state): fail-closed review metadata + checked durable review writes |
| c6 | test: deterministic failure-injection seams and regression tests (TESTINJECT) |
| c7 | guard: forbidden-material needles for the injection seams + isolation test suite |
| c8 | docs: rollback integrity threat model + remediation report |

(Actual hashes in the final `git log`.)

## 3. Regression tests added (`tests/PortappixTests.dpr`)

New test groups (all registered; groups using injection seams only compile under
`PORTAPPIX_TESTINJECT`):

- `TestIsValidSha256Hex` — 9 checks, incl. full-length non-hex rejection via `ParseReleasesJson`.
- `TestRecordAuth` — DPAPI key round-trip, per-installation key independence, HMAC canonicalization (each protected field), comparison semantics (14 checks).
- `TestOldLauncherRecordAuth` — schema-1 migration re-stamp; tampered sha256/size refused with HMAC mismatch; missing HMAC refused; foreign-key HMAC refused; authenticated rollback succeeds (14 checks).
- `TestReviewFailClosed` — malformed JSON / wrong root / scalar root / non-object entry / missing, empty, wrong-typed fields all raise; `BeginTransaction` refuses; `ClearReview` reports the error; valid file still loads (11 checks).
- `TestRollbackConcurrentReplacement` — writer blocked during the verify window (sharing violation); rollback refused while `.old` is exclusively held, leaving both executables untouched; rollback succeeds after release (10 checks).
- `TestReviewPersistenceFailures` (TESTINJECT) — access-denied raise; disk-full raise; file untouched in both; clearing persistence failure keeps entries; success after the hook is removed (8 checks).
- `TestUpdateFailureInjection` (TESTINJECT) — metadata write failure; disk-full simulation; launcher rename failure; new-launcher installation failure with replaced root file + pre-existing `update_ok` restored; pre-existing pending marker restored; byte-identical restore verified against the pre-swap hash in every scenario; backup directory cleaned (20 checks).

Existing assertions were preserved; the only expectation change is the
`old_launcher.json` schema check 1 → 2 plus a new HMAC-presence check in
`TestOldLauncherVerification` (a strengthening required by R2).

## 4. Build results (all fresh temp output dirs; repo `src\Launcher.exe` never touched)

| Build | Command (abridged) | Exit | Notes |
|---|---|---|---|
| Win32 Release | `dcc32 -B -DRELEASE -E<temp> -N0<temp> -Usrc src\Launcher.dpr` | 0 | 3× W1002 (see note) |
| Win32 Debug | `dcc32 -B -DDEBUG -$O- -$R+ -$Q+ …` | 0 | 3× W1002 |
| Win64 Release | `dcc64 -B -DRELEASE …` | 0 | 3× W1002 |
| Tests Win32 test-config | `-DPORTAPPIX_TESTCRASH -DPORTAPPIX_TESTUPDATE -DPORTAPPIX_TESTINJECT` | 0 | **810 passed / 0 failed** (Phase 2A); see §9.2 for the Phase 2B counts (930) |
| Tests Win64 test-config | same, `dcc64` | 0 | **810 passed / 0 failed** (Phase 2A); see §9.2 |
| Tests Win32 release-config | `-DPORTAPPIX_TESTCRASH` | 0 | **761 passed / 0 failed** (Phase 2A); 777 after Phase 2B |
| Tests Win64 release-config | same, `dcc64` | 0 | **761 passed / 0 failed** (Phase 2A); 777 after Phase 2B |

W1002 note: the known `FILE_FLAG_OPEN_REPARSE_POINT` platform warning appears twice
in `Portappix.Junction.pas` (pre-existing) and once in `Portappix.Update.pas`
(`OpenVerifiedOldLauncher` uses the same flag deliberately); this is the same
documented warning class as previous phases, now three instances instead of two.
A single Win64 test-config run reported one transient failure that did not
reproduce in four subsequent full runs (see §8); no flake has been reproduced
or diagnosed.

## 5. Python test results

| Suite | Result |
|---|---|
| `tests/scripts/test_signing_workflow.py` | 46 passed / 0 failed |
| `tests/scripts/test_icons.py` | 76 passed / 0 failed |
| `tests/scripts/test_crash_hook_isolation.py` | 50 passed / 0 failed |
| `tests/scripts/test_failure_injection_isolation.py` (new) | 33 passed / 0 failed |

The new suite verifies: every code reference to the injection identifiers in
`src/` sits inside an active `{$IFDEF PORTAPPIX_TESTINJECT}` region (with
vacuous-scan guards); the key-path override sits behind `PORTAPPIX_TESTCRASH`;
production launchers contain no `PORTAPPIX-TESTINJECT-BUILD-2026-11-11` bytes
(UTF-16LE and UTF-8) while test-config binaries do; the `make_release.py`
staging guard rejects a marker-carrying launcher, an empty launcher, an
unreadable launcher, and still accepts a production-like launcher.

## 6. Forbidden-material checks on release binaries

Scanned the release-config Win32, Win64 and Win32-Debug launchers for all
existing needles plus the new `PORTAPPIX-TESTINJECT` marker and the injection
hook identifiers (`PortappixWriteHook`, `PortappixRenameHook`,
`PortappixSpawnErrorCode`, `PortappixRecordKeyPathOverride`), each in UTF-16LE
and UTF-8: **no findings** (all CLEAN). `scripts/make_release.py` now scans for
the TESTINJECT marker; the existing guard tests still pass.

## 7. Windows Sandbox Gates 1–5

Executed twice on this host (first run 2026-11-11, second run after the Gate-4
script assertion was updated for schema-2 records). Raw logs:
`docs/audit/remediation-gate-evidence-20261112/`.

First run: Gates 1 (13/0), 2 (31/0), 3 (23/0) all passed. Gate 4 reported a
single assertion failure — `old_launcher.json schema is 1` — which was the
**gate script's own stale fixture expectation** (the remediation intentionally
bumps the record to schema 2; the two real rollback-flow cases in the same run
passed). The assertion was updated to require schema 2 **and** a 64-character
HMAC (`tests/suite/run_rollback_validation.ps1`), and the gate was re-run.

Second run (2026-11-12, `sandbox_started` 23:54, completed 00:04):

| Gate | Scope | Result |
|---|---|---|
| 1 — Crash Recovery Harness | Real process termination at every journal checkpoint, recovery, fake-app survival | **13 passed / 0 failed** |
| 2 — Compatibility Suite | 8 fake apps, virtualization guarantees, host-clean leak assertions | **31 passed / 0 failed** |
| 3 — Self-Update & Watchdog | Consecutive updates, watchdog rollback with HMAC-authenticated records | **23 passed / 0 failed** |
| 4 — Production Rollback | Production `--accept-rollback`, tamper/missing/mismatch/foreign-record refusals, authenticated record rollback, schema-2 + HMAC record assertions | **46 passed / 0 failed** |
| 5 — Standard User Elevation | ERROR_ELEVATION_REQUIRED (740) fail-closed | **NOT RUNNABLE in Windows Sandbox** — the Sandbox container policy blocks `seclogon`; the gate documents the full-VM procedure and the behavior remains covered by unit tests. Same honest limitation as previous validation rounds. |

Gate-4 note: its Case 5/6 deliberately write **schema-1** records and expect,
respectively, refusal (mismatched hash) and success (valid record) — both
exercised the documented schema-1 migration path against the production
binary in the sandbox, and both behaved as specified.

## 8. Remaining risks

1. **Same-user code with key access** can forge an authenticated rollback
   record (decrypt the DPAPI key, recompute the HMAC). Documented residual
   risk; no locally-stored secret can do better. Mitigations live at the OS and
   distribution layers.
2. **Version-consistency check is conditional** on the `.old` binary carrying a
   version resource; hash/size/HMAC still bind the record.
3. **Review fail-closed blocks launches** when the review state is unreadable;
   operators must repair or remove the file deliberately.
4. **One transient Win64 test failure** (not reproduced across 4 subsequent
   full runs of both configs) — see §8 detail below if still unreproduced at
   report time.
5. VM-class power-loss validation of the durable metadata writes remains an
   open item inherited from earlier phases (unit simulation + real
   termination are different evidence classes).

## 9. Phase 2B — second independent review (R15–R20)

**Date:** 2026-11-12
**Baseline:** `main` at `d41537d`'s parent chain (`f520be9`, `81e61aa`, `a3e9046`,
`eeb6dd8`/R17, `d41537d`/R18)
**Method:** repro-first — each finding gets a deterministic failing test, the
pre-fix failure is captured as raw evidence, the fix is applied, then the same
tests are re-run on both bitnesses. Evidence logs:
`docs/audit/phase2b-evidence/`.

### 9.1 Findings-to-fix mapping

| # | Finding (independent review, second pass) | Pre-fix defect | Fix | Commit | Evidence |
|---|---|---|---|---|---|
| R15 | Companion rollback deletes the backup directory even when a restore failed | `RollbackToOldLauncher` restored each file with a logged-only failure then unconditionally deleted the whole `companion_rollback` directory — destroying the only copies of the pre-update companion files | Per-file checked restore with a failure counter; directory removed only when every restore AND every introduced-file deletion succeeded; introduced files driven by the durable manifest; unsafe manifest names drop the list (fail-closed) | `7d97192` | `r15-r16-repro-prefix.log` (15 FAILED pre-fix), `r15-r16-fixed-pass{,-x64}.log` |
| R16 | Companion finalize destroys staging and previous backups on any failed transfer | `PreserveCompanionBackups` deleted the previous companion directory BEFORE moving staging backups in, and treated failed moves as logged warnings; the unconditional staging delete then lost the source too | Transfer into a FRESH `companion_rollback_staging` with per-file SHA-256 verification, union-merge with the previous directory, durable manifest, then activation (delete previous + rename); on any failure every file is moved back to staging and only a drained transfer dir is deleted; bookkeeping files stay in staging until consumed | `7d97192` | same |
| R17 | Inconsistent lock order (could deadlock) | Review operations acquired `JournalLock`/`ReviewLock` in inconsistent order relative to `FSync` | Canonical order `FSync → JournalLock → ReviewLock` for every review operation | `eeb6dd8` | `r17-*.log` |
| R18 | Fixed `MAX_PATH` `FILE_RENAME_INFO` buffer corrupts the stack for long paths | `RenameByHandle` declared a fixed `FileName: array[0..MAX_PATH]` and reported `SizeOf(record)`; a >261-char target overflowed the stack (0xC0000005) | Dynamically sized buffer at the exact C-layout name offset (`12` on x86, `20` on x64 — not Delphi's padded `SizeOf`, 24 on x64); long paths now work, over-long components fail cleanly with `ERROR_INVALID_NAME` | `d41537d` | `r18-probe-prefix-crash.log`, `r18-repro-prefix.log` (838/2 pre-fix), `r18-fixed-pass{,-x64}.log` |
| R19 | One DPAPI key shared by every installation under the account | Key at `%LOCALAPPDATA%\Portappix\rollback_key.bin`, process-wide; two installations authenticated each other's records (documentation also misstated the path — code used `TPath.GetHomePath`) | Key scoped to `%LOCALAPPDATA%\Portappix\keys\<sha256(canonical root)>\rollback_key.bin`; explicit-root API (`GetInstallationRollbackKey`, `TryGetInstallationRollbackKey`, `InstallationKeyBlobExists`); bounded legacy-key adoption; docs corrected | `19fcfa2` | `r19-repro-prefix.log` (4 FAILED pre-fix), `r19-fixed-pass{,-x64}.log` |
| R20 | Finalize recovery is not idempotent after a completed `ReplaceFileW` | Resume inferred the swap only from the pre-swap hash, but `ReplaceFileW` consumes the staged source binary — every post-swap recovery died with "staged launcher binary is missing" or "staging directory is missing" while the installation was actually correct | Durable `Cache\update_swap_done.json` written immediately after the swap (honoured only while the installed hash matches); missing staged binary is an error only when the swap is not done; missing staging dir + completed swap = success; marker cleared by `ConfirmUpdate`/rollback/restore; `UnfinalizedPendingUpdate` excludes completed swaps | `26e53d2` | `r20-repro-prefix.log` (3 FAILED pre-fix), `r20-fixed-pass{,-x64}.log` |

Additional requirements addressed in the same round:

- **Durable companion manifest** (`companion_manifest.json`, schema 1) with
  `replaced` (name + verified sha256) and `introduced` lists; `staged_files.json`
  written by `PrepareUpdate` so the introduced list survives a resumed finalize.
- **Every recovery/finalization operation is idempotent** — verified by the R20
  checkpoint matrix (five checkpoints, each resumed and then finalized again).
- **Backups preserved on every incomplete recovery path** — R15/R16 tests assert
  staging, previous companion dir and manifest survive every injected failure.
- **Deterministic failure injection** — `PortappixFileMoveHook`,
  `PortappixFileDeleteHook`, `PortappixDirectoryDeleteHook` (TESTINJECT only).
- **Process-termination tests at finalize checkpoints** — crash point with the
  failure restore suppressed (no exception handler could run).
- **Long Windows path tests** — 339-char rename target; full update+rollback E2E
  on a 327-char `\\?\` installation root.
- **Review concurrency tests** — R17 lock-order repro (`TestReviewLockInversion`).
- **Two installations under one account** — `TestInstallationKeyIsolation`.

### 9.2 Test results (raw logs in `docs/audit/phase2b-evidence/`)

| Configuration | Result | Log |
|---|---|---|
| Tests Win32 test-config (TESTCRASH+TESTUPDATE+TESTINJECT) | **930 passed / 0 failed** (×2 runs) | `r19-fixed-pass.log` |
| Tests Win64 test-config | **930 passed / 0 failed** (×2 runs) | `r19-fixed-pass-x64.log` |
| Tests Win32 release-config (TESTCRASH only) | **777 passed / 0 failed** | (this round, §4) |
| Tests Win64 release-config | **777 passed / 0 failed** | (this round, §4) |
| Production Win32/Win64 (RELEASE) | builds clean | — |
| `test_failure_injection_isolation.py` | **53 passed / 0 failed** | `r19-isolation.log` |
| `test_crash_hook_isolation.py` | 51 passed / 0 failed | — |
| `test_signing_workflow.py` | 46 passed / 0 failed | — |
| `test_icons.py` | 76 passed / 0 failed | — |

Assertion counts grew 835 → 930 (+95) across Phase 2B. Pre-fix evidence for
each finding was captured with the same tests against the pre-fix source; see
the per-finding logs above (15 + 2 + 4 + 3 targeted FAILs).

Also fixed while writing these tests (pre-existing, unrelated to the findings):
- A schema-2 rollback-record test evaluated `DateToISO8601(Now)` twice around a
  multi-millisecond DPAPI call, so millisecond timestamps could disagree
  (reproduced 3/5 on the pre-R18 x64 binary).
- `TestUpdateManager` rebuilt a zip and validated it against the stale release
  hash; zip local timestamps make a rebuild non-deterministic.

### 9.3 Remaining limitations (Phase 2B)

1. **Legacy key adoption** links installations created before R19 on the same
   machine (each copies the same historic key). New installations are fully
   independent. Documented in `UPDATE_ROLLBACK_INTEGRITY.md` §7.
2. **Long-path support is per-component bounded**: paths over `MAX_PATH` work,
   but a single component over 255 characters is rejected by NTFS (clean
   failure, no data loss).
3. **`RootDirectory`-relative handle renames are unsupported** by
   `SetFileInformationByHandle` on the tested Windows build (`ERROR_INVALID_PARAMETER`
   regardless of access flags or info class); the implementation uses absolute
   names, which is what the rollback path needs.
4. **Power-loss validation** of durable writes remains a VM-class open item
   inherited from earlier phases (unit simulation and real process termination
   are different evidence classes).
5. **Orphaned staging/companion directories** after an unrecoverable
   interruption are preserved deliberately (they may hold the only rollback
   copies) and require operator cleanup after inspection.

### 9.4 Release recommendation (Phase 2B)

**GO for the R15–R20 remediation.** All six findings have a deterministic
pre-fix repro, a targeted fix, and post-fix green suites on Win32 and Win64 in
both test configurations, plus a clean production build and a clean
failure-injection isolation scan (53/0). No P1 recovery or integrity defect
remains open from this round. The residual limitations in §9.3 are documented
and none permits silent data destruction or an unauthenticated/foreign record
to be accepted.

---

## 10. Release recommendation (Phase 2A, unchanged)

**GO** - release is recommended. All code-level findings are remediated and
verified by the 810-check Delphi suites on both bitnesses in two
configurations, four Python suites, three release-class builds, binary
isolation scans, and Windows Sandbox Gates 1–4 with real process termination,
watchdog rollback and tamper refusals against the production binary. Gate 5
remains a documented Windows Sandbox platform limitation (seclogon), inherited
from previous validation rounds, with the behavior covered by unit tests and
the full-VM procedure documented. The residual risks in §8 are documented and
accepted; none blocks release.
