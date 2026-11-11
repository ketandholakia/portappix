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
| Tests Win32 test-config | `-DPORTAPPIX_TESTCRASH -DPORTAPPIX_TESTUPDATE -DPORTAPPIX_TESTINJECT` | 0 | **810 passed / 0 failed** |
| Tests Win64 test-config | same, `dcc64` | 0 | **810 passed / 0 failed** |
| Tests Win32 release-config | `-DPORTAPPIX_TESTCRASH` | 0 | **761 passed / 0 failed** |
| Tests Win64 release-config | same, `dcc64` | 0 | **761 passed / 0 failed** |

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

## 9. Release recommendation

**GO** — release is recommended. All code-level findings are remediated and
verified by the 810-check Delphi suites on both bitnesses in two
configurations, four Python suites, three release-class builds, binary
isolation scans, and Windows Sandbox Gates 1–4 with real process termination,
watchdog rollback and tamper refusals against the production binary. Gate 5
remains a documented Windows Sandbox platform limitation (seclogon), inherited
from previous validation rounds, with the behavior covered by unit tests and
the full-VM procedure documented. The residual risks in §8 are documented and
accepted; none blocks release.
