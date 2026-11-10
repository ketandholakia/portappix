# Portappix — Phase 2 Report: Transactional Journal & Crash Recovery

Date: 2026-11-10. Branch `main`, HEAD `c4bce225d55c1b13ff9a88a9b8bc0d1fef1df180`
throughout (unchanged from the Phase 0/1 baseline; nothing committed or pushed).
All Phase 1 changes remain in place as uncommitted working-tree modifications,
plus the new Phase 2 changes.

## 1. Initial repository state

Verified at pre-flight: branch `main` @ `c4bce22`, 7 unpushed commits, working
tree = Phase 1's 11 modified files + untracked `docs/`, `keys/` (public key
only), `scripts/generate_signing_key.py`, `scripts/package_guard.py`,
`tests/scripts/`. All eight audit/security documents present. No discrepancies
against the expected baseline → no stop-and-report condition.

## 2. Phase 1 changes preserved

Every Phase 1 file survives byte-for-byte except where Phase 2 deliberately
extended shared files (`tests/PortappixTests.dpr` gained Phase 2 test
procedures; `.gitignore` gained `Transactions/` runtime-data entries; README
gained the transactional-flow description). Signing logic
(`Portappix.Signature.pas`, `sign_catalog.py`, `package_guard.py`) was not
modified in Phase 2. The signing key remains outside the repository; no key
material was read or printed.

## 3. Files changed (Phase 2)

Modified:

| File | Change |
| --- | --- |
| `src/Portappix.Transactions.pas` (**new**, 1,500+ lines) | Transaction model: 9-state machine with transition validation, operation records (8 kinds × 5 statuses), durable journal store (temp-file → `FlushFileBuffers` → verified → `MoveFileEx(REPLACE_EXISTING\|WRITE_THROUGH)` → directory flush, `.prev` fallback), strict JSON parse (schema 2), tx-id/app-id/path/backup-ownership validation, `TPortappixTransactionReconciler` (idempotent reverse-order undo shared by cleanup and recovery), `IPortappixHostPathOps` seam (default = real FS/junctions; fakes for tests), test-only `PORTAPPIX_CRASH_AT` checkpoint mechanism. |
| `src/Portappix.State.pas` (rewritten) | `TPortappixJournal` v2: `BeginTransaction` (durable `preparing`→`prepared`, refuses new work while any `recoveryRequired` transaction exists or the app has an unfinished one), journal-scoped named mutex (5 s timeout, `WAIT_ABANDONED` → mandatory validation + recovery assessment before proceeding), legacy schema-1 migration (verbatim payload, preserved as `run_state.json.legacy`, corrupt → `.bad`), recovery engine (oldest-first, app-running skip, idempotent reconcile, completion gate, quarantine of corrupt journals). |
| `src/Portappix.Runner.pas` (rewritten) | `Run` is now write-ahead: `BeginTransaction` before any host mutation (journal failure aborts the run with zero host changes); per-operation intent records persisted before and after each mutation; junction-host preparation captures the old junction target (new `GetJunctionTarget`, `FSCTL_GET_REPARSE_POINT`) and refuses removal when unrecordable; cleanup replays operations in reverse via the shared reconciler; `PerformCleanup` (legacy path) gained an optional host-ops seam. |
| `src/Portappix.Common.pas` | `WriteTextFileDurable` (flush + verified atomic replace + directory flush) and `FlushDirectoryWindows`. |
| `src/Portappix.Junction.pas` | `GetJunctionTarget` — read-only `FSCTL_GET_REPARSE_POINT` inspection (junction semantics unchanged). |
| `tests/PortappixTests.dpr` | `TestJournal` rewritten to schema 2 + five new test procedures (§6) + `TFakeTxRegistryOps`/`TFakeHostPathOps` fakes. |
| `.gitignore` | `Transactions/`, `run_state.json.legacy` added to runtime-data ignores. |
| `README.md` | Runtime flow + crash-safety sections rewritten for the transactional journal; layout table gains `Portappix.Transactions`. |
| `tests/fakeapps/src/CrashAtCheckpoint/` (**new**) | VM-integration fake app for crash-at-boundary runs (built successfully, execution is VM-only). |

Not modified (explicitly out of scope): junction preservation semantics,
ZIP extraction, license metadata, catalog features, UI.

## 4. Journal schema (v2)

```json
{
  "schemaVersion": 2,
  "txId": "<appid>-<16hex>-<16hex>",
  "appId": "...", "createdAt": "<ISO8601>",
  "state": "prepared|hostBackupComplete|hostStateChanging|hostStateChanged|
            running|cleaning|completed|recoveryRequired|preparing",
  "dataDir": "<root>\\Data\\<appid>",   // validated, must equal derived
  "legacy": false, "lastError": "",
  "operations": [ { "kind": "...", "status": "...", "hostPath": "",
                    "targetPath": "", "backupPath": "", "registryKey": "" } ]
}
```
Strict parsing: unknown schema version, missing/invalid fields, unknown
states/kinds/statuses, tx-id ↔ directory mismatch, app-id mismatch, or a
`dataDir` outside `<root>\Data\<appId>` all fail closed. Legacy
transactions carry `legacyKeys`/`legacyJunctions` arrays.

## 5. Evidence: journal persistence precedes every host mutation

- `Runner.Run` calls `FJournal.BeginTransaction` **before** any host work;
  `BeginTransaction` persists `preparing` then `prepared` durably and raises
  on any persistence failure (the runner then aborts with zero host changes).
- Every junction/registry step records its intent (`pending`, persisted,
  crash-point checkable) before the mutation and its completion after.
- Test evidence (Win32 + Win64, all passing):
  - "Ordering: journal failure prevents junction mutation" /
    "...registry mutation" — with the store armed to fail, `Run` raises and
    both fake call logs are empty.
  - "Ordering: crash after intent leaves the host directory untouched" —
    crash at `op:0:pending`; the intent is on disk, the rename never ran.
  - "Ordering: the pending intent is durably recorded".

## 6. Fault-injection and regression tests (new test counts)

All in `tests/PortappixTests.dpr` (hand-rolled harness, no DUnitX), executed
on Win32 and Win64 — **261 passed / 0 failed on each** (baseline 181 +
80 new checks):

- **TestTransactionPersistence** (13 checks): successful durable write;
  temp-file-creation failure; partial write; flush failure; replace failure;
  previous journal intact after each failure; invalid JSON; unsupported
  schema version; invalid state; invalid transition rejected; concurrent
  journal access → busy error (mutex held by another thread);
  abandoned-mutex → validation + recovery assessment, not blind continuation.
- **TestTransactionOrdering** (16): journal failure prevents junction AND
  registry mutation; crash after intent/before mutation; crash after
  registry backup (key untouched); crash after registry modification
  (recovery re-imports `registry_backup_1.reg`); crash during cleanup
  (transaction survives; recovery finishes the interrupted cleanup;
  junction removed; host directory restored).
- **TestRecoveryEngine** (24): recovery from `preparing` (discarded),
  `prepared`, `hostBackupComplete`, `hostStateChanging`, `running`,
  `cleaning`, `recoveryRequired` (retained, untouched, repeatedly);
  idempotency; failed restore retains the backup and retries successfully;
  missing backup fails closed (never false success); completed transactions
  finalized without restoration.
- **TestRecoveryPathSafety** (10): traversal, UNC, drive-root, junction
  target outside the data dir, tampered registry backup reference — each
  fails closed into `recoveryRequired` with zero host-path operations and
  no import of the tampered reference.
- **TestLegacyJournal** (7): valid schema-1 migration (export-before-delete
  order proven via call log; backup imported; junction removed; archived as
  `run_state.json.legacy`); invalid legacy key never reaches `reg.exe`;
  unusable entries preserved; corrupt `run_state.json` preserved as `.bad`
  with no host operations.
- The rewritten `TestJournal` (7): durable transaction.json; app id recorded;
  prepared state persisted; invalid transition rejected; empty prepared
  transaction resolved by recovery; corrupt journal quarantined as
  `transaction.json.bad` with the directory preserved.

## 7. Crash simulation results

- **Unit level (executed):** deterministic boundary crashes via the injected
  `PortappixCrashHook` at `state:*` and `op:N:{pending,done,restored}`
  checkpoints — covered by TestTransactionOrdering above (before intent,
  after intent, after backup, after mutation, mid-cleanup).
- **Process level (VM-only, NOT executed here):** the launcher honors
  `PORTAPPIX_CRASH_AT` (test-only env) with a hard `TerminateProcess` after
  the named checkpoint; `tests\fakeapps\src\CrashAtCheckpoint` (built
  successfully for Win32) drives the VM scenario. Per the phase constraints
  the destructive compatibility suite was **not run on this machine** — the
  documented VM/Sandbox procedure is in
  `docs/security/JOURNAL_TRANSACTION_AND_RECOVERY.md` §10.

## 8. Path-validation results

All ten §11 path/tampering cases pass (see TestRecoveryPathSafety), plus
dataDir validation at load time (fail closed → `recoveryRequired`). Also
proven: a junction whose live target does not match the record is never
removed ("refusing to remove ... not the recorded Portappix junction" →
manual), and a missing backup never yields false success.

## 9. Legacy journal migration results

Migration + recovery verified end-to-end with synthetic schema-1 fixtures
(valid / incomplete+invalid-id / corrupt): verbatim payload preservation,
export-before-delete ordering, backup import, junction removal, archive as
`run_state.json.legacy`, corrupt-file preservation. A migration bug found
during testing (legacy payload not serialized into the migrated journal) was
fixed and covered by the passing checks.

## 10. Build results

| Target | Result | Warnings |
| --- | --- | --- |
| Launcher Win32 (`dcc32 -B -E. -N0. -U<repo>\src src\Launcher.dpr`) | Success, 12,637 lines | W1002 ×2 (known, `Portappix.Junction.pas:49,73`) |
| Launcher Win64 (`dcc64`) | Success | W1002 ×2 |
| Tests Win32 | Success, 12,091 lines | W1002 ×2 |
| Tests Win64 | Success | W1002 ×2 |

All builds ran with isolated temp output directories; no existing ignored
artifact was overwritten. W1002 remains unsuppressed per instructions.

## 11. Test summary

| Suite | Result |
| --- | --- |
| Delphi tests Win32 | **261 passed / 0 failed** (181 baseline-equivalent + 80 new) |
| Delphi tests Win64 | **261 passed / 0 failed** |
| Python signing/package suite (Phase 1) | **24 passed / 0 failed** |
| `tests/suite/run_suite.ps1` | NOT-RUN — VM/Sandbox-only by its own header; destructive host tests prohibited on this machine |

The 181 baseline checks survive with their intent intact: the seven old
`run_state.json`-based journal checks were rewritten to their schema-2
equivalents (same guarantees), `PerformCleanup` ordering checks are
unchanged, and all other suites (manifest/policy/catalog/zip/trace/updates/
signature) are untouched and passing.

## 12. Remaining risks and limitations

1. **Same-user tampering**: documented honestly (§7 of the journal doc) —
   validation provides fail-closed consistency, not authenticity.
2. **VM integration unexecuted**: the full crash-at-boundary integration
   (real `TerminateProcess` + `CrashAtCheckpoint`) requires a VM/Sandbox;
   unit-level coverage is complete.
3. **`recoveryRequired` blocks all new transactions** until manually
   resolved — deliberately conservative; the manual procedure is documented.
4. **Registry operations remain non-transactional** (reg.exe limitation,
   documented since Phase 0); the journal guarantees ordering + retries.
5. **`FlushDirectoryWindows`** is best-effort on file systems that refuse
   directory-handle flushes.
6. A **pre-existing junction-host resolution bug** was found and fixed
   during testing: manifest junction hosts carrying `%VAR%` (e.g.
   `%APPDATA%\Foo`) previously resolved relative to the launcher root
   instead of the expanded path; expansion now matches what the policy
   engine validates. This is a behavioral fix, covered by the ordering
   tests operating on the expanded path.

## 13. Exact commands used

```
# pre-flight
git rev-parse --abbrev-ref HEAD; git rev-parse HEAD; git status --short

# builds (from %LOCALAPPDATA%\Temp\portappix-phase2-build\<dir>)
dcc32 -B -E. -N0. -UC:/Users/Admin/Documents/github/portappix/src \
    C:/Users/Admin/Documents/github/portappix/src/Launcher.dpr     # + dcc64
dcc32 -B -E. -N0. -UC:/Users/Admin/Documents/github/portappix/src \
    C:/Users/Admin/Documents/github/portappix/tests/PortappixTests.dpr  # + dcc64
dcc32 -B -Q -E. -N. ...tests/fakeapps/src/CrashAtCheckpoint/CrashAtCheckpoint.dpr

# tests
PortappixTests.exe                                        # Win32 + Win64
python tests/scripts/test_signing_workflow.py             # Phase 1 regression

# final review
git status --short; git diff --stat
```

## 14. Preservation confirmation

- HEAD and branch unchanged; 7 unpushed commits intact; nothing committed,
  pushed, stashed, reset or rebased.
- All Phase 1 modifications and untracked files present at the end of
  Phase 2 (verified by `git status` before and after).
- All ignored artifacts (`keys/`, `dist/`, `portappix.zip`, `bin/`, build
  outputs) untouched; Phase 2 builds ran in temp directories.
- No private-key material was read, printed, committed or packaged.
