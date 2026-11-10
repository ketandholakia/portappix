# Portappix Journal Transactions & Crash Recovery

Phase 2 of the Portappix security & reliability roadmap. This document
describes the transactional journal introduced in Phase 2, which guarantees
that a launcher crash, forced termination or power loss never leaves host
registry keys, junctions or renamed directories stranded without durable
recovery information.

## 1. Journal architecture

Each portable-app run is one **transaction**, stored under the launcher root:

```
Transactions\<txid>\transaction.json        durable journal (schema 2)
Transactions\<txid>\transaction.json.prev   previous good journal copy
Transactions\<txid>\registry_backup_<n>.reg host registry exports
```

- `<txid>` = `<appid>-<16 hex ticks>-<16 hex guid>` — validated against
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}-[0-9a-f]{16}-[0-9a-f]{16}$` before any
  directory is trusted; the app-id prefix must decode back to the
  transaction's `appId`.
- The journal is written by `TPortappixJournalStore` (injectable for tests);
  every state/operation change is a complete rewrite of `transaction.json`.
- The legacy schema-1 `run_state.json` is migrated into transactions on
  recovery and preserved as `run_state.json.legacy` (see §8).
- `Transactions/` is git-ignored runtime data, like `Cache/` and `Data/`.

Implementation units: `Portappix.Transactions` (model, state machine,
durable store, reconciler, path validation), `Portappix.State`
(`TPortappixJournal`: transaction creation, locking, migration, recovery
engine), `Portappix.Runner` (transactional run flow).

## 2. Transaction state machine

| State | Meaning |
| --- | --- |
| `preparing` | Record constructed in memory / first durable write; nothing host-visible has happened. |
| `prepared` | Intent durably persisted; the runner may begin the backup phase. |
| `hostBackupComplete` | Junction-host preparation and registry backups are complete; destructive mutations may begin. |
| `hostStateChanging` | Destructive mutations in progress (junction creation, host key deletion, portable registry import). |
| `hostStateChanged` | All mutations applied; the app may start. |
| `running` | The app process is running. |
| `cleaning` | Cleanup in progress: portable export, then reverse reconciliation. |
| `completed` | Host state fully restored; the transaction directory is removed. |
| `recoveryRequired` | The recovery engine hit an ambiguity it refuses to guess about; manual intervention required. |

Allowed transitions (enforced by `TPortappixTransaction.TransitionAllowed`;
invalid transitions raise):

```
preparing          -> prepared
prepared           -> hostBackupComplete | cleaning
hostBackupComplete -> hostStateChanging   | cleaning
hostStateChanging  -> hostStateChanged    | cleaning
hostStateChanged   -> running             | cleaning
running            -> cleaning
cleaning           -> completed
any non-terminal   -> recoveryRequired    (recovery engine only)
```

`completed` and `recoveryRequired` are terminal. Every transition is
durably persisted before the corresponding host work continues.

## 3. Write-ahead intent protocol

Every host mutation is represented by an **operation record** persisted
(`pending`) *before* the mutation and updated (`done`/`absent`/`failed`)
*after* it:

| Kind | Forward action | Recorded fields |
| --- | --- | --- |
| `junctionRemoveOld` | Remove a pre-existing reparse point | host path + the original junction target (captured via `FSCTL_GET_REPARSE_POINT`; removal is refused if the target cannot be recorded) |
| `hostDirBackup` | Rename an existing host directory to `<path>_host_backup` | host path + backup path (must equal `<path>_host_backup`) |
| `junctionCreate` | Create a Portappix junction | host path + target (must be inside the app data dir) |
| `registryBackup` | `reg.exe export` into the transaction dir | key + transaction-owned file name (`registry_backup_<opIndex>.reg`, assigned by the transaction itself) |
| `registryDelete` | `reg.exe delete` | key + the backup file it can be restored from |
| `junctionRemove` / `hostDirRestore` / `registryRestore` | Cleanup-phase undo steps | same fields as their forward counterparts |

Statuses: `pending` (intent only), `done` (performed + persisted),
`absent` (nothing to do — e.g. the key did not exist), `failed`
(attempt failed; the run aborts and recovery reconciles), `restored`
(undo verified during cleanup/recovery).

**Crash after mutation, before completion persistence:** the record stays
`pending` but the host may have changed. The reconciler never trusts the
status alone — it inspects the real host (reparse point? target match?
backup file present? key exists?) and reconciles accordingly. A missing
completion record is never interpreted as "did not happen".

## 4. Durable write strategy

`TPortappixJournalStore.Persist` (and `Portappix.Common.WriteTextFileDurable`):

1. Serialize the complete next journal state.
2. Write to a unique temporary file **in the same directory** (same volume).
3. `FlushFileBuffers` on the temp file; verify the written size.
4. `MoveFileEx(MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH)` onto
   `transaction.json` — the previous journal is copied to
   `transaction.json.prev` first (best effort) as a fallback copy.
5. Flush the parent directory (best effort) so the rename itself survives
   power loss.

Any failed step returns failure; the previous journal is never damaged and
the temporary file is removed. A failed persistence **raises**, and the
caller must not perform the associated host mutation — the runner's
`BeginTransaction` and every `RecordOperation`/state change follow this
rule. Loading tolerates a corrupt primary by falling back to `.prev`; if
both are unusable the files are preserved (`transaction.json.bad`) and the
transaction is quarantined, never destructively processed.

Note: `TFile.WriteAllText` alone (the old journal writer) is atomic but not
crash-durable; it is retained only for non-journal settings files.

## 5. Locking strategy

- A journal-scoped named mutex (`Local\Portappix.Journal.<sha256-24 of the
  root path>`) serializes transaction creation, recovery and completion
  **across processes**. It is distinct from the launcher single-instance and
  per-app mutexes so a headless `--run` can coexist with the tray launcher
  while journal mutations stay serialized.
- Acquisition waits up to 5 s; a timeout raises `EPortappixJournalBusy`
  instead of proceeding unlocked.
- **`WAIT_ABANDONED`** (the previous owner died holding the mutex) means we
  own the mutex but the previous holder may have died mid-update: the caller
  validates the journal first — `BeginTransaction` runs a full recovery
  assessment and *then* refuses to create a transaction while any
  `recoveryRequired` transaction exists; `RecoverPendingCleanups` proceeds
  with reconciliation, which is itself the assessment. Blind continuation
  after an abandoned mutex is not possible.
- Per-operation persists during a run rely on atomic per-file replacement;
  single-writer is guaranteed by the per-app mutex held for the run.
- An in-process critical section additionally serializes threads inside one
  launcher instance.

## 6. Recovery algorithm

`TPortappixJournal.RecoverPendingCleanups` (boot + `--recover`), under the
journal lock:

1. Migrate a legacy `run_state.json` if present (§8).
2. Enumerate `Transactions\*` directories with valid tx ids; load each
   journal (`.prev` fallback; corrupt → quarantine as `transaction.json.bad`
   and skip — never destructive).
3. Process oldest-first:
   - `preparing` → discard (nothing host-visible happened).
   - `completed` → remove the directory (final cleanup of a done run).
   - `recoveryRequired` → report manual intervention; leave untouched.
   - otherwise → if the app is running (per-app mutex or process scan),
     skip; else reconcile.
4. **Reconciliation** (`TPortappixTransactionReconciler`) walks operations in
   reverse order, skipping `restored`/`absent`, and for each `pending`/
   `failed`/`done` op verifies reality and restores the recorded original
   state:
   - junctions are removed **only** when the live target matches the
     recorded one (a foreign junction fails closed into `recoveryRequired`);
   - `_host_backup` renames are reverted only when the backup exists and the
     host path does not (both present → manual; both missing → manual);
   - registry deletes are restored by clearing the key (so app-added values
     cannot leak) and re-importing the transaction-owned backup; keys whose
     original state was "absent" are re-deleted if they reappeared;
   - a registry backup that is `done` but whose file is missing fails
     closed; a `pending` backup is re-exported or recorded `absent`;
   - **backup files are never deleted by recovery** — the whole transaction
     directory is removed only after every operation is confirmed restored.
5. Outcomes per operation: restored (persisted), retryable failure (kept
   for the next pass) or manual failure (persisted, state →
   `recoveryRequired`, other transactions still processed).
6. Completion requires **all** operations resolved (no `pending`/`failed`,
   and every undoable kind `restored`) — then `cleaning` → `completed` →
   directory removal.

Recovery is idempotent: re-running it skips `restored` operations, is
satisfied by already-restored host state, and never deletes backups before
their restore is confirmed.

## 7. Path validation and tamper posture

Every path loaded from the journal is validated before use
(`TPortappixTransaction`):

- transaction ids: strict pattern + app-id cross-check;
- `dataDir`: must be exactly `<root>\Data\<appId>` (canonical, component-
  wise compare — the journal's `dataDir` is redundant and untrusted);
- registry keys: `ParseRegistryPath` + HKCU-only + safe components before
  any `reg.exe` argument is built;
- registry backup references: must equal `<tx-dir>\registry_backup_<n>.reg`
  (transaction-owned naming, op-index owned by the transaction itself);
- junction host paths: absolute, non-UNC, not a drive root, traversal-free,
  never inside transaction storage; junction targets: inside the app data
  dir; `_host_backup` names: exactly `<host>_host_backup`;
- comparisons are canonicalized and component-wise with separator-boundary
  awareness (never plain string prefixes); traversal is rejected before
  canonicalization so `..` cannot sneak through `GetFullPath`.

**Integrity / threat model (honest statement):** the journal and backups
live in a user-writable directory. A process running as the same user can
rewrite the journal *and* the backup files, so no mechanism available here
(DPAPI is per-user too) defends against that attacker — the journal is NOT
tamper-proof. What validation buys: structural consistency (schema, state,
tx id, ownership) so a *corrupt or inconsistent* journal fails closed into
`recoveryRequired` instead of executing recovery from garbage, and a same-
user attacker gains nothing they could not do directly (their own HKCU, their
own files). Where the launcher runs elevated, journal contents are still
never executed as commands — only validated paths reach `reg.exe`, and
junction work requires target-match against the recorded values. No secret
is embedded; the catalog signing key is not used for journal authentication.

## 8. Legacy schema-1 migration

The old `run_state.json` (`apps.<id> = {active, dataDir, startedAt,
hijackedKeys[], junctions[]}`) is migrated on recovery:

- each app becomes a transaction with state `hostStateChanging` and
  `legacy: true`; the recorded keys/junctions are copied **verbatim**
  (nothing invented) after validation — invalid entries are dropped with a
  manual-review log line;
- the recorded `dataDir` is only accepted when it equals the derived
  `<root>\Data\<appId>`; otherwise the derived path is used (the field is
  redundant);
- recovery applies the **proven legacy semantics** — export-before-delete
  via `TPortableAppRunner.PerformCleanup` plus a scanned restore of
  remaining `host_backup_*.reg` files — and completes only when no host
  backups remain;
- the original file is copied to `run_state.json.legacy` and removed only
  after a successful migration pass; a corrupt file is preserved (`.bad`)
  and left for manual inspection.

Manual recovery procedure (for `recoveryRequired`): inspect
`Transactions\<txid>\transaction.json.lastError`, verify/repair the host
state described there (restore the named backup, remove the named
junction), then delete the transaction directory — or fix the underlying
cause and restart the launcher to let recovery retry. See the error text;
it always names the offending path or file.

## 9. Recovery failure handling

- Retryable failures (transient `reg.exe`/rename errors) keep the
  transaction in its current state with a persisted error note; the next
  boot retries.
- Manual failures set `recoveryRequired`, retain the journal and all
  backups, and **block all new transactions** until resolved.
- A corrupt journal is quarantined (`transaction.json.bad`) and skipped.
- Recovery never silently converts a failed restore into a successful
  cleanup, and never deletes the only remaining backup.

## 10. Crash simulation support

Crash injection is **compile-time isolated**. It exists only in builds
compiled with the `PORTAPPIX_TESTCRASH` define (the test-mode launcher and
the unit-test build). A production launcher contains no crash-injection
mechanism at all and never reads `PORTAPPIX_CRASH_AT`.

### 10.1 Production build (no `PORTAPPIX_TESTCRASH`)

- `Portappix.Transactions` declares neither `PortappixCrashPoint` nor
  `PortappixCrashHook`; `CheckCrashPoint` compiles to an empty no-op at
  every call site.
- `Launcher.dpr` contains no environment-variable reader for
  `PORTAPPIX_CRASH_AT` and no arming message.
- Verified by byte scan: the production launcher contains neither the
  string `PORTAPPIX_CRASH_AT` nor the marker
  `PORTAPPIX-TESTCRASH-BUILD-2026-11-10` (see
  `docs/audit/phase-4/PHASE_4A_REPORT.md` and
  `tests/scripts/test_crash_hook_isolation.py`).
- `scripts/make_release.py` inspects the actual staged launcher before
  packaging and refuses to publish a launcher that contains either string
  (and fails closed on a missing, empty or unreadable launcher).

### 10.2 Test-mode build (`-DPORTAPPIX_TESTCRASH`)

- `Launcher.dpr` reads `PORTAPPIX_CRASH_AT` **before** any CLI/UI
  initialization and arms the checkpoint through
  `SetCrashPointFromString`. A valid identifier is armed and reported with
  the `[testcrash]` marker line; an invalid identifier is ignored with a
  warning and **no** checkpoint is armed.
- Identifier grammar (case-sensitive, no whitespace anywhere):
  - `state:<canonical state name>` — one of `preparing`, `prepared`,
    `hostBackupComplete`, `hostStateChanging`, `hostStateChanged`,
    `running`, `cleaning`, `completed`, `recoveryRequired`.
  - `op:<non-negative index>:<status>` — status is one of `pending`,
    `done`, `absent`, `failed`, `restored`, or `created`.
  - Unknown names, unknown statuses, negative or non-numeric indices,
    empty or whitespace-only values, malformed separators and extra
    components are all rejected and never arm a checkpoint.
- At the armed boundary the launcher calls `TerminateProcess` on itself
  (exit code 1) — a real process termination, not an exception.
- Checkpoint call sites (unchanged in position by Phase 4A):
  `state:<name>` after the state was durably persisted,
  `op:<n>:pending` after the operation intent was durably persisted,
  `op:<n>:<status>` after the status was durably persisted,
  `op:<n>:done` after a created junction's tag **and identity** were
  durably persisted, and `op:<n>:created` inside
  `Runner.CreateJunctionJournaled` between the junction's creation and the
  persistence of its identity (`created` is never a persisted status).

### 10.3 What each kind of evidence does and does not prove

| Evidence | What it proves | What it does NOT prove |
|---|---|---|
| Unit test with a raising hook (`PortappixCrashHook`) | the boundary is reached and the code after it does not run | nothing about the OS state after the process dies |
| Real process termination (`TerminateProcess`) in a VM | the launcher really dies at that boundary with the documented durable journal on disk | nothing about a sudden power loss |
| Hard power loss / forced reset | — | **not performed**; it remains an outstanding validation item |

### 10.4 VM/Sandbox crash validation

`tests/suite/run_crash_validation.ps1` drives the test-mode launcher with
real process terminations, one fresh disposable root per checkpoint, and
asserts the fake app's survival, the durable journal state, and a two-pass
idempotent recovery. It is executed **manually inside an isolated VM or
Windows Sandbox only** (it refuses to run without `-IConfirmThisIsAVM` and
refuses any launcher that is not a test-mode build). It was **not executed**
on the development workstation; see the Phase 4A report for the current
status.


## 11. Known limitations

1. Same-user tampering cannot be defeated by any journal mechanism (§7);
   integrity here means consistency validation + fail-closed, not
   authenticity.
2. Recovery requires the launcher to run again — a machine that never boots
   the launcher keeps stranded state (by design: recovery is always
   user-visible, never a background service).
3. `FlushDirectoryWindows` is best-effort; on file systems that reject
   directory flushes the rename durability falls back to
   `MOVEFILE_WRITE_THROUGH` semantics.
4. The legacy migration trusts the *presence* of `host_backup_<n>.reg`
   files (legacy had no better record); unexpected backup names are flagged
   for manual review rather than imported.
5. `reg.exe` operations remain non-transactional (documented since Phase 0);
   the journal guarantees *ordering and retries*, not registry atomicity.
