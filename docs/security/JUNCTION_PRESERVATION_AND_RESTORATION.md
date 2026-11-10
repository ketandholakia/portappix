# Portappix Junction Preservation & Restoration

Phase 3 of the Portappix security & reliability roadmap. This document
specifies how Portappix inspects, classifies, replaces, and restores
host-filesystem reparse points so that a portable-app run can never destroy
a user's pre-existing filesystem configuration.

Implementation units: `Portappix.Junction` (inspection, classification,
creation, deletion), `Portappix.Transactions` (ownership metadata,
reconciler), `Portappix.Runner` (transactional junction lifecycle).

## 1. Windows reparse-point concepts

A reparse point is a filesystem object carrying a tag plus a data buffer
that redirects I/O. The generic on-disk layout is:

```
Offset  Size  Field
0       4     ReparseTag        (ULONG)
4       2     ReparseDataLength (USHORT)
6       2     Reserved          (USHORT)
8       ...   tag-specific data
```

The generic header is **8 bytes** (`ReparseHeaderSize`). For mount-point
junctions the tag-specific data is four USHORTs (substitute-name
offset/length, print-name offset/length) followed by the name buffer;
name offsets are relative to that buffer. Phase 2 and earlier used an
incorrect 16-byte header constant, which made `FSCTL_SET_REPARSE_POINT`
fail with `ERROR_REPARSE_ATTRIBUTE_MISMATCH` (4392) for every layout it
produced. The corrected layout was verified byte-for-byte against
junctions created by Windows itself (`mklink /J`): the names carry **no
terminators** inside their lengths, the print name starts one WCHAR after
the substitute name ends, and `ReparseDataLength` covers the fields plus
both names plus two trailing pad bytes.

## 2. Junction vs symbolic link

| | Junction (`IO_REPARSE_TAG_MOUNT_POINT`) | Symbolic link (`IO_REPARSE_TAG_SYMLINK`) |
| --- | --- | --- |
| Scope | Local volumes only (`\??\` device-space name) | Local, UNC, and relative targets |
| Creation privilege | None required | `SeCreateSymbolicLink` (developer/elevated) |
| Removal | `FSCTL_DELETE_REPARSE_POINT` + `RemoveDirectory`, non-recursive | Same mechanism, but Portappix **never removes symlinks** |

Portappix only ever creates, removes, and restores **mount-point
junctions**. Symbolic links and all other reparse tags are classified,
reported, and left untouched.

## 3. Supported reparse tags and classification

`Portappix.Junction.InspectPath` opens the object with
`FILE_FLAG_OPEN_REPARSE_POINT` (never following it), read-only, reads the
reparse buffer via `FSCTL_GET_REPARSE_POINT`, and classifies:

| Result | Meaning |
| --- | --- |
| `rkMissing` | `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` |
| `rkFile` / `rkDirectory` | Ordinary objects (no reparse attribute) |
| `rkJunction` | `IO_REPARSE_TAG_MOUNT_POINT` with a safely parsed target |
| `rkSymlink` | `IO_REPARSE_TAG_SYMLINK` (target decoded but never followed/removed) |
| `rkOtherReparse` | Any other tag — recognized, never interpreted |
| `rkInspectionFailed` | Exists but cannot be inspected (access denied, malformed buffer, open failure) — **fails closed**, never treated as an ordinary directory |

The inspection result carries path, kind, attributes, reparse tag, decoded
target (`TargetParsed` flag), object identity (§5), and error details.
`ParseReparseBuffer` validates buffer length, declared data length, and
name offsets/lengths before reading; malformed buffers fail safely. The
parser does **not** erase fields captured before parsing (identity is
captured from the open handle first; the parser takes the record by `var`
and only manages target/tag fields).

## 4. Original-state preservation strategy

`TPortableAppRunner.PrepareJunctionHost` classifies the host path before
any mutation and records the outcome on the junction-create operation
(`expectedOriginal`):

| Case | Behavior |
| --- | --- |
| A: absent | Record `absent`; proceed to create. Restoration verifies absence is regained. |
| B: ordinary directory | Never deleted. Renamed to `<path>_host_backup` (contents preserved) under a journaled `hostDirBackup` operation; restored after the run. A pre-existing `_host_backup` path aborts the run. |
| C: mount-point junction | Capture the exact target via `FSCTL_GET_REPARSE_POINT`; refuse if unparsable. Record `junctionRemoveOld` with the target (durable intent), then remove, then create the Portappix junction. |
| D: symbolic link | **Reject** with a clear error; the link is never removed. |
| E: other reparse tag | **Reject**; the object is never removed or overwritten. |
| F: inspection failure / ambiguous target | **Fail closed**; no host mutation. |

For case C the durable intent record *is* the preserved original: the
exact target is persisted before removal, and restoration recreates the
junction from it (mount-point junctions are fully described by their
tag + target).

## 5. Portappix junction ownership model

Every Portappix-created junction is recorded on its transaction operation
with:

- canonical host path and canonical target path,
- the reparse tag (hex),
- **filesystem object identity** — `volumeSerial:fileIndex` from
  `GetFileInformationByHandle` on the same non-following handle used for
  inspection, captured at creation time,
- the transaction ID (the operation lives inside the transaction
  directory) and application ID (encoded in and validated against the
  transaction id).

### 5.1 Phase 3 provenance: identity ownership is mandatory for new transactions

Transaction provenance is carried by an **optional top-level journal
field** (§7.1). A journal that is *positively identified* as a Phase 3
transaction (`"junctionOwnership": "identity"`) makes the **persisted
creation identity mandatory**: before the reconciler removes a
junction-create/remove object it requires an identity comparison that can
establish ownership.

- **Recorded identity absent → never remove.** If the record carries no
  identity, the junction is *not* removed based on the matching tag and
  target, even when both match perfectly. Ownership cannot be
  established from target+tag alone in that state, because there is a
  crash window between the junction object coming into existence
  (`FSCTL_SET_REPARSE_POINT`) and `MarkJunctionCreated` durably
  persisting the identity (`transaction.json` replace). In that window
  any other process on the same user account can delete the junction and
  recreate one with the *same canonical target but its own filesystem
  object* — every target+tag check then passes against an object
  Portappix never created. Recovery therefore: refuses removal,
  **preserves the current filesystem object untouched**, retains all
  recovery metadata (journal, registry backups — the transaction
  directory is never removed), sets the transaction state to
  `recoveryRequired`, and reports that ownership could not be
  established in `lastError`.
- The same rule applies when the on-disk object *is* still the one
  Portappix created: missing persisted identity is a record-side gap,
  not a fact about the object, and recovery never assumes facts it
  cannot verify. Removing the object in that state would be safe only by
  assumption.
- **Legacy Phase 2 transactions keep the compatibility behavior.** A
  journal *without* the provenance field is positively identified as
  Phase 2 (Phase 3 writers persist the field from the first durable
  journal write, before any junction operation exists, so a Phase 3
  journal can never lose it by omission). For those records the
  reconciler falls back to the strict target+tag match — which is still
  positive verification against both recorded values, not a blind
  removal.
- Unknown provenance values are rejected at parse time; ambiguous
  provenance always fails closed (§7.1).
- When the record carries an identity but the *filesystem* cannot supply
  one to compare against (non-NTFS), a Phase 3 transaction logs that the
  identity could not be verified and falls back to the strict target+tag
  match; the recorded-identity gap above is never tolerated, only the
  documented filesystem-side limitation is.

Before removing a junction, the reconciler re-inspects the current object
(non-following) and requires ALL of:

1. it is still a mount-point junction,
2. its target matches the recorded target canonically,
3. **for a positively identified Phase 3 transaction, the record also
   carries the persisted creation identity** — its absence fails closed
   into `recoveryRequired` before any comparison is attempted (§5.1), and
4. when the record and the filesystem both supply an identity, they
   match (a deleted-and-recreated object always has a new file index),
   with
5. host path, transaction id, and app id consistent with the transaction
   being reconciled.

Any mismatch → the object is **preserved**, the transaction becomes
`recoveryRequired`, and the recorded restoration information is retained.
No automatic conflict resolution ever deletes the unexpected object.

**Identity limitations (documented honestly):** `dwVolumeSerialNumber` +
`nFileIndex` are stable for a live object but are *not* guaranteed
permanent across filesystem migrations, backups/restores, or defrag-style
moves on non-NTFS filesystems; NTFS is the supported filesystem. When the
**filesystem** cannot supply an identity (ReFS via different APIs,
non-NTFS), or when a Phase 2 journal record carries none, the reconciler
falls back to the strict target+tag match and states so in the log — it
does not fail the operation, because target+tag ownership is still
positively verified. A **record-side** identity gap on a positively
identified Phase 3 transaction is different: it fails closed (§5.1). A same-user attacker
who replaces the junction with an identical-tag, identical-target junction
created by their own process WILL change the identity and is detected;
an attacker who also edits the journal can defeat the record (see the
journal threat model in
`docs/security/JOURNAL_TRANSACTION_AND_RECOVERY.md` §7 — the journal is
not tamper-proof).

## 6. Restoration algorithm

The reconciler walks the transaction's operations in reverse order
(newest first). For each junction operation it inspects reality first:

| Recorded intent | Current state | Action |
| --- | --- | --- |
| `junctionRemoveOld` (original target T) | Absent | Recreate the junction to T; **verify** target matches T; only then mark `restored`. |
| | Junction to T already present | Already restored — success, nothing done (idempotent). |
| | Junction with a different target | Conflict → `recoveryRequired`, object preserved. |
| | Symlink / other tag / directory / file | Conflict → `recoveryRequired`, object preserved. |
| | Original target directory missing | Restore proceeds; the missing target is explicitly reported (the junction is recreated exactly as recorded, dangling). |
| `junctionCreate` (Portappix junction) | Absent | Success (nothing to undo). |
| | Junction matching recorded target **and** identity | Remove (non-recursive), verify absence, mark `restored`. |
| | Anything else | Conflict → `recoveryRequired`, object preserved. |
| `hostDirBackup` / `hostDirRestore` | Backup present, host absent | Rename back; verify; `restored`. |
| | Both present or both missing | Conflict → `recoveryRequired`. |

Statuses are persisted (`restored`) only after verification succeeds.
The transaction directory — which holds the only registry backup files —
is removed **only** after every operation is resolved, so restoration is
idempotent and recovery data survives failed attempts.

## 7. Transaction integration

Phase 3 adds three optional fields to the existing schema-2 operation
records: `expectedOriginal`, `reparseTag`, `identity`. They are parsed
tolerantly (missing → empty) so **Phase 2 journals load unchanged**; for
those records the reconciler uses target+tag ownership (still positive
verification, no blind removal). The state machine, durable persistence,
locking, and recovery engine are Phase 2 mechanisms, unchanged. Every
junction mutation follows the same write-ahead protocol: inspect →
capture metadata → persist intent → mutate → verify → persist completion.

### 7.1 The provenance field (`junctionOwnership`)

Distinguishing legacy Phase 2 operations from Phase 3 operations needs an
explicit, migration-safe marker, because the operation-record fields
above are optional by design. The smallest representation that cannot
misclassify anything is an **optional top-level string field** on the
journal (not per operation — every operation in a journal is written by
one build):

```json
{ "schemaVersion": 2, ..., "junctionOwnership": "identity", ... }
```

Rules:

| Journal | Classification | Junction-ownership behavior |
| --- | --- | --- |
| Field present, value `identity` | Positively **Phase 3** | Persisted creation identity is **mandatory** (§5.1); missing identity → object preserved, `recoveryRequired`, ownership reported as unestablishable. |
| Field absent | Positively **Phase 2 legacy** | Documented compatibility: strict target+tag match (still positive verification, never blind). |
| Field present, any other value | **Ambiguous → fail closed** | The journal is rejected at parse time (quarantined like any invalid journal); no operation is ever attempted against it. |
| Field present with a non-string value | **Ambiguous → fail closed** | Same as above. |

Phase 3 writes persist the field from the **first durable journal write**
(transaction creation, state `preparing`), before any junction operation
can exist — so a Phase 3 transaction can never be silently classified as
legacy because an optional field is missing. Loaded journals are written
back with their own provenance verbatim, so a Phase 2 journal stays
Phase 2 through recovery passes (state changes and status marks never
invent the field).

The field is a provenance marker only. It is **not** an integrity
mechanism: the journal remains user-writable and non-tamper-proof (§2
of `JOURNAL_TRANSACTION_AND_RECOVERY.md`); it is never mixed with the
catalog signing key.

## 8. Crash-boundary behavior

Crashes between any two durable steps leave a state the recovery engine
reconciles against reality:

| Crash after… | Recovery action |
| --- | --- |
| original-target capture (intent persisted) | Junction still intact → reconcile verifies and marks restored, nothing destructive. |
| original junction removal | Recreate from the recorded target, verify. |
| junction object creation, **before the creation identity is persisted** (`MarkJunctionCreated` not yet durable) | The Portappix junction exists but the record carries no identity: ownership **cannot** be established from target+tag alone for a Phase 3 transaction (any same-user process could have swapped a same-target junction into that window). Recovery refuses removal, preserves the on-disk junction untouched, and marks the transaction `recoveryRequired`; the original junction cannot be restored past an unresolved conflict, so it is reported instead of recreated. Idempotent across passes. |
| portappix junction creation, **after** the creation identity is persisted (`MarkJunctionCreated` durable) | Remove the owned junction (identity+target verified), recreate the original. |
| Portappix junction removal (cleanup) | Continue restoring the original. |
| original restoration, before completion record | Verify restored state, finalize. |

Recovery is idempotent for every boundary (tested: running recovery twice
changes nothing). These boundaries are unit-tested with the injected
crash hook (`PortappixCrashHook`, exception-based) over fake host
operations, **plus** native filesystem tests (§9). The
junction-created-but-identity-unpersisted boundary above has its own
deterministic checkpoint between the created junction and
`MarkJunctionCreated` (`op:<n>:created`, test-only).

**Crash injection is compile-time isolated (Phase 4A).** The hook and the
`op:<n>:created` checkpoint exist only in builds compiled with
`-DPORTAPPIX_TESTCRASH`; a production launcher contains no crash-injection
mechanism and never reads `PORTAPPIX_CRASH_AT` (verified by byte scan — see
`docs/audit/phase-4/PHASE_4A_REPORT.md`). The `op:<n>:created` checkpoint
is fired by `Runner.CreateJunctionJournaled` between the junction's
creation and the persistence of its identity, so a test-mode run can be
stopped exactly inside the ownership window described above.

**Evidence classes are not interchangeable.** Exception-based unit tests
prove that the boundary is reached and that the code after it does not run;
they do not prove anything about the OS state after the process dies. Real
process termination in a VM (`tests/suite/run_crash_validation.ps1`,
executed manually with `-IConfirmThisIsAVM` only) additionally proves the
durable journal state and the fake app's survival. Hard power-loss /
forced-reset validation is still **outstanding** — it is not covered by
either of the two.

## 9. Test evidence

- **Parser unit tests (synthetic buffers):** unsupported tag classified,
  short buffer rejected, lying `ReparseDataLength` rejected, empty
  substitute name rejected — no out-of-bounds reads.
- **Native NTFS integration (real junctions in a dedicated temp root):**
  creation (verified layout), inspection/classification, identity capture
  and stability, delete+recreate identity change, broken (dangling)
  target inspection, symbolic-link classification, long-path handling,
  and a full real-reconciler lifecycle: preserve → replace → ownership-
  verified removal → verified restoration → idempotency → externally
  recreated junction (same target, new identity) refused and preserved →
  dangling-original restore with explicit reporting.
- **Fault injection (fake host ops):** the full §11 matrix from the phase
  brief — preservation cases A–F, ownership mismatches (target, identity,
  symlink replacement, directory replacement, Phase-2-record fallback),
  restoration (absent/original/idempotent/conflict/missing-target/
  transient-failure retry), and all eight crash boundaries with
  second-recovery idempotency.
- **Ownership window regression (Phase 3 remediation):** a junction is
  created with the intent durable and the process terminated *before*
  `MarkJunctionCreated` persists the creation identity; the junction is
  then replaced with a same-canonical-target junction of a *different*
  filesystem identity. Recovery refuses removal, leaves the external
  junction untouched, marks the transaction `recoveryRequired` with an
  explicit *ownership could not be established* report, and is
  idempotent (`TestJunctionCrashBeforeIdentityPersisted`, fake-host-ops
  runner + real recovery engine). A second test shows the same fail-closed
  outcome when the on-disk object is UNCHANGED but the identity was never
  persisted (`TestJunctionOwnershipUnpersistedIdentity`), keeps the
  Phase 2 no-identity record removable by strict target match, and
  quarantines a journal with an unknown `junctionOwnership` value
  without acting on it. Both also verified natively with real NTFS
  objects through the real reconciler
  (`TestNativeJunctionIdentityMandatory`): refusal, preservation, open
  transaction, and log reporting, for the untouched object *and* the
  same-target replacement.
- **Not executed here:** Windows Sandbox / VM forced-termination runs and
  the destructive compatibility suite (`tests/suite/run_suite.ps1`) —
  VM-only by their own safety contract. The Phase 4A crash harness
  (`tests/suite/run_crash_validation.ps1`) is prepared and statically
  inspected, but was **not executed** on the development workstation; see
  `docs/audit/phase-4/PHASE_4A_REPORT.md` for the current status.

## 10. Manual recovery procedure

When a transaction is `recoveryRequired` (a junction conflict, ambiguous
state, or validation failure):

1. Read `Transactions\<txid>\transaction.json` — `lastError` names the
   offending path and reason.
2. Inspect the named host path: if it holds a foreign junction/symlink,
   decide its fate manually (Portappix left it untouched).
3. If the recorded original junction should be restored: remove the
   foreign object yourself and re-create the junction to the recorded
   `targetPath` (e.g. `mklink /J <host> <target>`).
4. If the recorded state is correct and nothing is stranded, delete the
   transaction directory and restart the launcher — recovery will
   re-assess.

Never delete a `recoveryRequired` transaction without reading its
`lastError`: the transaction directory also holds registry backups that
may still be needed.

## 11. Known filesystem limitations

- NTFS only for junction semantics; `file index` identity is NTFS-backed
  (ReFS provides FileId via different APIs and is untested).
- Long paths (>260 chars) are not a supported configuration; inspection
  does not follow or crash on them, but creation is refused by the OS.
- Directory symbolic links require `SeCreateSymbolicLink`; the inspection
  test skips gracefully when absent.
- `FSCTL_*` operations require the handle opened with
  `FILE_FLAG_OPEN_REPARSE_POINT`; all inspection handles are read-only.
