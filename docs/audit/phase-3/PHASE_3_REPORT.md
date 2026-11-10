# Portappix — Phase 3 Report: Junction Preservation & Safe Restoration

Date: 2026-11-10. Branch `main`, HEAD `c4bce225d55c1b13ff9a88a9b8bc0d1fef1df180`
throughout (unchanged since Phase 0; nothing committed or pushed). Phase 1 and
Phase 2 uncommitted changes fully preserved alongside the Phase 3 changes.
No secrets or private-key material appear in this report or the diff (scanned).

## 1. Initial repository state (continuation checks)

Verified: branch `main`, HEAD `c4bce22`, 7 unpushed commits, 0 stashes, 22
modified/untracked paths carrying Phase 1 (signing rotation, package guard)
and Phase 2 (transactional journal) work, `docs/audit/phase-{0,1,2}`,
`docs/security/{SIGNING_KEY_MANAGEMENT,JOURNAL_TRANSACTION_AND_RECOVERY}.md`,
signing key outside the repo (1 file under `%USERPROFILE%\.portappix\signing`).
No discrepancies → continuation approved.

## 2. Files modified / added (Phase 3 delta)

| File | Change |
| --- | --- |
| `src/Portappix.Junction.pas` (rewritten cleanly) | Reparse inspection & classification (`TPortappixPathInspection`, 7 kinds), correct 8-byte reparse header, verified junction buffer layout, `GetFileInformationByHandle` object identity, `ParseReparseBuffer` (pure, bounds-checked, takes the record by `var` so identity survives parsing), `GetJunctionTarget` reimplemented over the inspector. |
| `src/Portappix.Transactions.pas` | Operation records gain `expectedOriginal` / `reparseTag` / `identity` (tolerant parse — Phase 2 journals still load); `MakeJunctionOperation`, `MarkJunctionCreated` (interface + impl); `InspectPath` added to `IPortappixHostPathOps`; reconciler rewritten to inspection-based ownership verification and verified restoration for `junctionRemoveOld` / `junctionCreate` / `hostDirBackup` / `hostDirRestore`. |
| `src/Portappix.Runner.pas` | `PrepareJunctionHost` classification-driven (Cases A–F: absent/directory/junction/symlink/other-tag/inspection-failure — symlinks and other tags rejected untouched, ambiguous targets fail closed); `CreateJunctionJournaled` verifies created type+target and persists ownership identity; per-junction original-kind tracking. |
| `tests/PortappixTests.dpr` | New test procedures: `TestReparseInspection` (native NTFS + synthetic buffers), `TestJunctionPreservation`, `TestJunctionOwnership`, `TestJunctionRestoration`, `TestJunctionCrashBoundaries`, `TestNativeJunctionLifecycle` (real reconciler + real FS), upgraded `TFakeHostPathOps` (junction/symlink/other-tag/identity/access-denied/target-parse simulation); manifest fixtures corrected. |
| `docs/security/JUNCTION_PRESERVATION_AND_RESTORATION.md` (**new**) | Full specification (concepts, layout, classification, ownership, restoration, threat model, manual recovery, limitations). |
| `docs/audit/phase-3/PHASE_3_REPORT.md` (**new**) | This report. |

## 3. Old vs new junction lifecycle

**Old (Phase 0/2):** backup-dir-or-remove-reparse-point using a generic
empty-target check — a symlink or foreign reparse point was rejected only
indirectly (its "target" read as empty); the original junction target was
captured (Phase 2) but restoration was never verified, absence of the host
path was not persisted, and removal relied on target-match alone (an
externally recreated junction with the same target passed).

**New:** classify first (7-way, fail-closed); reject symlinks and unknown
tags explicitly; persist `expectedOriginal`; capture target AND filesystem
identity; removal requires tag+target+identity+path+transaction match;
restoration re-inspects and verifies before `restored`; conflicts become
`recoveryRequired` with the foreign object preserved.

## 4. Reparse-point classification evidence

`TestReparseInspection` (real NTFS junctions + real symlink when privilege
allows + synthetic buffers): missing/directory/file/junction/symlink/
broken-target/unsupported-tag classifications all PASS; malformed and
lying-length buffers rejected; identity captured, stable, and changed
after delete+recreate; `ParseReparseBuffer` never reads out of bounds.
Native creation now succeeds with the corrected layout (previously 4392).

## 5. Original-junction preservation evidence

`TestJunctionPreservation` (fake host ops, 18 checks): originally-absent
paths persist `expectedOriginal: 'absent'` (verified in the surviving
journal after a simulated crash); directories and contents survive;
existing junction targets are captured before removal and restored after;
symlinks/unsupported tags/ambiguous targets/inspection failures/
persistence failures each reject with the specific message and leave the
object preserved.

## 6. Ownership-verification evidence

`TestJunctionOwnership` (13 checks): the recorded junction is removed;
different target, symlink replacement, directory replacement, externally
recreated junction (same target, fresh identity), and inspection failures
each refuse removal → `recoveryRequired`, object preserved; Phase 2
records without identity still removed by strict target match.

## 7. Restoration + idempotency evidence

`TestJunctionRestoration` (12 checks) and the native lifecycle (16 checks):
original junction restored with exact target; absent restored to absent;
repeated reconciliation idempotent; already-restored original untouched;
conflicts persist; missing original target reported while the junction is
restored exactly as recorded (dangling); transient import failure retains
the backup and a retry succeeds; failed restoration never completes the
transaction; restored status recorded only after verification.

## 8. Crash-boundary results (fake-ops fault injection)

All 8 boundaries exercised in `TestJunctionCrashBoundaries` (intent,
post-preservation, post-creation, post-restoration checkpoints +
`op:N:{pending,done,restored}` machine), each followed by fresh recovery,
host-state verification, and a second recovery for idempotency — PASS.
Additionally Phase 2's ordering scenarios re-exercised pre-launch and
mid-cleanup crashes against the new reconciler — PASS.

**Clearly distinguished:** unit crash tests are exception-based over fake
ops; native integration runs the real reconciler over real NTFS objects;
real child-process termination and VM/Sandbox power-loss tests were NOT
run (pending, §11).

## 9. Real Windows integration results

- `TestReparseInspection`: real `CreateJunction`/`DeleteJunction`/
  `InspectPath` on temp-root NTFS — creation succeeds with the corrected
  buffer layout (the Phase 2 layout failed with error 4392; root cause was
  the 16-byte header constant plus missing name-padding bytes; verified
  byte-for-byte against `mklink /J` output, documented in the security
  doc §1).
- `TestNativeJunctionLifecycle`: real reconciler + real FS lifecycle —
  preservation, replacement, ownership-verified removal, verified
  restoration, idempotency, external-recreation conflict (refused and
  preserved untouched, transaction stays open), dangling-original
  restoration with explicit reporting. 16 checks PASS.
- Defects found and fixed by these tests: reparse header size (16 → 8),
  buffer layout (no terminators, 2-byte print-name gap, trailing pads),
  `ParseReparseBuffer` `out`→`var` (identity was erased by parsing),
  junction host paths not %-expanded in `ResolvePaths` (found by the
  Phase 2 ordering suite), and the completion gate treating undone-`done`
  ops as resolved (Phase 2 defect, fixed and covered).

## 10. Build and test results

| Target | Result |
| --- | --- |
| Launcher Win32 (`dcc32 -B -E. -N0. -U<repo>\src src\Launcher.dpr`) | Success — 13,100 lines |
| Launcher Win64 (`dcc64`, same) | Success — 13,100 lines |
| Tests Win32 | Success — 13,598 lines, **345 passed / 0 failed** |
| Tests Win64 | Success, **345 passed / 0 failed** |
| Python signing/package suite (Phase 1) | **24 passed / 0 failed** |
| `tests/suite/run_suite.ps1` | NOT-RUN — VM/Sandbox-only by contract |

Baseline for comparison: Phase 2 ended at 261/261 per target. Phase 3 adds
84 checks (345 − 261). All builds used fresh isolated output directories
(`%LOCALAPPDATA%\Temp\portappix-phase3-build\`); no ignored artifact was
overwritten; the known W1002 warnings remain unsuppressed.

## 11. Remaining risks, limitations, pending validation

1. **VM/Sandbox crash validation pending** — real forced termination /
   power-loss durability of the journal and junction restoration is
   designed and unit-modeled but not OS-verified here.
2. **Same-user journal tampering** can still forge a target-only record
   for Phase 2-era journals (documented threat model; identity metadata
   closes this for new transactions).
3. `fileIndex` identity is NTFS-backed; other filesystems fall back to
   target+tag ownership (still positive verification).
4. Long paths (>260) unsupported; symlinks require privilege (tests skip
   gracefully).
5. A `recoveryRequired` transaction blocks new runs until manual
   resolution (documented procedure).

## 12. Exact commands used

```
git rev-parse --abbrev-ref HEAD; git rev-parse HEAD; git status --short
dcc32 -B -E. -N0. -U<repo>\src <repo>\tests\PortappixTests.dpr   # + dcc64
dcc32 -B -E. -N0. -U<repo>\src <repo>\src\Launcher.dpr           # + dcc64
PortappixTests.exe                                               # Win32 + Win64
python tests/scripts/test_signing_workflow.py
git diff --stat; git diff | grep -iE "PRIVATE KEY|PASSWORD|API_KEY"
```

## 13. Preservation confirmation

- HEAD and branch unchanged; 7 unpushed commits intact; no stash/reset/
  rebase/amend; nothing committed or pushed.
- All Phase 1 and Phase 2 modifications and untracked files present
  (22 paths before, same set plus the two new Phase 3 documents).
- All ignored artifacts untouched; builds ran in fresh temp directories.
- Diff secret scan: zero matches for private-key/password/API-key
  markers; no debug instrumentation remains in `src/` or the test file.

## 14. Remediation addendum: mandatory persisted ownership identity

Date: 2026-11-10 (same session, same HEAD `c4bce22`; still **nothing
committed or pushed**; branch unchanged; 7 unpushed commits intact; all
Phase 1/2 work and ignored artifacts preserved).

### 14.1 Gap closed

An identity-carrying Phase 3 junction-create record whose creation
identity had not yet been persisted (crash between the junction object
existing and `MarkJunctionCreated`'s durable journal replace) was
previously removable by the reconciler on tag+target match alone — the
identity check silently degraded to the Phase 2 fallback whenever the
record's `identity` field was empty, regardless of transaction
provenance. In that crash window a same-user process can replace the
junction with an identical-tag, identical-target junction of its own, so
target+tag equality is not evidence of ownership for a new transaction.

### 14.2 Distinguishing legacy from new operations (smallest migration-safe change)

A new, optional, top-level schema-2 journal field
`"junctionOwnership": "identity"` marks provenance (not integrity — the
journal is not tamper-proof and is not mixed with the catalog signing
key):

| Journal | Classification | Behavior on junction removal |
| --- | --- | --- |
| Field present, value `identity` | Phase 3 | Persisted identity MANDATORY; absent → refuse removal, object preserved, `recoveryRequired`, ownership reported as unestablishable, recovery metadata retained, idempotent. |
| Field absent | Positively Phase 2 legacy | Documented strict target+tag compatibility match (positive verification). |
| Unknown / non-string value | Ambiguous → fail closed | Journal rejected at parse time and quarantined; nothing acted upon. |

Phase 3 writers persist the field from the FIRST durable journal write
(transaction creation), before any junction operation can exist — a
Phase 3 journal therefore cannot be misclassified as legacy for missing
a field. Loaded journals are re-persisted with their own provenance
verbatim, so Phase 2 journals stay Phase 2 through recovery. Legacy
migrated transactions (`legacy: true`) are unaffected and carry no
provenance field. Schema version remains 2.

### 14.3 Files changed in the remediation delta

| File | Change |
| --- | --- |
| `src/Portappix.Transactions.pas` | Provenance constants, `TPortappixTransaction.JunctionOwnership` (+ optional trailing constructor parameter, default legacy), strict provenance validation in `ParseJsonInto`, provenance round-trip in `ToJson`, `IdentityOwnershipRequired`, and the fail-closed rule in `UndoJunctionCreate`. |
| `src/Portappix.State.pas` | `BeginTransaction` passes `PortappixOwnershipFieldIdentity` so the provenance is durable before any junction op. |
| `src/Portappix.Runner.pas` | Test-only crash checkpoint `op:<n>:created` in `CreateJunctionJournaled` (between junction existence and identity persistence). |
| `tests/PortappixTests.dpr` | Three new regression tests (§14.4); no existing test changed. |
| `docs/security/JUNCTION_PRESERVATION_AND_RESTORATION.md` | §5.1 provenance rules, rewrote the §5 ownership checklist, §7.1 provenance field table, §8 crash table row for the identity window, §9 test evidence. |
| `docs/audit/phase-3/PHASE_3_REPORT.md` | This addendum. |

### 14.4 New regression tests (23 new checks; existing checks unchanged)

1. `TestJunctionCrashBeforeIdentityPersisted` (9 checks) — the full
   deterministic crash scenario: intent persisted → junction created →
   termination before identity persistence → same-canonical-target
   replacement with a different identity → recovery refuses removal →
   replacement junction untouched → transaction `recoveryRequired` →
   explicit ownership report → recovery metadata retained → second
   recovery pass idempotent.
2. `TestJunctionOwnershipUnpersistedIdentity` (6 checks) — unchanged
   object with unpersisted identity still fails closed (no ownership
   assumption from target+tag); Phase 2 record without identity remains
   removable by strict target match; an unknown provenance value
   quarantines the journal and preserves the junction.
3. `TestNativeJunctionIdentityMandatory` (8 checks) — real NTFS junctions
   + real reconciler: refusal and preservation for (a) the untouched
   object and (b) a same-target external replacement; transaction stays
   open; refusal is idempotent; log reports the unresolved ownership.

### 14.5 Results

| Target | Result |
| --- | --- |
| Tests Win32 (`dcc32`, fresh dir `%LOCALAPPDATA%\Temp\p3rem-w32`) | **368 passed / 0 failed** (baseline 345 + 23 new) |
| Tests Win64 (`dcc64`, fresh dir `%LOCALAPPDATA%\Temp\p3rem-w64`) | **368 passed / 0 failed** |
| Launcher Win32 (`dcc32`, fresh dir `p3rem-w32-launch`) | Success — 13,222 lines |
| Launcher Win64 (`dcc64`, fresh dir `p3rem-w64-launch`) | Success — 13,222 lines |
| Python signing/package suite | **24 passed / 0 failed** |
| Native NTFS junction lifecycle (`TestNativeJunctionLifecycle` + `TestNativeJunctionIdentityMandatory`) | All checks PASS on real NTFS (creation, classification, identity capture/stability, verified restoration, idempotency, ownership-window refusals). |
| `tests/suite/run_suite.ps1` | NOT-RUN — VM/Sandbox-only by contract |

Legacy compatibility evidence (unchanged behavior where the transaction
is positively Phase 2): Phase 2 records without identity are still
removed by strict target match (`TestJunctionOwnership` and the new
pending-record check); Phase 2 journals round-trip recovery without
gaining the provenance field; migrated legacy transactions are
untouched. External same-target replacements are never removed, never
overwritten, and never deleted either directly or over-written by
another operation — the conflicting junction is preserved and only the
recorded restoration information is retained (§14.4 checks 1 and 3, and
the native preserved-untouched checks).

### 14.6 Preservation confirmation (addendum)

- `git rev-parse HEAD` = `c4bce225d55c1b13ff9a88a9b8bc0d1fef1df180`
  unchanged; branch `main`; 7 unpushed commits intact; index/worktree
  carry the same pre-existing modified/untracked paths plus this
  remediation delta; nothing staged, committed, stashed, reset,
  rebased, or pushed.
- No Phase 1 or Phase 2 change was reverted or overwritten; the only
  source edits are additive (new field/parameter/checkpoint/rules). All
  previously existing tests still pass with their exact original
  assertions (no existing test was modified).
- Builds and outputs live in fresh `%LOCALAPPDATA%\Temp` directories;
  no pre-existing artifact was overwritten.
