# Update Rollback Integrity — Threat Model and Design

**Status:** Implemented 2026-11-11 as part of the independent source-code review remediation.
**Scope:** launcher self-update rollback metadata (`Cache\old_launcher.json`), the
pre-rollback verification (`Portappix.Update.pas`), the review-metadata subsystem
(`Portappix.State.pas`), and the deterministic failure-injection seams.

---

## 1. Assets and adversaries

| Asset | Location | Sensitivity |
|---|---|---|
| Previous launcher binary | `Launcher.exe.old` | High — it becomes the running launcher after a rollback |
| Rollback verification record | `Cache\old_launcher.json` | High — it authenticates the binary above |
| Update state markers | `Cache\update_ok`, `Cache\update_pending.json` | Medium — control the watchdog/rollback offer |
| Review metadata | `Transactions\needs_review.json` | High — gates whether apps may run |

Adversary classes considered:

1. **Accidental corruption** — a crash, power loss, disk fault, or misbehaving
   tool truncates or garbles the metadata files.
2. **Unprivileged / other-user tampering** — code running as a different user
   or with a restricted token that can nonetheless reach the install directory
   (portable installations often live in user-writable locations).
3. **Same-user malware without key access** — code running as the launcher's
   user that can write the install directory but cannot read the DPAPI-protected
   rollback record key (e.g. blocked by ACL, or running in a context where DPAPI
   decryption of the key blob fails).
4. **Same-user arbitrary code (residual risk, NOT defended):** code running as
   the launcher's user that can read `%LOCALAPPDATA%\Portappix\rollback_key.bin`
   and call `CryptUnprotectData` can recover the HMAC key and forge a fully
   authenticated record. **No locally-stored secret can defend against this
   class**; the launcher deliberately does not pretend otherwise. The defense
   for this class is OS-level (user separation, AV/EDR) and distribution-level
   (signed catalogs and releases.json), which are documented separately
   (`SIGNING_KEY_MANAGEMENT.md`).

## 2. Rollback metadata authentication (schema 2)

`RecordOldLauncher` writes `Cache\old_launcher.json` as **schema 2**:

```json
{
  "schema": 2,
  "sha256": "<64-hex lowercase sha256 of Launcher.exe.old>",
  "size": <exact byte length>,
  "version": "<retiring launcher version>",
  "time": "<ISO-8601>",
  "recordedAt": "<ISO-8601>",
  "hmac": "<64-hex HMAC-SHA256>"
}
```

- The HMAC-SHA256 is computed with `System.Hash.THashSHA2.GetHMACAsBytes` over a
  canonical, length-prefixed serialization of the protected fields, in fixed
  order:

  ```
  portappix-rollback-record-v2\n
  <len(sha256)>:<sha256>\n
  <size>\n
  <len(version)>:<version>\n
  <len(recordedAt)>:<recordedAt>
  ```

  Length-prefixing prevents any field value from shifting into another field's
  position. `time` is informational and is not covered by the HMAC (it always
  equals `recordedAt` in records the launcher writes).
- The HMAC key is 32 random bytes (`BCryptGenRandom`) generated per
  installation on first use, wrapped with DPAPI (`CryptProtectData`, user
  scope, `CRYPTPROTECT_UI_FORBIDDEN`) and stored at
  `%LOCALAPPDATA%\Portappix\rollback_key.bin`. The user-profile ACL (user-only
  by default on NTFS) plus DPAPI user scoping mean the key blob is bound to the
  user account that created it. The key file is created without wide sharing.
- **Failure behavior is fail-closed everywhere:**
  - record write failure → the update aborts before the executable is renamed
    (`RecordOldLauncher` runs BEFORE the rename);
  - missing/invalid HMAC on a schema-2 record → rollback refused;
  - HMAC from a different installation key → rollback refused;
  - unreadable key → rollback refused with the reason.

### 2.1 Schema-1 migration

Records written by earlier launchers (schema 1, no HMAC) are accepted at
verification time **only** after passing every other check (hex sha256, size,
version consistency, hash match). A verified schema-1 record is then
**re-stamped** as schema 2 with a computed HMAC. Re-stamping is best-effort: if
the key or the write fails, the still-valid schema-1 record remains and the
verification is no weaker than before the migration existed. The migration is
no weaker than the pre-remediation state, where every record was unauthenticated.

### 2.2 Record-field validation

`ValidateOldLauncherRecordText` validates, in order: schema ∈ {1, 2};
`sha256` exactly 64 hex characters (`IsValidSha256Hex`); `size` a non-negative
number ≤ 512 MiB; `version` a non-empty string; `time`/`recordedAt` (when
present) strict ISO-8601; `hmac` (schema 2) present and matching. Note: the
Delphi RTL defines `TJSONNumber` as a descendant of `TJSONString`, so every
string-field check explicitly rejects `TJSONNumber` — a plain `is TJSONString`
would accept numeric values.

Consistency checks bind the record to the artifact: recorded size and SHA-256
must match `Launcher.exe.old`, and when the `.old` binary carries a readable
version resource it must match the recorded `version` (files without a version
resource skip this check; documented limitation).

## 3. Time-of-check/time-of-use (TOCTOU) closure

Pre-remediation, `VerifyOldLauncher` hashed `Launcher.exe.old` through an
open-and-close stream, and the rollback rename happened afterwards — a
concurrent replacement between the two steps would be moved into place
unverified. The remediation closes the gap:

`OpenVerifiedOldLauncher` (Portappix.Update.pas):
1. path-level reparse-point refusal (unchanged semantics/messages);
2. opens `Launcher.exe.old` with `CreateFile(GENERIC_READ,
   FILE_SHARE_READ | FILE_SHARE_DELETE)` — **write access is not shared**, so a
   concurrent replacement attempt fails with `ERROR_SHARING_VIOLATION` for the
   entire verify-to-move window;
3. opens with `FILE_FLAG_OPEN_REPARSE_POINT` so a junction is not silently
   followed; a reparse point at the handle is detected via
   `GetFileInformationByHandle` attributes and refused;
4. size and SHA-256 are computed **through the still-open handle**
   (`Sha256Handle`), so what is verified is exactly what is moved;
5. `RollbackToOldLauncher` renames the verified file with the handle still
   open (`FILE_SHARE_DELETE` permits the rename) and closes it only
   afterwards; every failure inside the verification releases the handle
   immediately.

A rollback attempt against an externally locked `.old` refuses closed and
leaves both executables untouched. Residual window: after the rename
completes, the restored `Launcher.exe` is subject to the same post-move risks
as any executable on disk; the `.failed_*` copy of the displaced build is kept
for forensics.

## 4. Self-update transaction (all-or-nothing swap)

`PrepareUpdate` is a transaction with checked restore:

1. **Backup phase (no mutation yet):** replaced root files, the previous
   rollback record, `update_ok`, and any pre-existing `update_pending.json`
   are copied into `Cache\launcher_rollback_<timestamp>\`; the pre-swap
   SHA-256 of the launcher is persisted there too.
2. **Mutation phase:** durable write of the new `update_pending.json`;
   `RecordOldLauncher` for the launcher **before** any rename (a crash after
   the rename can no longer wedge rollback with a missing record);
   `Launcher.exe → Launcher.exe.old → new launcher` renames; release root
   files are moved into place.
3. **Failure restore:** `RestoreFailedSwap` reverses every completed mutation
   with *checked* operations (a failing restore raises instead of being
   silent), then verifies the post-restore invariant — the launcher exists and
   is byte-identical to the pre-swap hash — and the metadata invariants
   (previous record restored or absent, markers restored or absent). On a
   failed restore the backup directory is preserved for forensics.
4. **Crash windows:** a process crash at any point leaves either the fully
   swapped state with the watchdog armed (`update_ok` deleted), or the original
   state; the record-before-rename ordering removes the `.old`-without-record
   wedge.

All update-state metadata (`old_launcher.json`, `update_pending.json`,
`update_ok`, `launcher_version.json`) is now written with
`WriteTextFileDurable` (FlushFileBuffers before replace, directory flush
after).

## 5. Review metadata fail-closed semantics

`TPortappixJournal.ListReviewItems` raises `EPortappixStateError` when
`needs_review.json` is unreadable, malformed JSON, not an array, contains a
non-object entry, or an entry with missing/empty/non-string `appId`,
`junctionPath`, `target`, or non-string `time`/`reason`. Only a **missing**
file is the normal empty state. Consequences:

- `BeginTransaction` refuses to run an application while the review state is
  unreadable (fail closed — an app that may need review is never silently
  unblocked);
- `--status` reports `REVIEW STATE UNREADABLE` and exits with the
  needs-review contract instead of reporting "Clean";
- the GUI surfaces a warning instead of an empty list;
- `RecordReviewItem` raises when persistence fails (the junction is *not*
  recorded — the caller knows the app is not blocked yet), and `ClearReview`
  returns an error and keeps the entries when the rewrite cannot be
  persisted, including when the file deletion fails.

Review persistence uses `WriteTextFileDurable`.

## 6. Failure-injection seams (test builds only)

Deterministic failure injection follows the Phase 4A compile-time isolation
pattern: a new define `{$IFDEF PORTAPPIX_TESTINJECT}` gates

- `PortappixWriteHook` (Common.pas): per-call outcomes `whPass`, `whFail`,
  `whFailAfterTemp` (disk-full semantics: temp written and lost, target never
  replaced), `whRaiseAccessDenied`;
- `PortappixRenameHook` (Update.pas): rename calls fail with an injected Win32
  error code;
- `PortappixSpawnErrorCode` (Update.pas): injected launcher spawn failure;
- the marker constant `PortappixTestInjectMarker` =
  `PORTAPPIX-TESTINJECT-BUILD-2026-11-11`, materialized into the test binary
  and byte-scanned.

Production binaries contain no reference to any of these (verified by the
source scan and binary byte scans in
`tests/scripts/test_failure_injection_isolation.py`); `scripts/make_release.py`
refuses a staged launcher carrying the marker in either encoding. The
rollback-record key path override (`PortappixRecordKeyPathOverride`) is
similarly gated behind `{$IFDEF PORTAPPIX_TESTCRASH}` so unit tests never touch
the real `%LOCALAPPDATA%`.

## 7. Limitations

1. Same-user arbitrary code with key access defeats the record HMAC (§1.4) —
   documented residual risk, mitigated at OS/distribution layers.
2. The version-consistency check cannot run for launchers without a version
   resource (plain test fixtures); the record hash/size/HMAC checks still bind
   the record to the artifact.
3. The review fail-closed design intentionally *blocks* application launches
   when the review state is unreadable. Operators resolve by repairing or
   deleting `Transactions\needs_review.json` after inspection.
4. `WriteTextFileDurable` reduces but cannot eliminate power-loss windows
   (documented in the Phase 2 report); `FlushDirectoryWindows` is best-effort
   and not supported on every file system.
