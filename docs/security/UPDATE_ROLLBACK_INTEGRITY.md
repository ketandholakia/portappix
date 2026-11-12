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
   the launcher's user that can read
   `%LOCALAPPDATA%\Portappix\keys\<installation-id>\rollback_key.bin`
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
  **installation** on first use, wrapped with DPAPI (`CryptProtectData`, user
  scope, `CRYPTPROTECT_UI_FORBIDDEN`) and stored at
  `%LOCALAPPDATA%\Portappix\keys\<installation-id>\rollback_key.bin`, where
  `<installation-id>` is the SHA-256 of the canonical installation root path
  (R19). The user-profile ACL (user-only by default on NTFS) plus DPAPI user
  scoping mean the key blob is bound to the user account that created it; the
  per-installation subdirectory additionally binds it to one installation, so
  two installations under the same account never share key material. The
  canonicalization resolves the full path, strips a `\\?\` prefix, drops any
  trailing delimiter, normalizes separators and lowercases, so spelling
  variants of one installation resolve to one key while genuinely different
  installations get different keys. The key file is created without wide
  sharing.
- **Legacy key migration (bounded):** launchers before R19 stored one unscoped
  key at `%LOCALAPPDATA%\Portappix\rollback_key.bin` shared by every
  installation under the account. On first use, an installation without a
  scoped key adopts (copies) that blob into its scoped location; the legacy
  file is left in place because other installations may still need to migrate
  from it. Adoption never invents key material, never overwrites an existing
  scoped key, and the verification path performs it without creating key
  material for an installation that had truly none.
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

### 4.1 Staging (`PrepareUpdate`)

`PrepareUpdate` performs **no mutation of the installation root**:

1. The package is verified (sha256 + size) and extracted into
   `Cache\launcher_new\` (same zip-slip and entry caps as apps).
2. A staging directory `Cache\launcher_rollback_<timestamp>\` receives:
   - `staged_files.json` — the package's non-launcher root-file names (the
     basis of the introduced-file list);
   - one **copy** of every package root file that already exists in the root
     (the "replaced" set);
   - copies of the previous `old_launcher.json`, `update_ok` and
     `update_pending.json` (with distinct prefixed names);
   - `rollback_pre_swap.json` — the pre-swap launcher SHA-256.
3. `update_ok` is removed (arms the watchdog), any superseded `.old` is
   removed, the schema-2 record for the **current** launcher is written, and
   `update_pending.json` (with the staging reference) is written durably.
4. A finalize helper (`launcher_new\Launcher.exe --finalize-update`) is
   spawned after this process exits.

A failure anywhere in staging runs `RestoreFailedSwap` and raises; the
installation is never left half-staged.

### 4.2 Finalizing (`FinalizePendingUpdate`)

```
        pending marker + staging dir
                    │
                    ▼
      ┌────── swap already completed? ──────┐
      │  (durable swap-done marker matches  │
      │   the installed hash, OR pre-swap   │
      │   hash inference)                   │
      │                                     │
     no ─────────────────────────────────► yes
      │                                     │
      ▼                                     ▼
 ReplaceFileW(Launcher.exe,           staging dir present?
   launcher_new\Launcher.exe,                │
   Launcher.exe.old)                  ┌──────┴──────┐
      │                              yes            no
      ▼                              │              │
 write update_swap_done.json         │              ▼
 (durable, R20)                      │      clean launcher_new,
      │                              │      return success (idempotent)
      ▼                              │
 move package root files ◄───────────┘
      │
      ▼
 PreserveCompanionBackups (R16)
      │
      ▼
 delete launcher_new; clear swap marker at confirmation
```

Key invariants:

- **`Launcher.exe` is never missing.** The transition is a single
  `ReplaceFileW` with backup; there is no window in which the executable does
  not exist (test: `TestLauncherNeverMissingDuringSwap`).
- **The helper never installs from its own image (R21).** The helper runs as
  `launcher_new\Launcher.exe`, and Windows refuses to use the caller's mapped
  image as a `ReplaceFileW` source (`ERROR_SHARING_VIOLATION`). The helper
  therefore installs from a private copy (`launcher_new\install_<pid>.exe`),
  which it consumes, and removes the copy if the swap fails.
- **Every step is idempotent on resume**, including after the staged source
  binary was consumed by `ReplaceFileW` (R20). The durable
  `Cache\update_swap_done.json` records the installed hash immediately after
  the swap; it is honoured only while the installed launcher still matches it.
- **Failure restores are checked and verified.** `RestoreFailedSwap` reverses
  every completed mutation with raising operations, deletes the swap marker,
  then verifies the launcher is byte-identical to `rollback_pre_swap.json` and
  that the metadata invariants hold. A failed restore preserves every backup
  and raises (never a silent partial rollback).
- **Companion backups are never destroyed by a failed operation (R15/R16).**
  Backups move into a FRESH `Cache\companion_rollback_staging\` with per-file
  SHA-256 verification, union-merged with the previous companion directory,
  and only then is the previous directory replaced. Any failure moves every
  transferred file back to the staging directory; only a fully drained
  transfer directory is deleted. The companion manifest
  (`companion_manifest.json`, schema 1) records the replaced files with their
  verified hashes and the files the update introduced.

### 4.3 Recovery states

| State on disk | Meaning | Next finalize |
|---|---|---|
| pending + staging + `launcher_new\Launcher.exe` | staged, not swapped | swap normally |
| pending + staging + swap-done marker | swapped, post-swap steps pending | skip swap, continue |
| pending + no staging + swap-done marker | all steps ran; cleanup interrupted | finish cleanup, success |
| pending + no staging + no marker | staging destroyed externally | error, manual inspection |
| no pending | confirmed or never staged | `ConfirmUpdate`/rollback |

`UnfinalizedPendingUpdate` (the recovery respawn condition) excludes the
completed-swap states, so recovery never respawns a helper that would
deterministically fail on a missing staged binary.

### 4.4 Rollback (`RollbackToOldLauncher`)

1. The `.old` file is opened with a write-denying handle and verified
   (reparse-point rejection, size, sha256, authenticated schema-2 record).
2. The running launcher is renamed aside (`Launcher.exe.failed_<stamp>`), and
   the verified `.old` is renamed into place **through the still-open handle**
   (`FileRenameInfo`, R10/R18) — what was verified is what is installed.
3. Companion files: every "replaced" backup is restored and every
   manifest-recorded "introduced" file is deleted. The companion directory is
   removed **only if every restore and deletion succeeded** (R15); otherwise
   it is kept intact with its manifest so the rollback can be retried. An
   unsafe manifest entry drops the whole introduced list (fail-closed).
4. The swap marker, pending marker, `update_ok` and previous record are
   removed; `launcher_version.json` is restored.

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
- `PortappixFileMoveHook`, `PortappixFileDeleteHook`,
  `PortappixDirectoryDeleteHook` (Update.pas): injected failures for the
  companion-backup transfer, companion restore and introduced-file deletion
  paths (R15/R16);
- `PortappixUpdateCrashPoint` / `PortappixUpdateCrashKill` (Update.pas): armed
  finalize checkpoints, including the R20 resume matrix
  (`finalize:before-swap`, `finalize:after-swap`,
  `finalize:after-root-files`, `finalize:after-preserve-companions`,
  `finalize:after-newdir-delete`);
- `PortappixKeyCreateDelayMs` (RecordAuth.pas): widened first-creation window;
- the marker constant `PortappixTestInjectMarker` =
  `PORTAPPIX-TESTINJECT-BUILD-2026-11-11`, materialized into the test binary
  and byte-scanned.

Production binaries contain no reference to any of these (verified by the
source scan and binary byte scans in
`tests/scripts/test_failure_injection_isolation.py`); `scripts/make_release.py`
refuses a staged launcher carrying the marker in either encoding. The
rollback-record key path overrides (`PortappixRecordKeyPathOverride`,
`PortappixKeyRootOverride`) are similarly gated behind
`{$IFDEF PORTAPPIX_TESTCRASH}` so unit tests never touch the real
`%LOCALAPPDATA%`.

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
5. Handle-based renames (`RenameByHandle`) support long Windows paths
   (> `MAX_PATH`) with valid components, but a single path component longer
   than the NTFS limit (255 characters) is rejected by the OS with
   `ERROR_INVALID_NAME`; the rollback then fails cleanly without destroying
   anything (R18).
6. The staging and companion directories can be left on disk after an
   unrecoverable interruption; they are preserved deliberately (they may hold
   the only rollback copies) and are consumed by the next successful
   finalize/rollback or by operator cleanup after inspection.
7. Companion metadata (the manifest) is fail-closed for the introduced-file
   list only: a missing or corrupt manifest never blocks the launcher rollback;
   it merely means the introduced files cannot be identified and are left in
   place.
8. Legacy unscoped-key adoption (R19) means that on a machine where several
   installations were created before R19, each of them copies the same legacy
   key on first use. That preserves compatibility for existing records, but
   those pre-existing installations remain mutually linked by that historical
   key; only installations that create a fresh key (the normal case after
   upgrade) are fully independent.
