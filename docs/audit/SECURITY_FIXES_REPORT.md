# Portappix — Security Fixes Audit Report

**Date:** 2026-11-11  
**Repository:** Portappix (Delphi 12, VCL/Win32, RTL only)  
**Status:** IMPLEMENTED AND FULLY VERIFIED on development workstation  
**Windows Sandbox gates:** NOT RUN (pending for the user)  
**Signing Key Integrity:** No private keys were created, committed, packaged, or printed. `catalog.json` and `catalog.json.sig` remain byte-identical.

---

## Executive Summary

Three security vulnerabilities identified during review were remediated, hardened, and verified with comprehensive automated tests:

1. **Issue 1:** `--allow-insecure-release-urls` existed in release builds and allowed plain HTTP release downloads.
2. **Issue 2:** Package zip extraction decompressed full entries into memory before running capacity checks, risking zip-bomb memory exhaustion.
3. **Issue 3:** `Cache\pending_updates.json` was an unsigned, trusted local file storing URLs and hashes, permitting update hijacking if written.

All three issues have been fixed without weakening existing checks.

---

## Issue 1: `--allow-insecure-release-urls` Exists in Release Builds

### Files Changed
- `src/Portappix.Cli.pas`
- `src/Portappix.Update.pas`
- `scripts/make_release.py`
- `tests/scripts/test_crash_hook_isolation.py`
- `tests/PortappixTests.dpr`

### Behaviour Before
- The CLI switch `--allow-insecure-release-urls` was unconditionally accepted in release builds, setting `AllowInsecureReleaseUrls := True`.
- `IsPermittedReleaseUrl` permitted plain `http://` release URLs whenever `AllowInsecureReleaseUrls` was true.
- `scripts/make_release.py` did not check production launcher binaries for the presence of the insecure URL switch string.

### Behaviour After
- Switch parsing in `Portappix.Cli.pas`, the `AllowInsecureReleaseUrls` variable in `Portappix.Update.pas`, and its check in `IsPermittedReleaseUrl` are wrapped inside `{$IFDEF PORTAPPIX_TESTUPDATE}`.
- In normal release builds:
  - The `AllowInsecureReleaseUrls` variable does not exist.
  - The switch `--allow-insecure-release-urls` is rejected as an unknown argument (`Cli.Parse` returns `False`).
  - All plain `http://` URLs (including loopback `127.0.0.1` and `localhost`) are strictly rejected; only `https://` URLs are permitted.
- In `PORTAPPIX_TESTUPDATE` test builds:
  - Only loopback `http://` (`127.0.0.1` and `localhost`) is accepted by default.
  - Non-loopback HTTP URLs, including crafted loopback prefixes like `http://127.0.0.1.evil.com/` and `http://localhost.evil.com/`, are rejected.
  - Passing `--allow-insecure-release-urls` explicitly enables non-loopback HTTP for local testing.
- `scripts/make_release.py` release staging guard was extended:
  - Any staged launcher containing the literal byte string `allow-insecure-release-urls` (in either UTF-8 or UTF-16LE encoding) is rejected, preventing release packaging.
- `tests/scripts/test_crash_hook_isolation.py`:
  - Enforces that production Win32 and Win64 launcher binaries contain no occurrences of `allow-insecure-release-urls`.
  - Verifies that `make_release.py` staging guard catches both UTF-8 and UTF-16LE occurrences of `allow-insecure-release-urls` and combined markers.

### Tests Added
- `TestReleaseUrlSecurity` in `tests/PortappixTests.dpr`:
  - **Normal build:** Verifies rejection of `http://127.0.0.1:8080/releases.json`, `http://localhost:8080/releases.json`, `http://example.com/releases.json`; acceptance of `https://example.com/releases.json`; rejection of `--allow-insecure-release-urls` switch as unknown argument.
  - **`PORTAPPIX_TESTUPDATE` build:** Verifies acceptance of loopback `127.0.0.1` and `localhost` with ports and paths; rejection of `http://127.0.0.1.evil.com/`, `http://localhost.evil.com/`, `http://example.com/`; parsing of `--allow-insecure-release-urls` and subsequent non-loopback HTTP allowance.
- `tests/scripts/test_crash_hook_isolation.py`:
  - Inspection of production Win32 and Win64 binaries for `allow-insecure-release-urls`.
  - Synthetic test cases verifying staging guard rejection on `allow-insecure-release-urls` in UTF-8 and UTF-16LE.

### Anything Not Done
- None.

---

## Issue 2: Zip-Bomb Memory Exhaustion in Package Extraction

### Files Changed
- `src/Portappix.PackageManager.pas`
- `tests/PortappixTests.dpr`

### Behaviour Before
- `TPortappixPackageManager.ExtractArchive` called `Zip.Read(Index, EntryStream, LocalHeader)`, which decompressed each entry into memory in its entirety before checking cumulative uncompressed bytes against `MaxZipUncompressedBytes`.
- A small archive expanding to gigabytes could exhaust process memory before any byte checks ran.
- There was no per-entry size cap.
- Actual written bytes were not cross-checked against declared `UncompressedSize`.
- On abort or extraction failure, partially written files could remain on disk.

### Behaviour After
- Added `MaxZipEntryBytes = Int64(512) * 1024 * 1024` (512 MB per-entry cap, below `MaxZipUncompressedBytes = 2 GB`).
- Added properties `MaxZipEntryBytesCap` and `MaxZipUncompressedBytesCap` for test configurability.
- Pre-read declared size validation:
  - Before decompressing or reading any bytes, each entry's declared `Header.UncompressedSize` is checked.
  - If `Header.UncompressedSize > FMaxZipEntryBytes` or `Header.UncompressedSize < 0`, extraction fails immediately with `EPortappixPackageError`.
- Streaming chunked extraction:
  - Decompresses and writes in 64 KB chunks (`Buffer: array[0..65535] of Byte`).
  - Maintains running `EntryBytesWritten` and `TotalActualBytes` counters.
  - Aborts immediately as soon as `EntryBytesWritten > FMaxZipEntryBytes` or `TotalActualBytes > FMaxZipUncompressedBytes`.
  - On abort, deletes the partially written file immediately.
- Cross-check declared vs actual size:
  - Verifies `EntryBytesWritten = Header.UncompressedSize`. Any discrepancy aborts with corrupt package error.
- Destination cleanup on failure:
  - The extraction loop is wrapped in `try..except DeleteDirectoryQuiet(ADestinationDir); raise; end;`.
  - On any failure or abort, the destination directory is deleted, ensuring no half-extracted applications remain.
  - Existing zip-slip, Alternate Data Stream (`:`), Windows device name, and duplicate/case-collision checks are fully preserved.
- Launcher update extraction:
  - `TPortappixUpdateManager.ExtractLauncherZip` delegates directly to `TPortappixPackageManager.Create(FRootPath).ExtractArchive(...)`, inheriting the same protections.

### Tests Added
- `TestZipBombAndHardening` in `tests/PortappixTests.dpr`:
  - Entry declaring size exceeding cap is rejected before any bytes are read.
  - Over-cap entry leaves no destination directory or partial files.
  - Entry whose declared size lies (small declared size, actual data exceeding cap) is aborted during streaming as soon as the cap is reached.
  - Aborted streaming leaves no destination directory or partial files.
  - Total cap (`MaxZipUncompressedBytes`) enforced across multiple small entries.
  - Total cap abort leaves no destination directory or partial files.
  - Mismatch between actual bytes written and declared size is caught and rejected as corrupt package.
  - Corrupt size mismatch leaves no partial files.

### Anything Not Done
- None.

---

## Issue 3: `Cache\pending_updates.json` Unsigned and Trusted

### Files Changed
- `src/Portappix.PackageManager.pas`
- `tests/PortappixTests.dpr`

### Behaviour Before
- `LoadPendingUpdates` and `ApplyPendingUpdates` read `url`, `sha256`, and `size` directly from `Cache\pending_updates.json`.
- The file was unsigned and local; anyone who could write to `Cache\` (or an erroneous local write) could inject malicious download URLs and hashes.
- Malformed or oversized files were not explicitly bounded.
- The file was written without atomic replacement.

### Behaviour After
- Redesigned `pending_updates.json` to schema 2:
  - Stores only `id` and `version` as operational hints.
  - Does NOT store `url`, `sha256`, `size`, or `kind`.
- Verified Catalog Lookup at Apply Time:
  - `ApplyPendingUpdates` loads the catalog from `catalog.json` and verifies its signature via CNG (`Catalog.SignatureVerified`).
  - If the catalog cannot be verified, `ApplyPendingUpdates` logs the failure, aborts immediately, applies nothing, and preserves the pending queue intact.
  - For each queued entry, looks up the app in the verified catalog via `Catalog.FindById(Def.Id)`.
  - All update metadata (`Url`, `Sha256`, `Size`, `Kind`, `Recipe`, `StripPrefix`, `ManifestOverlay`, `ExePath`) is taken exclusively from the verified catalog entry.
  - Any URL, hash, or size present in `pending_updates.json` is completely ignored.
- Queue filtering & downgrade protection:
  - Entries whose `id` is missing from the catalog are logged and dropped from the queue.
  - Entries whose catalog version is no newer than the installed version (`TPortappixSemVer.Compare <= 0`) are logged as skipped and dropped.
  - Existing downgrade protection in `ValidateUpdateAllowed` remains active.
- File integrity & atomic writes:
  - Bound by `MaxPendingUpdatesBytes = 64 * 1024` (64 KB). Oversized files are treated as empty.
  - Malformed JSON is treated as empty queue without crashing.
  - Writes use `WriteTextFileAtomic` (temporary file + atomic file replace).
- Schema Migration:
  - When loading `pending_updates.json`, if `schema < 2` or untrusted fields are detected, it reads only the app `id`s, ignores all other fields, and immediately rewrites the file in schema 2 format atomically.

### Tests Added
- `TestPendingUpdatesSecurity` in `tests/PortappixTests.dpr`:
  - Malformed `pending_updates.json` is treated as empty queue.
  - Oversized `pending_updates.json` (> 64 KB) is treated as empty queue.
  - Old schema 1 format migrates to schema 2, preserves app IDs, and drops attacker URLs and hashes.
  - Unverifiable catalog (missing `.sig` file) preserves the pending updates queue and applies nothing.
  - Unknown app IDs not present in the catalog are dropped during apply.
  - Queued updates where catalog version is no newer than installed version are skipped and dropped.
  - File specifying attacker URL and attacker SHA-256 still results in verified catalog URL and catalog SHA-256 being used.

### Anything Not Done
- None.

---

## Documentation Updates

1. **`docs/security/SIGNING_KEY_MANAGEMENT.md` (§6):**
   - Corrected signature verification description to specify that `releases.json` has unconditional signature verification with no developer flags or bypasses, and that `catalog.json` signature verification is enforced by default with an internal `AllowUnsignedCatalogs` developer flag for development/test harnesses only. Documented that `ApplyPendingUpdates` strictly enforces `Catalog.SignatureVerified`.
2. **`docs/audit/phase-4/PHASE_4A_REPORT.md` (§15):**
   - Added Section 15 documenting the three security hardening fixes.

---

## Verification Results Summary

| Suite / Verifier | Command | Result |
|---|---|---|
| Delphi Win32 Engine Tests (Test Defines) | `tests\PortappixTests.exe` (with `PORTAPPIX_TESTCRASH;PORTAPPIX_TESTUPDATE`) | **610 passed, 0 failed** |
| Delphi Win32 Engine Tests (Release Configuration) | `tests\PortappixTests.exe` (without `PORTAPPIX_TESTUPDATE`) | **598 passed, 0 failed** |
| Crash Hook & Binary Isolation | `python tests\scripts\test_crash_hook_isolation.py` | **47 passed, 0 failed** (+ 30 signing = 77) |
| Icon Artwork & Conversion | `python tests\scripts\test_icons.py` | **76 passed, 0 failed** |
| Signing Workflow & Package Guard | `python tests\scripts\test_signing_workflow.py` | **30 passed, 0 failed** |
| Catalog Integrity Validation | `python scripts\validate_catalog.py` | Verified (see task log) |
| Release Staging Guard on Real Exes | `make_release.py` on fresh `%TEMP%\p4a-prod-*` and `p4a-test-*` | **Production accepted (0 findings), Test rejected (3 findings)** |
| Windows Sandbox Gates | Crash harness, compatibility suite, two-update self-update | **NOT RUN** (pending for user) |
| Signing Key & Catalog Integrity | `git status`, SHA-256 cross-check | **Byte-identical** (`catalog.json` / `catalog.json.sig`), no keys committed |
