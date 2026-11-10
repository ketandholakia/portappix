# Portappix — Phase 0 Security Inventory

Read-only inspection at HEAD `c4bce22`. No secrets are reproduced in this document.
Risk classification: **High** / **Medium** / **Low** / **Info**.
"Recommended phase" refers to the Portappix Security & Reliability Hardening Roadmap
(Phase 1 = next phase; numbers beyond that are indicative).

## A. Signing and key management

### Current state (verified)

| Aspect | Finding |
| --- | --- |
| Private-key location | `keys/catalog_signing_key.pem` (241 bytes, present on disk). **Not tracked by Git** — `git ls-files keys/` is empty; `.gitignore:27` ignores `keys/`. |
| Key in distribution artifacts | Present inside the root-local `portappix.zip` (see PH0-SEC-01). **Not** present in `dist\*.package.zip` or any other artifact checked. |
| Public-key embedding | `src/Portappix.Signature.pas:15-17`, constant `CatalogPublicKeyHex` — an ECCPUBLICBLOB-format P-256 **public** key (magic `ECS1` + 32-byte key length header). Public material only; no private data in source. |
| Algorithm | ECDSA P-256 (SECP256R1). Signature = raw 64-byte `r||s` over SHA-256 of the exact file bytes (`sign_catalog.py:41-45`; `Portappix.Signature.pas:68-109` verifies via CNG `BCryptVerifySignature`). |
| Key generation workflow | Not scripted in the repo (Python `cryptography` assumed; `sign_catalog.py` only loads). `Portappix.Consent`, catalog, and releases all reuse the same key. |
| Signing workflow | `scripts/sign_catalog.py --catalog … --key keys/catalog_signing_key.pem` (also used by `make_release.py` and `tools/build_catalog.py` via import). |
| Catalog verification workflow | `TPortappixCatalog.LoadFromFile/LoadFromUrl` require a valid signature or the dev-only `AllowUnsignedCatalogs` flag (`Portappix.Catalog.pas:72,333-343,375-381`); `TPortappix.Update.DownloadReleases` requires a signature unconditionally (`Portappix.Update.pas:256-278`). |

### Findings

**PH0-SEC-01 — Private signing key and full Git history inside a distribution zip** — Risk: **High**
- File: `portappix.zip` (repository root, 10,801,195 bytes, 632 entries, git-ignored local artifact).
- Evidence: zip entry listing contains `keys/` and `keys/catalog_signing_key.pem`, plus `.git/`,
  `__history/`, `bin/`, `dist/`, and all sources — the archive is a full snapshot of the repository
  including the private key and the entire Git object database.
- Method: entry-name inspection only; key contents were never read or printed.
- Risk: any distribution of this file (it sits at a very "shippable" path and predates
  `scripts/make_release.py`, which packages only a staging folder) leaks the catalog/release signing
  key: an attacker could sign hostile catalogs/releases that every existing launcher accepts, and
  `.git/` exposure reveals unpushed history.
- Recommended remediation: **Phase 1, first item** — treat the current key as compromised when this
  zip has ever left the machine: rotate to a new P-256 key pair, update `CatalogPublicKeyHex`,
  re-sign the catalog; delete/rebuild `portappix.zip`; add a packaging guard that refuses to zip
  `keys/` or `.git/`.

**PH0-SEC-02 — Host state is mutated before journal persistence** — Risk: **Medium**
- File: `src/Portappix.Runner.pas` — `TPortableAppRunner.Run`.
- Evidence: order of operations — `CreateJunctions` / `BackupHostRegistryKeys` /
  `DeleteHostRegistryKeys` / `ImportPortableRegistry` at `Runner.pas:407-410`, then
  `FJournal.AddActiveApp(...)` at `Runner.pas:425-431`. A hard crash (power loss, `TerminateProcess`)
  in that window leaves junctions, `_host_backup` directory renames and hijacked HKCU keys **not
  recorded** in `run_state.json`.
- Mitigations already present: relaunch is fail-safe (`CreateJunctions` refuses when `_host_backup`
  exists, `Runner.pas:544-547`; `BackupHostRegistryKeys` refuses when `host_backup_<n>.reg` exists,
  `Runner.pas:869-872`); `RecoverPendingCleanups` restores scanned backups — but only for apps that
  *have* a journal entry (`State.pas:392-429`). An unjournaled crash strand requires manual repair.
- Recommended remediation: **Phase 1** — write a journal *intent* record before the first host
  mutation (or add a scan-based recovery that repairs `_host_backup`/`host_backup_*.reg` orphans for
  apps absent from the journal).

**PH0-SEC-03 — Recovery trusts `dataDir` from the plaintext journal** — Risk: **Medium** (same-user
local attack; escalates if the launcher runs elevated)
- File: `src/Portappix.State.pas` (`ResolveDataDir`, `:229-251`) and
  `src/Portappix.Runner.pas` (`PerformCleanup`, `:913-940`).
- Evidence: `RecoverPendingCleanups` resolves `apps.<id>.dataDir` from `run_state.json` and, if
  absolute, uses it verbatim for `RestoreBackupsWithOps` (`reg.exe import` of
  `<dataDir>\host_backup_*.reg`) and `RemoveJunctionsWithLog`. A tampered journal (any process of the
  same user can rewrite the plaintext file) causes `reg.exe import` of an attacker-chosen `.reg` file
  and reparse-point removal at attacker-chosen recorded junction paths on the next recovery.
- Constraints: junction deletion only touches mount-point reparse points; `reg.exe` imports execute
  with the launcher's privileges (HKLM writes possible when elevated).
- Recommended remediation: **Phase 1/2** — validate that the journal `dataDir` is under
  `<root>\Data\<id>` (the `dataDir` is redundant — it is derivable from the safe app id), or
  authenticate/integrity-check `run_state.json`.

**PH0-SEC-04 — ZIP extraction hardening gaps** — Risk: **Medium** (blocked in the primary catalog
path by SHA-256 pinning; relevant for self-update/test flows)
- File: `src/Portappix.PackageManager.pas` — `ExtractArchive`, `:223-276`.
- Evidence and gaps:
  1. **Declared-size bomb window**: the 2 GiB cap sums `Zip.FileInfo[Index].UncompressedSize`
     *declared in zip headers* (`:246-251`). A lying header passes the check; `TZipFile.Extract`
     then writes whatever the stream actually decodes, unbounded. Actual extracted bytes are not
     counted.
  2. **Alternate data streams**: entry names containing `:` (e.g. `file.dll:ads`) are not rejected —
     `IsZipSlip` keeps them under the base dir, and stream creation would attach an ADS to an
     existing file.
  3. **Duplicate / case-insensitive collisions**: two entries differing only by case (or exact
     duplicates) overwrite each other silently (last wins) — no detection, unlike the catalog
     id checks.
  4. **Reparse-point extraction**: `System.Zip` cannot materialize reparse-point entries, so no
     junction/symlink escape exists via this path (recorded as verified-by-absence; no custom
     handling present).
- Mitigations present: `IsZipSlip` on every entry (`:256,263`), rooted/UNC entry names fall out of
  the base-prefix check, 20,000-entry cap, app.json-at-root + id-match + full policy re-validation
  after extraction (`:326-357`), SHA-256+size pinning of catalog packages, and the identical
  extractor is reused for launcher self-update zips.
- Recommended remediation: **Phase 2** — count bytes actually written during extraction, reject
  entry names containing `:`, reject duplicate/case-colliding entry names.

**PH0-SEC-05 — Catalog licensing: provenance pinned, licensing not recorded** — Risk: **Medium**
(policy/legal, not runtime)
- Files: `recipe.schema.json`, `recipes/*.json` (25), `recipes/README.md`, `recipes/SKIPPED.md`.
- Evidence: recipes pin `source.url` (https), `source.sha256`, `source.size`, and
  `source.hashSource` (provenance of the hash); `recipe.schema.json` has **no** license,
  redistribution-permission, or EULA field. `recipes/SKIPPED.md` documents an explicit policy of
  vendor URLs only (no third-party repacks such as PortableApps.com; no `.7z`-only vendors;
  installer-only apps excluded) — a licensing *decision log*, but not machine-readable.
- Classification of the 25 pinned recipes (informational, per `recipes/README.md` + vendor pages):
  - 18 × Sysinternals tools (accesschk, adexplorer, autologon, autoruns, bginfo, desktops, handle,
    procmon, processexplorer, pstools, rammap, sdelete, sigcheck, strings, tcpview, vmmap, winobj,
    zoomit) — Microsoft freeware under the Sysinternals Software License Terms (EULA-gated, no
    explicit redistribution grant; recipes correctly ship no binaries and pin the live-download
    hash; `version` = pin date).
  - 1 × voidtools Everything — freeware (closed source, no-charge; redistribution terms not stated
    in-repo).
  - 5 × open source: fastfetch (open source, permissive), PowerShell 7 (MIT), KeePassXC (GPL-3.0),
    MPC-HC (GPL-3.0), Telegram Desktop (GPL-3.0), x64dbg (GPL-3.0) — licenses permit redistribution,
    but the pinned artifact is always the *vendor* build.
  - No recipe embeds vendor binaries (verified: recipes are JSON metadata only; built packages land
    in git-ignored `dist/`).
- Official download provenance: all 25 `source.url` values are https vendor URLs (GitHub releases
  for fastfetch/keepassxc/telegram/x64dbg/powershell; voidtools.com; download.sysinternals.com per
  roster notes). `hashSource` records where each pin came from ("computed from the vendor download on
  2026-11-09" or a vendor checksum page, e.g. Everything).
- Recommended remediation: **Phase 2/3** — add optional `license`/`eula` metadata to
  `recipe.schema.json`, record Sysinternals EULA-acceptance handling for first run, and decide
  policy for redistributing *cached vendor packages* (`dist/` is git-ignored today — keep it that
  way or document terms).

### Signing — positive controls verified (Info)

- Private key untracked by Git and excluded from `dist\*` package zips (entry listings checked).
- Signature is mandatory at all consumption points except the two explicit dev/test switches
  (`AllowUnsignedCatalogs`, and http-URL-only relaxation via `--allow-insecure-release-urls`; the
  latter never skips signature verification, `Portappix.Update.pas:271-275`).
- Verification failure messages do not echo key material; failures delete the rejected package
  (`PackageManager.pas:202-208`, `Update.pas:428-446`).
- Root `catalog.json` is an empty stub (`{"apps": []}`) with a 64-byte signature — a signed but
  empty catalog; the populated catalog pipeline exists in `tools/` only.

## B. Registry/journal recovery (transaction ordering)

Covered in PH0-SEC-02/03. Additional verified controls:

- **Export-before-delete invariant** holds on all three paths: normal run
  (`Runner.pas:803-828` — host keys deleted only if the portable export succeeded), crash recovery
  (`PerformCleanup`, `Runner.pas:928-936` — same condition), and the suite asserts it
  (`tests/suite/run_suite.ps1:457-461`).
- Backups refuse to be silently overwritten: pre-existing `host_backup_<n>.reg` or `<host>_host_backup`
  aborts the run before any host key is deleted (`Runner.pas:544-547,869-872`).
- `RecoverPendingCleanups` skips running apps (per-app mutex **or** process-path scan,
  `State.pas:399-403`) and keeps journal entries whose backups could not be restored (`:424-429`).
- Journal writes are critical-section-guarded and atomic (`State.pas:163-168`,
  `Portappix.Common.pas:325-343`); corrupt journals are quarantined to `run_state.json.bad`
  (`State.pas:145-156`).
- Registry ops use `reg.exe` resolved from `GetWindowsDirectory\System32` — immune to `PATH` hijack
  (`Portappix.Registry.pas:48-56`).

## C. Junctions

- `CreateJunction`/`DeleteJunction` use direct `FSCTL_SET/DELETE_REPARSE_POINT` with
  `IO_REPARSE_TAG_MOUNT_POINT` (`Portappix.Junction.pas:52-133`); `cmd.exe` never sees the paths, so
  `%` expansion cannot mangle them.
- **Target preservation**: `DeleteJunction` removes only the reparse point (non-recursive) then
  `RemoveDir`; it cannot recurse into the target. `RemoveJunctionsWithLog` additionally checks
  `IsReparsePoint` before deleting and restores `<host>_host_backup` **only when the host path is
  gone and the backup is not itself a reparse point** (`Runner.pas:285-322`).
- **Existing directory backup/restore**: real host directories are renamed (not copied) to
  `<host>_host_backup` before junction creation and renamed back after; a pre-existing backup aborts
  with an error rather than overwriting (`Runner.pas:544-571`).
- Policy containment (defense in depth before any of the above): host paths must resolve inside
  `%APPDATA%`/`%LOCALAPPDATA%`/`%PROGRAMDATA%` (strictly below the root) or `%USERPROFILE%\.<name>`;
  tokens and `..\` in host paths rejected; targets must be relative or token-bearing and traverse
  nowhere (`Portappix.Policy.pas:179-288`). The Python validator mirrors the same rules
  (`scripts/validate_catalog.py` `validate_junction_host/target`), so CI rejects recipes the
  launcher would reject.
- Residual (Low): the `..\` traversal checks are textual substring tests
  (`Policy.pas:204,275-276`); a trailing `..\..` without a following separator is not matched, but
  the final location checks (`IsPathUnder` against expanded environment roots) still gate acceptance,
  so no exploit path was identified. Also Low: `ValidateJunctionHost` expands `%VAR%` from the
  **host** environment at validation time — a different environment at run time could resolve a
  host path elsewhere; not exploitable through catalog recipes (CI lint pins the same text) and
  requires a hand-edited local manifest (user-own risk).
- W1002 (`FILE_FLAG_OPEN_REPARSE_POINT` platform-specific, `Junction.pas:49`) — cosmetic, known
  per RELEASE_CHECKLIST step 1.

## D. ZIP extraction

Covered in PH0-SEC-04. Additional verified controls: destination wiped before extraction
(`:231-233`); directory entries also pass `IsZipSlip` (`:254-261`); path separators normalized from
`/` to `\` before checks (`:253`); extraction to `Apps\<id>.new` keeps host installs atomic even if
extraction dies mid-way. Catalog validator applies equivalent rules in Python
(`validate_zip_entry_name`, `MAX_ENTRIES`, `MAX_UNCOMPRESSED_BYTES`) — the two implementations must
be kept in sync (Info; drift risk noted for Phase 2).

## E. Environment and process surface (supplementary)

- Environment overrides are allow-listed (15 variables) and path-like overrides must reference
  `{app}`/`{data}` so the host `PATH` is never inherited wholesale (`Portappix.Policy.pas:290-333`);
  the suite's `bad-env-path-hijack` case asserts rejection (`run_suite.ps1:481-490`).
- Elevated launches are refused, not silently started (`EPortappixElevationRequired`, exit 740,
  `Runner.pas:729-734`) — elevated processes cannot inherit the redirected environment.
- Process-tree containment relies on job objects; processes that break away are not tracked
  (documented limitation, `README.md` "Notes and limitations") — Info.

## F. Finding index

| ID | Area | Risk | Location | Remediation phase |
| --- | --- | --- | --- | --- |
| PH0-SEC-01 | Signing key in `portappix.zip` (+ `.git/`) | High | `portappix.zip` (root, ignored) | 1 — rotate key, purge artifact, guard packager |
| PH0-SEC-02 | Host mutation precedes `AddActiveApp` | Medium | `src/Portappix.Runner.pas:407-431` | 1 — journal intent before mutation / orphan scan |
| PH0-SEC-03 | Journal `dataDir` trusted for cleanup | Medium | `src/Portappix.State.pas:229-251` | 1–2 — validate against `<root>\Data\<id>` |
| PH0-SEC-04 | Zip: declared-size cap, ADS, duplicate/case collisions | Medium | `src/Portappix.PackageManager.pas:223-276` | 2 — actual-bytes cap, reject `:` and duplicates |
| PH0-SEC-05 | No machine-readable license/redistribution metadata | Medium | `recipe.schema.json`, `recipes/` | 2–3 — schema fields + EULA policy |
| PH0-SEC-06 | `AllowUnsignedCatalogs` global dev switch | Low | `src/Portappix.Catalog.pas:72` (UI sets only `False`, `MainForm.pas:137`) | 2 — compile-time/test-only gating |
| PH0-SEC-07 | Unbounded in-memory catalog/release download | Low | `src/Portappix.Catalog.pas:97-132` | 2 — size cap |
| PH0-SEC-08 | Textual `..\` checks in policy | Low | `src/Portappix.Policy.pas:204,275-276` | 2 — normalize-then-compare |
| PH0-SEC-09 | `RunHiddenProcess` waits INFINITE (hung `reg.exe` stalls cleanup) | Low | `src/Portappix.Process.pas:111-154` | 2 — timeout + retry policy |
| PH0-SEC-10 | Policy mirror drift risk (Delphi vs Python validator) | Info | `scripts/validate_catalog.py` vs `Portappix.Policy.pas` | 2 — golden-vector tests |
| PH0-SEC-11 | W1002 platform warning | Info | `src/Portappix.Junction.pas:49` | accepted (documented) |
