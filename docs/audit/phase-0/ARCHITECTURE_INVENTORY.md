# Portappix — Phase 0 Architecture Inventory

All statements below were verified by reading the current source at HEAD
`c4bce22`. Line references are to the files as of that commit.

## 1. Source unit responsibilities and dependencies

### Entry point

**`src/Launcher.dpr`** (51 lines) — program entry.
- If `HasCliArguments` (first param starts with `--`, `Portappix.Cli.pas:934-937`) →
  `Halt(ExecuteCli)`: headless mode never creates forms and never takes the launcher mutex.
- Otherwise acquires `TPortappixSingleInstance` (mutex name = `Local\Portappix.Launcher.<sha256-24 of root path>`),
  shows `MessageBox` and exits 0 if another launcher owns it, then creates `TMainLauncherForm`.
- `uses` list defines the full unit set; the `.dpr` references no `.res` file.

### Common / infrastructure

| Unit | Responsibility | Depends on |
| --- | --- | --- |
| `src/Portappix.Common.pas` | Path helpers (`IsRelativePath`, `ResolveRootPath`, `ResolveFromRoot`, `IsPathUnder`), token expansion (`{root}`,`{app}`,`{data}`,`{id}`, `%VAR%`), `IsSafeFileComponent` (rejects `\/:*?"<>\|`, control chars, `.`/`..`), `IsZipSlip`, SHA-256 (via `System.Hash`), named mutexes (launcher + per-app, `Local\` namespace), `WriteTextFileAtomic` (`.tmp` + `MoveFileEx(MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH)`), `IsTransientAppFolder` (`.new`/`.old`/`.prev`) | RTL only |
| `src/Portappix.Process.pas` | `TPortappixJob` (job object create/assign/query/`WaitForEmpty` poll loop, 100 ms), `RunHiddenProcess` (CREATE_NO_WINDOW, waits INFINITE), `IsProcessRunningUnderPath` (Toolhelp32 snapshot + `QueryFullProcessImageNameW`; refuses drive roots), `QuoteArgument` | Common |
| `src/Portappix.Junction.pas` | Raw `FSCTL_SET_REPARSE_POINT` / `FSCTL_DELETE_REPARSE_POINT` mount-point management: `IsReparsePoint` (attributes), `CreateJunction` (creates dir, writes `\??\` substitute name; removes dir on failure), `DeleteJunction` (removes reparse point **non-recursively**, then `RemoveDir`) | Common |
| `src/Portappix.Registry.pas` | `IPortappixRegistryOps` (`KeyExists`/`ExportKey`/`ImportFile`/`DeleteKey`) implemented by `TPortappixRegistryOps` shelling out to `reg.exe` resolved from `GetWindowsDirectory\System32` (never from `PATH`); `ParseRegistryPath`/`NormalizeRegistryPath` (rejects NUL, collapses `\\`); `MergeRegistryFiles` (text merge of UTF-16 `.reg` exports) | Common, Process |

### Policy and data model

| Unit | Responsibility | Depends on |
| --- | --- | --- |
| `src/Portappix.Manifest.pas` | `TPortappixManifest`: parse/validate `app.json` (schema ≤ 1, safe id, required `exe`, env/junction string maps, registry array, `dataVersion` ≥ 0); `ReadDataVersion`/`WriteDataVersion` (`Data\<id>\data_version.json`) | Common |
| `src/Portappix.Policy.pas` | `TPortappixPolicy.ValidateManifest` → `TPolicyResult`: registry paths must be `HKCU\Software\<vendor>\<app>` (≥ 3 components, vendor on deny-list rejected: Microsoft/Classes/Policies/Windows/Windows NT/CurrentVersion); junction hosts must be absolute, token-free, traversal-free, under `%APPDATA%`/`%LOCALAPPDATA%`/`%PROGRAMDATA%` (strictly below) or `%USERPROFILE%\.<name>`, with protected-component deny-list; junction targets must be relative or token-bearing; env keys allow-listed (15 names), `PATH`/`PATHEXT` must reference `{app}`/`{data}` | Common, Manifest, Registry |
| `src/Portappix.Consent.pas` | `TPortappixConsent`: first-run approval per app id, stored as `Data\<id>\policy_consent.json` with `manifestHash` = SHA-256 of the exact `app.json` file; apps with zero registry/junction/env surface need no consent | Common, Manifest, Policy |
| `src/Portappix.Settings.pas` | `Cache\settings.json`: `updateUrl`, `autoCheckUpdates`, `autoApplyPendingUpdates`; tolerant load, atomic save | Common |
| `src/Portappix.Version.pas` | `TPortappixSemVer`: strict parse (1–3 numeric core, optional pre-release, ignored `+build`), semver 2.0.0 ordering | RTL only |

### Execution engine

| Unit | Responsibility | Depends on |
| --- | --- | --- |
| `src/Portappix.Runner.pas` | `TPortableAppRunner` — the execution engine (see §4). Declares `IPortappixJournal` (interface implemented by `Portappix.State`) | Common, Junction, Manifest, Policy, Process, Registry |
| `src/Portappix.State.pas` | `TPortappixJournal` (implements `IPortappixJournal`): crash journal at `<root>\run_state.json`, critical-section-guarded load/modify/save, atomic writes, corrupt-file quarantine to `run_state.json.bad`, boot/`--recover` cleanup driver | Common, Process, Registry, **Runner** (for `PerformCleanup` — note: Runner also consumes the journal interface, so State ↔ Runner is a compile-time cycle broken by the interface) |
| `src/Portappix.Trace.pas` | `TPortappixTraceRunner` / `TPortappixTrace`: before/after file+registry snapshots (injectable probes, caps: 20,000 files/keys, 256 values/key, 1 MiB hashing, 5 s budget), noise filter (Prefetch, thumbnails, Explorer MRUs/UserAssist, hive files, launcher folders, env-overridable via `PORTAPPIX_TRACE_ROOTS`/`PORTAPPIX_TRACE_REGISTRY`), diff, suggestion generation, `report.json`/`report.md`/`suggested_app.json` writers | Common, Manifest, Policy, Process (+ own probe types) |

### Store / updates / UI

| Unit | Responsibility | Depends on |
| --- | --- | --- |
| `src/Portappix.Signature.pas` | `CatalogPublicKeyHex` (embedded ECCPUBLICBLOB-format P-256 **public** key), `VerifySignature(content, 64-byte r||s)`: SHA-256 + CNG `BCrypt*` (`bcrypt.dll` imports declared locally) | Common |
| `src/Portappix.Catalog.pas` | `TCatalogApp` (`id/name/publisher/version/category/url/sha256/size/kind/recipe`), `TPortappixCatalog`: `LoadFromFile` (signature mandatory unless `AllowUnsignedCatalogs`), `LoadFromUrl` (https-only, fetch `<url>.sig`, verify, parse to temp list then atomic swap, cache to `Cache\catalog.json[.sig]`), strict field validation (https URL, 64-hex sha256, safe id, duplicate-id rejection, `kind` ∈ {package, recipe}) | Common, Signature |
| `src/Portappix.PackageManager.pas` | `TPortappixPackageManager`: `InstallApp` (https-only download → SHA-256+size verify → `ExtractArchive` (zip-slip + 20,000-entry + 2 GiB caps) → manifest id match + policy validation → downgrade/dataVersion protection → `AtomicSwap` with `.prev`), `RollbackApp`, `QueueUpdate`/`ApplyPendingUpdates` (`Cache\pending_updates.json`, tolerant corrupt handling, atomic save) | Common, Catalog, Manifest, Policy, Process, Version |
| `src/Portappix.Update.pas` | Launcher self-update: `DownloadReleases` (https unless `AllowInsecureReleaseUrls`; **signature always mandatory**), `TPortappixUpdateManager`: version compare, zip verify, `PrepareUpdate` (write `update_pending.json` **before** swap → rename running exe to `Launcher.exe.old` → move new exe → replace extra root files → rollback on failure), `ConfirmUpdate` (`--post-update` → `update_ok` + `launcher_version.json`), `RollbackToOldLauncher` (watchdog restore, failed build kept as `Launcher.exe.failed_<ts>`) | Common, Catalog, PackageManager, Process, Signature, Version |
| `src/Portappix.Importer.pas` | `TPortappixImporter`: version-info extraction (`GetFileVersionInfo*`), id/name scaffolding, `AnalyzeSource` (size/count/drive-root, reparse points skipped), `ImportToApps` (copy to `Apps\<id>.new` skipping reparse points, write `app.json`, rename; source never written) | Common |
| `src/Portappix.Cli.pas` | Headless commands: `--run`, `--trace`, `--check-manifest`, `--recover`, `--apply-updates`, `--check-updates`, `--self-update`, `--post-update`; flags `--accept-policy` (test-only), `--allow-insecure-release-urls` (test-only), `--root`, `--exit-code-file`, `--log-file`; exit codes 0/2/3/4/5/7/740; writes JSON result record atomically | Common, Manifest, Policy, PackageManager, Runner, Trace, State, Settings, Update, Consent |
| `src/Portappix.TrayUI.pas` | Tray icon + popup menu, category grouping, background launch threads with per-app mutex, consent callback (`TConsentRequest`), id/folder match check | Common, Consent, Manifest, Runner, State |
| `src/MainForm.pas` / `.dfm` | Dashboard: Installed tab (launch/uninstall/refresh/import/trace), Store tab (catalog list, install/update, progress), search; owns `TPortappixJournal` (boot recovery), catalog cache/URL persistence (`PORTAPPIX_CATALOG_URL` env override → `Cache\catalog_url.txt`), settings, package manager; `WM_QUERYENDSESSION` never blocks logoff; close-with-running-apps confirm | Common, Manifest, Catalog, PackageManager, Settings, State, Runner, TrayUI, Importer, Trace, Update |

Dependency direction: `Common ← {Junction, Registry(via Process), Manifest} ← Policy ← {Runner, PackageManager, Cli} ← UI`. The only back-edge is `Portappix.State → Portappix.Runner` (static `TPortappixRunner.PerformCleanup` call), paired with `Runner → (IPortappixJournal)` — a deliberate interface seam so tests can inject fakes.

## 2. Application initialization flow

`Launcher.dpr` → (CLI? `Portappix.Cli.ExecuteCli` : VCL path):

1. Acquire launcher single-instance mutex (`Local\Portappix.Launcher.<hash>`); refuse duplicate.
2. `TMainLauncherForm.FormCreate` (`MainForm.pas:131-149`):
   1. `InitializePaths` — root = exe folder; `Cache\catalog.json`, `Cache\catalog_url.txt`; load settings.
   2. `CheckLauncherUpdateWatchdog` — self-update rollback offer if `Launcher.exe.old` exists without `update_ok`.
   3. `LoadCatalogUrl` — `PORTAPPIX_CATALOG_URL` env var wins over `Cache\catalog_url.txt`.
   4. `InitializeRuntime` — create `Apps`/`Cache` dirs; create `TPortappixJournal` and run **`RecoverPendingCleanups` (boot recovery)**; create catalog + package manager.
   5. `InitializeTray` — `TPortappixTrayUI` with consent callback.
   6. `LoadInstalledApps`, `LoadCatalogFromCache` (instant), `RefreshCatalogInBackground` (thread), `ApplyPendingUpdatesInBackground`.

## 3. Catalog loading flow

1. `TPortappixCatalog.LoadFromUrl(url)` — https enforced; download bytes; fetch `<url>.sig`;
   verify ECDSA P-256 over SHA-256 of exact bytes; unsigned/invalid → raise unless the
   `AllowUnsignedCatalogs` unit global is set (UI only ever sets it `False`, `MainForm.pas:137`).
2. `Parse` builds a **new** `TObjectList<TCatalogApp>`; any error keeps the previous list intact
   (atomic swap at `Portappix.Catalog.pas:301-303`). Duplicate ids rejected.
3. On success the bytes + signature are cached to `Cache\catalog.json[.sig]`.
4. Store tab entries come from `FindById`; install/update re-verify the package independently.

## 4. Package installation flow (`TPortappixPackageManager.InstallApp`, PackageManager.pas:398-451)

1. Validate: non-nil definition, non-empty id, URL present and `https://`.
2. `DownloadPackage` → `Cache\<id>_<version>.zip` via `.download` temp + move.
3. `VerifyPackage` — SHA-256 must equal catalog value (file deleted on mismatch); byte size must match when `size > 0`.
4. `ExtractArchive` into `Apps\<id>.new` (destination wiped first): entry count ≤ 20,000; declared
   uncompressed total ≤ 2 GiB; every entry name checked with `IsZipSlip`; subdirectories preserved.
5. `ValidateExtractedManifest` — `app.json` must exist at archive root, its `id` must equal the
   catalog id, and it must pass `TPortappixPolicy.ValidateManifest`.
6. `ValidateUpdateAllowed` — semver downgrade refused; recorded `dataVersion` (from
   `Data\<id>\data_version.json`) must not exceed the incoming package's.
7. `AtomicSwap` — existing `Apps\<id>` → `Apps\<id>.prev` (after deleting an old `.prev`), `.new` →
   `Apps\<id>`; failed rename restores the previous generation. `Data\<id>` is never touched.
8. Cached zip deleted. Failure at any point deletes the `.new` directory.
9. If the app was running (per-app mutex or process-path scan), `QueueUpdate` records the entry in
   `Cache\pending_updates.json` instead; `ApplyPendingUpdates` re-applies when closed.

## 5. Portable execution lifecycle (`TPortableAppRunner.Run`, Runner.pas:373-453)

Exact sequence:

1. `TPortappixPolicy.ValidateManifest` — any violation raises `EPortappixPolicyError` **before any
   host change**.
2. Executable existence check (`FExePath` resolved: relative → app folder; tokens expanded).
3. `PrepareDataDirectories` — `ForceDirectories(Data\<id>)` and every junction target.
4. `TPortappixManifest.WriteDataVersion` (records `data_version.json`; best-effort, logged on failure).
5. `BuildEnvironment` — copy host env block, apply manifest overrides (tokens + `%VAR%` expanded from
   host env), `EnsureEnvironmentDirectories` creates folder-variables that point under `Data\<id>`.
6. `BuildEnvironmentBlock` — sorted, double-NUL-terminated.
7. **Host mutation block** (wrapped in try/except that rolls back: `RemoveJunctions` + `RestoreHostRegistryBackups`):
   1. `CreateJunctions` — per junction: refuse if `<host>_host_backup` already exists; if an existing
      reparse point occupies the host path → `DeleteJunction` (must succeed); else if a real directory →
      renamed to `<host>_host_backup`; a plain file → error. `FCreatedJunctions` updated; on partial
      failure all created junctions are rolled back and the error re-raised.
   2. `BackupHostRegistryKeys` — per key: refuse if `Data\<id>\host_backup_<n>.reg` already exists;
      `reg.exe export` if the key exists; failure → restore already-made backups and raise.
   3. `DeleteHostRegistryKeys` — `reg.exe delete /f` (host values cannot leak into the portable registry).
   4. `ImportPortableRegistry` — import `Data\<id>\registry.reg` if present.
8. **Journal persistence** — `FJournal.AddActiveApp(id, hijackedKeys, createdJunctions)` (best-effort;
   failure is only logged). *See SECURITY_INVENTORY finding PH0-SEC-02: this happens after step 7.*
9. `LaunchProcess` — `CreateProcess(CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT)` with the private
   env block, assign to job object, `ResumeThread`, wait for job-empty (`INFINITE`, 100 ms poll) with
   fallback to main-process wait. `ERROR_ELEVATION_REQUIRED` (740) → `EPortappixElevationRequired`.
10. Cleanup (`finally`): `CleanupHostRegistry` — export listed keys to temp `.reg`s and merge into
    `registry.reg`; **only if export succeeded** delete host keys; then always `RestoreHostRegistryBackups`
    (import + delete backup file; failed imports keep the file for retry). Then `RemoveJunctions`
    (reverse order; only removes reparse points, restores `_host_backup` if host path is gone).
11. `FJournal.RemoveActiveApp(id)` (best-effort).

Pre-launch failures roll back junctions + registry backups (step 7's except branch); journal entries
are removed in step 11 so `run_state.json` returns to empty.

## 6. Recovery lifecycle

- **Crash journal** — `TPortappixJournal` (`Portappix.State.pas`): `AddActiveApp` writes
  `apps.<id> = {active, dataDir, startedAt, hijackedKeys[], junctions[]}` atomically under a critical
  section; corrupt journal quarantined to `run_state.json.bad`.
- **`RecoverPendingCleanups`** (`State.pas:361-450`), invoked at UI boot and via `--recover`:
  1. Load journal; for each app entry (snapshot of ids first):
  2. Skip if the app is running (`IsAppRunning`: per-app mutex **or** process-path scan of `Apps\<id>`).
  3. `TPortappixRunner.PerformCleanup(appId, keys, junctions, dataDir)`: export hijacked keys → merge
     into `registry.reg`; delete host keys **only if export succeeded**; `RestoreBackupsWithOps`
     (import each `host_backup_*.reg`, delete on success, keep on failure); `RemoveJunctionsWithLog`
     (reverse order, reparse points only, restore `_host_backup` when host path absent).
  4. If any `host_backup_*.reg` files remain in `Data\<id>` → keep the journal entry for a later
     attempt; otherwise remove the entry. Save state once at the end.
  5. Entries with no recorded keys/junctions still get `RestoreScannedBackups` (import any
     `host_backup_*.reg` found in the data dir).
- **Launcher self-update watchdog** — `NeedsRollbackOffer` = `Launcher.exe.old` present ∧ `update_ok`
  absent; UI offers restore, headless runs log a warning (`Portappix.Cli.WarnIfUpdateUnconfirmed`).

## 7. Release build process

Documented in `README.md` §Build and `RELEASE_CHECKLIST.md`:

1. Command-line builds (verified working in Phase 0): `cd src && dcc32 -B Launcher.dpr` /
   `dcc64 -B Launcher.dpr`, or from repo root with `-Usrc`. `src/Launcher.dpr` lists units by name
   only, so any `-U` search path works. IDE path: open `src\Portappix.dproj` (Debug/Release ×
   Win32/Win64; DCU+exe output to `$(Platform)\$(Config)`).
2. Tests: `cd tests && dcc32 -B -U..\src PortappixTests.dpr` (+ Win64 twin); run the exe (exit 0 = green).
3. Fake apps for the suite: `tests\fakeapps\build.cmd [32|64|all]` → `tests\fakeapps\out[64]\<name>\`.
4. Release artifact: `python scripts/make_release.py --source <staging> --out dist --version x.y.z
   --channel stable --key keys/catalog_signing_key.pem --url-base https://…` — zips the staging
   folder, computes sha256/size, writes + signs `dist\releases.json`.
5. Catalog: `tools/build_recipe.py` (lint/verify/build per recipe) → `tools/build_catalog.py`
   (combine into signed `catalog.json` with `kind`/`recipe` provenance) → `scripts/validate_catalog.py`
   (schema, hashes, zip inspection, policy lint) → `scripts/sign_catalog.py` (re-sign).
6. Compatibility suite + real-app checklist in a clean VM/Sandbox (see RELEASE_CHECKLIST §5–7).

## 8. Key files (quick reference)

| Concern | File:lines |
| --- | --- |
| Entry / headless gate | `src/Launcher.dpr:30-40`, `src/Portappix.Cli.pas:934-937` |
| Policy gate before host mutation | `src/Portappix.Runner.pas:382-390` |
| Host mutation vs journal order | `src/Portappix.Runner.pas:407-425` |
| Export-before-delete (normal + crash path) | `src/Portappix.Runner.pas:803-828`, `:913-940` |
| Journal atomic save / corrupt quarantine | `src/Portappix.State.pas:163-168`, `:111-161` |
| Recovery driver | `src/Portappix.State.pas:361-450` |
| Junction create/delete primitives | `src/Portappix.Junction.pas:52-133` |
| Zip-slip + caps | `src/Portappix.PackageManager.pas:223-276` |
| Atomic swap / rollback | `src/Portappix.PackageManager.pas:300-324`, `:470-515` |
| Signature verification (CNG) | `src/Portappix.Signature.pas:68-109` |
| Catalog atomic swap | `src/Portappix.Catalog.pas:217-310` |
| Self-update swap / watchdog | `src/Portappix.Update.pas:449-534`, `:391-394` |
| Job-object tree wait | `src/Portappix.Process.pas:156-205` |
