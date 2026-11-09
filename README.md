# Portappix

Portable Windows application launcher core using **Level 2 virtualization**: no DLL injection. The launcher redirects environment variables, registry data, and NTFS junction paths, starts the target, waits for it to exit, then exports and restores the host state.

Delphi 12 / Object Pascal, standard RTL/VCL only.

## Engine units

- `src/Portappix.Manifest.pas` — `TPortappixManifest`, parses and validates `app.json`.
- `src/Portappix.Runner.pas` — `TPortableAppRunner`, performs environment virtualization, registry import/export/cleanup, host-backup restore, junction redirection, and process execution.
- `src/Portappix.State.pas` — `TPortappixJournal`, tracks active runs in `run_state.json` and recovers from crashes or forced exits.
- `src/Portappix.Catalog.pas` — `TPortappixCatalog`, downloads/loads `catalog.json` and parses app entries (`id`, `name`, `version`, `category`, `url`, `sha256`, `size`).
- `src/Portappix.PackageManager.pas` — `TPortappixPackageManager`, downloads, SHA-256 verifies, extracts, and atomically installs app packages without touching `Data\<id>`.
- `src/Portappix.Importer.pas` — `TPortappixImporter`, extracts Windows version info (`GetFileVersionInfo*`/`VerQueryValue`), generates a scaffolded `app.json` for an existing app folder, and can optionally copy it into `Apps\<id>`.

## VCL frontend (Phase 4)

- `src/Portappix.TrayUI.pas` — tray icon/popup menu manager; scans `Apps\*\app.json`, groups by category, and launches apps via `TPortableAppRunner` on anonymous background threads (UI stays responsive).
- `src/MainForm.pas` / `src/MainForm.dfm` — dashboard with **Installed Apps** (scan, launch, uninstall `Apps\<id>` only; `Data\<id>` preserved) and **Store** (cached/remote catalog, search, install + progress bar).
- `src/Launcher.dpr` — application entrypoint.

## App Importer (Final Utility)

`src/Portappix.Importer.pas` — `TPortappixImporter`:
- `GenerateManifest(SourceFolder, TargetExe[, Publisher, out ManifestPath, out AppId])` extracts Windows version info from `TargetExe` using `GetFileVersionInfoSize`/`GetFileVersionInfo`/`VerQueryValue` (`ProductName`, `CompanyName`, `FileVersion`, with fixed-file-info fallback). Falls back to the EXE file name if version info is missing.
- Builds `id` by lowercasing `ProductName` (or EXE name) and stripping/collapsing non-alphanumerics.
- Writes formatted `SourceFolder\app.json` with `id`, `name`, optional `publisher`/`version`, `exe` (path relative to `SourceFolder`), and Level 2 virtualization stubs:
  - `"env": {"APPDATA": "{data}\\AppData"}`
  - `"registry": []`
  - `"junctions": {}`
- Optional integration: `ImportToApps(SourceFolder, TargetExe, Publisher, AppsRoot)` generates the manifest, then copies the whole source folder to `Apps\<id>` (refuses if destination exists). It never touches `Data\<id>`.

## UI boot sequence

1. `MainForm.FormCreate` resolves the launcher root (`ParamStr(0)`), creates `Apps\`/`Cache\` dirs.
2. Initializes `TPortappixJournal` and calls `RecoverPendingCleanups` immediately.
3. Loads local `Cache\catalog.json` to populate the Store tab.
4. Starts a background thread to fetch the latest catalog (`FCatalogUrl`) and updates the UI via `TThread.Queue`.

Set `TMainLauncherForm.CatalogUrl` (or assign it in `FormCreate`) to enable remote refresh. Installs run in a background thread; `TDownloadProgressEvent` updates `TProgressBar`/status through `TThread.Queue`.

## Manifest

```json
{
  "id": "notepadpp",
  "name": "Notepad++",
  "exe": "{app}\\App\\notepad++.exe",
  "env": {
    "APPDATA": "{data}\\AppData",
    "LOCALAPPDATA": "{data}\\LocalAppData",
    "TEMP": "{data}\\Temp",
    "TMP": "{data}\\Temp",
    "PATH": "{app}\\App;%PATH%"
  },
  "junctions": {
    "C:\\ProgramData\\AppName": "{data}\\ProgramData"
  },
  "registry": [
    "HKCU\\Software\\Notepad++"
  ]
}
```

### Fields

| Field | Required | Description |
| --- | --- | --- |
| `id` | No | Folder name under `Data\`. Defaults to the manifest's parent folder name. |
| `name` | No | Display name. Defaults to `id`. |
| `exe` | Yes | Executable path. Supports tokens. |
| `env` | No | Object of environment variable overrides. Values must be strings. |
| `junctions` | No | Object mapping host directory paths to portable target directories. Tokens are expanded in both sides. |
| `registry` | No | Array of registry key paths. Every key the portable `.reg` touches should be listed so it can be exported and cleaned up. |

### Path resolution

- Relative paths resolve against the launcher directory (`ExtractFilePath(ParamStr(0))`).
- `{root}` — launcher directory.
- `{app}` — directory containing the `app.json` file.
- `{data}` — absolute `Data\<id>` directory.
- `{id}` — manifest id.
- `%VAR%` inside `env` values is expanded from the **host** environment before overrides are applied. This makes values such as `%PATH%` deterministic.

The portable registry file is always `Data\<id>\registry.reg`.

## Usage

Recover pending cleanups before normal app starts:

```pascal
var
  Journal := TPortappixJournal.Create; // root = launcher directory
  Journal.OnLog := procedure(const Message: string) begin { log } end;
  Journal.RecoverPendingCleanups;
```

Run an app with journaling:

```pascal
var
  Runner := TPortableAppRunner.Create('Apps\notepadpp\app.json', Journal);
try
  Runner.OnLog := procedure(const Message: string) begin { log } end;
  ExitCode := Runner.Run;
finally
  Runner.Free;
end;
```

`Run` is synchronous: it returns the child process exit code after the application closes. Call it from a worker thread when wiring the VCL UI.

## Runtime flow

1. Parse and validate `app.json`; resolve paths, junctions, and registry key paths.
2. Create `Data\<id>`, redirected folder variables, and junction target directories.
3. Export any existing host registry keys to `Data\<id>\host_backup_<index>.reg`.
4. Create NTFS junctions. Existing host reparse points are removed; existing real host directories are renamed to `<HostPath>_host_backup`. Junctions are created with hidden `cmd.exe /c mklink /J`.
5. Import `Data\<id>\registry.reg` with hidden `reg.exe import`.
6. Record the active app, hijacked registry keys, and created junction host paths in root `run_state.json` (when a journal is provided).
7. Build a custom Unicode environment block from the host environment plus manifest overrides.
8. `CreateProcess`, then block in `WaitForSingleObject`.
9. Export the listed registry keys with `reg.exe export`, merge them into `registry.reg`, delete them with `reg.exe delete /f`, and restore registry backups.
10. Remove created junctions with `cmd.exe /c rmdir`/`RemoveDir` (never recursive delete), restore `<HostPath>_host_backup` directories, and remove the app from `run_state.json`.

## Package manager

`TPortappixPackageManager.InstallApp` performs:

1. **Download** — `System.Net.HttpClient` downloads `url` to `Cache\<id>_<version>.zip` (with optional `TDownloadProgressEvent`).
2. **Verify** — `THashSHA2` (SHA-256) must match `sha256`; the cached zip is deleted on mismatch.
3. **Extract (atomic staging)** — `TZipFile` extracts to `Apps\<id>.new`; rejects zip-slip paths and requires `Apps\<id>.new\app.json`.
4. **Swap** — if `Apps\<id>` exists, renames it to `Apps\<id>.old`, renames `.new` to the final app directory, deletes `.old` and the cached zip. `Data\<id>` is never modified during install/update.

## Storefront CI/CD

- `catalog.json` — public app catalog (`apps[]` with `id`, `name`, `version`, `category`, `url`, `sha256`, `size`).
- `catalog.schema.json` — JSON Schema for PR validation.
- `scripts/validate_catalog.py` — validates `catalog.json` against the schema (prints exact JSON paths on failure), then streams each package URL with `requests`, computes SHA-256 on the fly, and verifies hash and byte size.
- `.github/workflows/validate-pr.yml` — runs the validator on pull requests that modify `catalog.json`, the schema, the validator, or the workflow.

## Notes and limitations

- Host registry keys present before launch are backed up to `Data\<id>\host_backup_<index>.reg` and restored after cleanup. If backup creation fails, `Run` raises before junction/registry import.
- Existing real host directories at junction paths are renamed to `<HostPath>_host_backup` before a junction is created. If `<HostPath>_host_backup` already exists, junction setup fails to avoid overwriting host data.
- Junction removal uses `cmd.exe /c rmdir` (and `RemoveDir` fallback) so it removes the junction point, not the target contents on the USB drive.
- If portable registry import fails, `Run` rolls back created junctions and restores host registry backups before raising. A partially imported `.reg` may still need manual cleanup because registry import is not transactional.
- If the portable registry cannot be exported, the host keys are left in place so data is not destroyed; the failure is reported through `OnLog`. Junctions and registry backups are still restored.
- `run_state.json` is the crash journal. It records `hijackedKeys` and `junctions` host paths. `TPortappixJournal.RecoverPendingCleanups` should run once at launcher startup; it deletes recorded keys, removes recorded junctions, restores host backups, and keeps the entry when backup files still cannot be restored.
- Every registry key in the portable `.reg` should also appear in the manifest's `registry` array; otherwise it will not be exported or removed.
- Registry view follows the launcher process bitness. A 32-bit `Launcher.exe` uses the 32-bit registry view and the redirected `reg.exe`; a 64-bit build uses the 64-bit view.
- The launcher waits only for the directly started process. Child processes that outlive it are not tracked.
