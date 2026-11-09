# Portappix

Portable Windows application launcher using **Level 2 virtualization**: no DLL injection, no
filesystem filter drivers. Portappix redirects environment variables, registry data and NTFS
junction paths, starts the target, waits for the whole process tree, then exports and restores
the host state. Everything ships as a single `Launcher.exe` plus the app folders.

Delphi 12 / Object Pascal, Win32 + Win64, standard RTL/VCL + Win32 API (Windows CNG for
signatures). No third-party components.

## Solution layout

| Unit | Purpose |
| --- | --- |
| `src/Portappix.Common.pas` | Path/token helpers, SHA-256, named-mutex single-instance and per-app locks, atomic file replacement. |
| `src/Portappix.Process.pas` | Hidden process execution, job-object process-tree waiting. |
| `src/Portappix.Junction.pas` | Direct Win32 directory junctions (`FSCTL_SET_REPARSE_POINT` / `FSCTL_DELETE_REPARSE_POINT`). |
| `src/Portappix.Registry.pas` | `IPortappixRegistryOps`, `reg.exe` implementation, registry path parsing, `.reg` merging. |
| `src/Portappix.Policy.pas` | `TPolicyResult` and allow/deny validation for registry keys, junctions and environment overrides. |
| `src/Portappix.Signature.pas` | ECDSA P-256 catalog signatures verified with Windows CNG (`BCrypt*`). |
| `src/Portappix.Consent.pas` | First-run approval per app id + `app.json` hash. |
| `src/Portappix.Manifest.pas` | `TPortappixManifest`, parses and validates `app.json`. |
| `src/Portappix.Runner.pas` | `TPortableAppRunner` — the execution engine. |
| `src/Portappix.State.pas` | `TPortappixJournal` — crash journal, locking, boot recovery. |
| `src/Portappix.Catalog.pas` | `TPortappixCatalog` — signed `catalog.json` download/parse. |
| `src/Portappix.PackageManager.pas` | Download, SHA-256/size verification, safe unzip, atomic install/update. |
| `src/Portappix.Importer.pas` | Version-info extraction and non-destructive import into `Apps\<id>`. |
| `src/Portappix.TrayUI.pas` | Tray icon/popup menu; category grouping; background launches; app locks; consent. |
| `src/MainForm.pas` / `.dfm` | Dashboard (installed apps + signed store + updates) and importer UI. |
| `src/Launcher.dpr` | Entry point; acquires the launcher single-instance mutex before anything else. |

Engine units (`Portappix.*`) have no VCL/Forms dependency. UI logic lives in `MainForm` and
`Portappix.TrayUI`.

## Manifest (`app.json`)

```json
{
  "schema": 1,
  "id": "notepadpp",
  "name": "Notepad++",
  "publisher": "Don Ho",
  "version": "8.6.9",
  "category": "Editors",
  "exe": "App\\notepad++.exe",
  "args": "-multiInst",
  "env": {
    "APPDATA": "{data}\\AppData",
    "LOCALAPPDATA": "{data}\\LocalAppData",
    "TEMP": "{data}\\Temp",
    "TMP": "{data}\\Temp",
    "PATH": "{app}\\App;%PATH%"
  },
  "junctions": {
    "%PROGRAMDATA%\\Notepad++": "{data}\\ProgramData"
  },
  "registry": [
    "HKCU\\Software\\Notepad++\\Notepad++"
  ]
}
```

| Field | Required | Description |
| --- | --- | --- |
| `schema` | No | Manifest schema version. Defaults to `1`; higher values are rejected. |
| `id` | No | Folder name under `Data\` and `Apps\`. Defaults to the manifest folder name. Must match the `Apps\<folder>` name when scanned. |
| `name` | No | Display name. Defaults to `id`. |
| `publisher` | No | Informational. |
| `version` | No | Used for update detection against the catalog. |
| `category` | No | Tray menu group. Defaults to `Apps`. |
| `exe` | Yes | Executable path. Supports tokens. |
| `args` | No | Raw command-line arguments appended to the executable. |
| `env` | No | Environment overrides. Values must be strings. |
| `junctions` | No | Host directory → portable target. Tokens expand on both sides. |
| `registry` | No | HKCU keys touched by the app; listed keys are backed up, cleared, imported and exported. |

### Path resolution

- A **plain relative `exe`** resolves against the **app folder** (the folder that contains
  `app.json`), not the launcher root.
- `{root}` — launcher directory (`ExtractFilePath(ParamStr(0))`).
- `{app}` — directory containing `app.json`.
- `{data}` — absolute `Data\<id>` directory.
- `{id}` — manifest id.
- `%VAR%` inside `env` values is expanded from the **host** environment before overrides are applied.

The portable registry file is always `Data\<id>\registry.reg`.

## Security policy

Validated by `Portappix.Policy` before any host change, and mirrored in the catalog CI:

- **Registry** — only `HKCU\Software\<vendor>\<app...>` with at least two levels below
  `HKCU\Software`. HKLM/HKCR/HKU/HKCC, `HKCU\Software` itself, and deny-listed vendors
  (`Microsoft`, `Classes`, `Policies`, `Windows`, `Windows NT`, `CurrentVersion`) are rejected.
- **Junctions** — host paths must be inside `%APPDATA%`, `%LOCALAPPDATA%`, `%PROGRAMDATA%`, or
  `%USERPROFILE%\.<name>`. Profile roots, `Documents`, `Desktop`, `Downloads`, `OneDrive`,
  `Windows`, `System32`, `Program Files` and `%PROGRAMDATA%\Microsoft` are rejected. Manifest
  tokens and `..` traversal in host paths are rejected. Targets must stay inside `{data}`.
- **Environment** — only an allow-list is overridable (`APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`,
  `PATH`, `PATHEXT`, `HOME`, `PROGRAMDATA`, `PUBLIC`, `XDG_*`, `USERNAME`, ...). Path-like
  variables must reference `{app}` or `{data}`.

Policy violations abort `Run` before junctions or registry keys are touched.

## Runtime flow

1. Parse and validate `app.json`; run the policy checks; resolve paths.
2. Create `Data\<id>` and redirected environment folders.
3. Create NTFS junctions with direct Win32 reparse-point calls. Existing reparse points are
   removed with `FSCTL_DELETE_REPARSE_POINT`; existing real host directories are renamed to
   `<HostPath>_host_backup`. Existing `<HostPath>_host_backup` aborts to avoid data loss.
4. **Back up** existing host registry keys (`reg.exe export` → `Data\<id>\host_backup_<n>.reg`).
5. **Delete** the listed host keys, so host values cannot leak into the portable registry.
6. **Import** `Data\<id>\registry.reg` (if present).
7. Record the app, hijacked keys and created junctions in `run_state.json`.
8. Start the process suspended, assign it to a **job object**, resume it, and wait until the
   job has no active processes (whole process tree), falling back to waiting on the main process
   if job objects are unavailable.
9. Export the listed keys, merge them into `registry.reg`, and **only then** delete the host
   keys (`reg.exe delete /f`). If the export fails, keys are left in place.
10. Restore host backups (`reg.exe import` + delete backup files), remove junctions with
    `FSCTL_DELETE_REPARSE_POINT` (never recursively), restore `<HostPath>_host_backup`, and
    remove the journal entry.

A pre-launch failure rolls back created junctions and restores host registry backups.
`ERROR_ELEVATION_REQUIRED` (740) raises `EPortappixElevationRequired` with a clear message.

## Crash safety, locks and shutdown

- `run_state.json` records active apps, hijacked keys, junction host paths and `dataDir`.
  All load/modify/save operations run under a critical section and are written to a temp file
  then atomically replaced (`MoveFileEx` with `MOVEFILE_REPLACE_EXISTING`).
- A corrupt journal is copied to `run_state.json.bad` before a fresh journal is started.
- `RecoverPendingCleanups` exports the recorded keys to `registry.reg` **before** deleting them,
  restores host backups, removes recorded junctions, and skips apps whose per-app mutex is held.
- A named launcher mutex (hash of the launcher root) enforces a single running launcher and is
  acquired before recovery runs.
- A per-app mutex prevents double launches; the tray/UI reports "already running".
- Closing the form while apps run asks whether to wait for cleanup; Windows logoff/shutdown is
  never blocked (`WM_QUERYENDSESSION`).

## First-run consent

Before an app with registry/junction/env surface runs for the first time, the UI shows exactly
what it will touch. Approval is stored in `Data\<id>\policy_consent.json` together with the
SHA-256 of that exact `app.json`; changing the manifest invalidates the approval. The engine
never prompts on its own — the UI passes a consent callback to `TPortappixTrayUI`.

## Catalog and signatures

`catalog.json` is signed with ECDSA P-256. The signature is the raw 64-byte `r||s` value over
the SHA-256 digest of the exact catalog bytes, stored in `catalog.json.sig` next to the catalog.
The launcher embeds the public key (`Portappix.Signature.CatalogPublicKeyHex`) and verifies the
signature with Windows CNG before parsing. Unsigned or invalid catalogs are refused unless the
development flag `AllowUnsignedCatalogs` is enabled.

Signing:

```bash
pip install cryptography
python scripts/sign_catalog.py --catalog catalog.json --key keys/catalog_signing_key.pem
python scripts/sign_catalog.py --catalog catalog.json --public-key catalog_public.pem --verify
```

The private key is intentionally **not** committed (`keys/` is ignored). Replace the embedded
public key if you generate a new key pair.

`TPortappixCatalog` requires `https://` catalog and package URLs, downloads the catalog and
signature to `Cache\`, and parses into a temporary list so a bad download never empties the
previous catalog.

## Package manager

`TPortappixPackageManager.InstallApp`:

1. **Download** — HTTPS only; `Cache\<id>_<version>.zip` with a throttled progress callback.
2. **Verify** — SHA-256 must match; the byte size must match the catalog `size`.
3. **Extract** — `Apps\<id>.new`; rejects zip-slip entries, caps entry count (20,000) and total
   uncompressed size (2 GiB), keeps subdirectories and requires `app.json` at the archive root.
4. **Validate** — the manifest id must equal the catalog id and pass the same policy checks.
5. **Swap** — existing `Apps\<id>` → `.old`, `.new` → `Apps\<id>`, delete `.old` and the cached
   zip. `Data\<id>` is never touched.

## Importer

`TPortappixImporter` reads `ProductName` / `CompanyName` / `FileVersion` through
`GetFileVersionInfo*` / `VerQueryValue` and scaffolds a manifest with `schema`, `id`, `name`,
`publisher`, `version`, a relative `exe`, and the Level 2 stubs (`env.APPDATA`, empty
`registry`/`junctions`).

`ImportToApps` copies the folder to `Apps\<id>.new` (skipping reparse points), writes `app.json`
into the copy, and only then renames the directory. The user's source folder is never written
to by the import flow. `AnalyzeSource` reports size/file count/drive-root so the UI can ask for
confirmation above 2 GiB or 20,000 files.

## Store and updates

The Store tab shows catalog entries with a **Status** column (`Installed` / `Update available`).
`Install` installs fresh apps; `Update` reuses the same atomic install path for an app whose
installed `version` differs from the catalog. Uninstall removes `Apps\<id>` only; `Data\<id>` is
preserved. Scanning skips `.new`/`.old` folders and manifests whose id does not match the folder.

## Build

Delphi 12 Athens, Win32 and Win64 targets: open `Portappix.dproj` and build, or:

```bash
dcc32 -B -Usrc src\Launcher.dpr
dcc64 -B -Usrc src\Launcher.dpr
```

`src\Launcher.dpr` lists its units by name only (no `in '...'` paths), so it resolves whether it
is built through the `.dproj` (unit search path `src`) or straight from the `src` folder. The
`.dpr` does not reference `Launcher.res`, so a clean clone builds without pre-generated
resource files (add version info/icon in the IDE if desired). `*.res`, DCUs and the runtime
`Apps`/`Data`/`Cache` folders are ignored by git.

## Tests

`tests\PortappixTests.dpr` is a console program with a tiny assertion helper (no third-party
framework):

```bash
dcc32 -B -Usrc tests\PortappixTests.dpr
tests\PortappixTests.exe
```

or open `tests\PortappixTests.dproj`. Coverage: manifest parsing/validation, token expansion,
policy allow/deny, catalog parsing with atomic swap, zip-slip rejection, subfolder-preserving
extraction, SHA-256 reference value, journal save/recover/corrupt handling, and
export-before-delete ordering with an injected registry-ops fake.

## Storefront CI

- `catalog.json` — public app catalog (`apps[]` with `id`, `name`, optional `publisher`,
  `manifestSchema`, `version`, `category`, `url` (https only), `sha256`, `size`).
- `catalog.schema.json` — strict JSON Schema (no extra properties).
- `scripts/validate_catalog.py` — schema validation, duplicate ids, streaming download with
  SHA-256 and byte-size checks, zip inspection (root `app.json`, id match, zip-slip, entry/size
  caps) and the same registry/junction/env policy rules as the launcher.
- `scripts/sign_catalog.py` — creates/verifies `catalog.json.sig`.
- `.github/workflows/validate-pr.yml` — PR validation with GitHub Actions pinned to commit SHAs.

## Notes and limitations

- Host registry keys present before launch are backed up and restored. If a backup cannot be
  created — or a backup from a previous crash still exists — `Run` raises before any host key
  is deleted so the original state can be recovered first.
- Registry import is not transactional; a partially imported `.reg` may need manual cleanup.
- Junctions use `FSCTL_*` directly, so `%` in paths is never expanded by `cmd.exe`.
- Registry operations use `reg.exe` resolved from `SystemRoot\System32`; the registry view
  follows the launcher process bitness.
- The launcher waits only for processes that stay inside the job object. Processes that break
  away from the job are not tracked.
- Elevated apps cannot inherit the redirected environment; the launcher reports this instead of
  silently launching them.
- Catalog signatures protect the catalog bytes; they do not replace code signing of the
  packages themselves.

### Manual testing required on Windows

Job-object process-tree waiting, junction create/delete/restore, registry backup/export/delete/
restore ordering, first-run consent dialogs, data-size confirmation during import,
`ERROR_ELEVATION_REQUIRED`, single-instance mutex, per-app lock, tray Exit with running apps,
and logoff/shutdown handling.
