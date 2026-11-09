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
| `src/Portappix.Cli.pas` | Headless CLI mode (`--run`, `--check-manifest`, `--recover`); used by the compatibility suite; never shows UI. |
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
| `src/Portappix.PackageManager.pas` | Download, SHA-256/size verification, safe unzip, atomic install/update, `.prev` rollback, pending-update queue. |
| `Portappix.Version.pas` | Semantic version parsing and comparison for update decisions. |
| `Portappix.Settings.pas` | `Cache\settings.json` (update URL, auto-check, pending-apply flags). |
| `Portappix.Update.pas` | Signed `releases.json` self-update: swap, `--post-update` confirmation, rollback watchdog. |
| `src/Portappix.Importer.pas` | Version-info extraction and non-destructive import into `Apps\<id>`. |
| `src/Portappix.Trace.pas` | "What did this app touch" trace reports: before/after snapshots, diff, noise filter, sandboxing suggestions. |
| `src/Portappix.TrayUI.pas` | Tray icon/popup menu; category grouping; background launches; app locks; consent. |
| `src/MainForm.pas` / `.dfm` | Dashboard (installed apps + signed store + updates) and importer UI. |
| `src/Launcher.dpr` | Entry point; acquires the launcher single-instance mutex before anything else. |
| `tools/build_recipe.py` / `tools/build_catalog.py` | Recipe tooling: lint, verify, package known portable apps; combine into a signed `catalog.json`. |
| `recipes/` | 25 pinned known-app recipes (`recipes/README.md`); `SKIPPED.md` documents apps that cannot be wrapped. |

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
| `dataVersion` | No | Bump when an update changes the on-disk data schema. The runner records it in `Data\<id>\data_version.json`; updates that would move to an older data version are refused. |
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

## Headless CLI

`Launcher.exe` accepts command-line switches for scripts and the compatibility suite. With
any `--` switch present it never creates forms, never shows a window and never takes the
launcher single-instance mutex (so a headless run can start while the tray launcher is
running, and vice versa):

| Switch | Meaning |
| --- | --- |
| `--run <app-id\|app.json>` | Run an installed app and wait for its whole process tree. The process exit code is the app's own exit code. |
| `--wait` | Accepted for readability; `--run` always waits for the tree. |
| `--trace <app-id\|app.exe>` | Run an app **without virtualization** and write a "what did it touch" report (see "Writing a manifest with Trace"). VM/Sandbox only. |
| `--accept-policy` | Test-only: records first-run consent without a prompt. Never use on a real desktop. |
| `--check-manifest <app.json>` | Validate a manifest against `Portappix.Policy` without running anything. |
| `--recover` | Run the crash journal's pending cleanups and exit. |
| `--apply-updates` | Apply updates queued while apps were running. |
| `--check-updates <url>` | Download + verify `releases.json`; report `updateAvailable` in the exit-code file. |
| `--self-update <url>` | Download, verify and apply a launcher update, then restart. |
| `--post-update` | First start after a self-update: confirm and record the new version. |
| `--allow-insecure-release-urls` | Test-only: allow `http://` release URLs (signatures stay mandatory). |
| `--root <path>` | Launcher root (defaults to the folder containing `Launcher.exe`). |
| `--exit-code-file <path>` | Write a JSON record: `{"command", "app", "exitCode", "alreadyRunning", "message"}`. |
| `--log-file <path>` | Append a timestamped run log. |

Exit codes: `0` success (for `--run`, the app's own exit code; for `--trace`, "report written" —
the app's exit code is inside the report), `2` manifest/policy rejection, `3` usage error, `4`
app already running, `5` consent required but `--accept-policy` missing, `7` other failure,
`740` `ERROR_ELEVATION_REQUIRED`.

## Compatibility suite

`tests\suite\` contains eight fake apps (built by `tests\fakeapps\build.cmd`), valid and
deliberately-bad manifests, and `run_suite.ps1` which snapshots the host, runs every case
headless, asserts marker data lands under `Data\<id>`, asserts the host snapshot is unchanged,
and writes a JSON + Markdown summary. See **`tests\suite\README.md`** for build/run
instructions — and note that the suite must only run in a VM or Windows Sandbox. The manual
20-app checklist for release testing is `tests\suite\real_apps.md`; the release process is
`RELEASE_CHECKLIST.md`.

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

## Writing a manifest with Trace

Portappix can watch an app run **without any sandboxing** and produce a report of what it wrote,
then draft the Level 2 manifest for it. Trace mode is for **virtual machines or Windows
Sandbox** — the app runs unrestricted on the host.

Two entry points:

- **UI** — select an installed app on the *Installed* tab and press **Trace** (a warning dialog
  reminds you that the app is not sandboxed).
- **CLI** — `Launcher.exe --trace <app-id|app.exe> [--accept-policy]`. First-run consent applies
  like `--run`; a loose `app.exe` is only accepted when an `app.json` sits next to it.

The run writes `Trace\<id>_<timestamp>\` inside the launcher root:

| File | Content |
| --- | --- |
| `report.json` | Full machine-readable diff: files added/modified/deleted, registry keys added/modified/deleted, suggestions, snapshot stats, notes. |
| `report.md` | Human-readable summary of the same data. |
| `suggested_app.json` | Draft `app.json` with the discovered `env`, `junctions` and `registry` surface. `_warnings` / `_manualReview` entries must be reviewed before use. |

How suggestions are derived:

- Writes under `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%` become **env overrides**
  (`APPDATA={data}\AppData`, `LOCALAPPDATA={data}\LocalAppData`, `TEMP`/`TMP={data}\Temp`).
- Writes under `%PROGRAMDATA%` become **junction** suggestions
  (`%PROGRAMDATA%\<vendor>` → `{data}\ProgramData\<vendor>`), validated by the same policy as
  real manifests.
- Changed registry keys collapse to the shortest common `HKCU\Software\<vendor>\<app>` prefix
  and become **registry** suggestions; anything outside that hive or shallower than
  `\<vendor>\<app>` is flagged for manual review.
- Writes into `Documents`, `Desktop`, `%PUBLIC%`, the profile root or elsewhere produce
  **warnings** — Portappix cannot redirect those folders.
- Known host noise (Prefetch, thumbnail caches, Explorer MRUs/`UserAssist`, Windows Search
  index, crash dumps, and the launcher's own `Cache`/`Data`/`Apps`/`Trace` folders) is filtered
  out before diffing.

Snapshot limits (per before/after pass): 20,000 files, 20,000 keys, 256 values per key,
4096 bytes per registry value, 1 MiB per hashed file (larger files are compared by size and
timestamp only), and a 5 second time budget; truncated snapshots are marked in the report.
Registry **reads** are not captured — only keys that appeared or whose values changed are listed.

For scripts and CI the scan can be re-pointed without touching real folders:

```bash
PORTAPPIX_TRACE_ROOTS=C:\vm\appdata=6;C:\vm\programdata=4   # replaces the default file roots
PORTAPPIX_TRACE_REGISTRY=HKCU\Software                      # replaces the default registry roots
```

## Store and updates

The Store tab shows catalog entries with a **Status** column (`Installed` /
`Update available` / `Update pending`). `Install` installs fresh apps; `Update`
reuses the same atomic install path for an app whose installed `version`
differs from the catalog. Uninstall removes `Apps\<id>` (plus its rollback
copy) only; `Data\<id>` is preserved. Scanning skips `.new`/`.old`/`.prev`
folders and manifests whose id does not match the folder.

## Updates

### App updates (safe)

- **Downgrade protection** — a package whose semantic `version` is older than
  the installed app is refused, and so is a package whose `dataVersion` is
  older than the recorded one (`Data\<id>\data_version.json`, written by the
  runner on every launch when the manifest declares a non-zero `dataVersion`).
- **Pending updates** — updating an app that is currently running (per-app
  mutex or the app folder seen in the process list) queues the update in
  `Cache\pending_updates.json` instead of failing. Queued updates install
  automatically at the next launcher start (or `--apply-updates`) once the
  app has closed; `Data\<id>` is never touched. A failed queued update stays
  queued.
- **Rollback** — every app update keeps one previous generation in
  `Apps\<id>.prev`. Rolling back restores it while the app is closed.

### Launcher self-update

`releases.json` (signed as `releases.json.sig` with the same embedded ECDSA
P-256 key as `catalog.json`) advertises the newest launcher release
(`schema`, `channel`, `version`, `url` (https), `sha256`, `size`, `notes`).
Build it with:

```bash
python scripts/make_release.py --source staging --out dist --version 1.1.0 \
    --channel stable --key keys/catalog_signing_key.pem \
    --url-base https://example.com/downloads
```

Flow (see `Portappix.Update`):

1. `--check-updates <url>` verifies the signature, compares semantic versions
   and reports `updateAvailable` in the exit-code file.
2. `--self-update <url>` downloads the zip (sha256 + size verified), extracts
   it with the same zip-slip/entry caps as app packages, writes
   `Cache\update_pending.json`, renames the running `Launcher.exe` to
   `Launcher.exe.old`, moves the new one into place (extra release files are
   replaced too), starts `Launcher.exe --post-update` and exits.
3. `--post-update` writes `Cache\update_ok`, records the version in
   `Cache\launcher_version.json` and removes the pending file.
   `Launcher.exe.old` stays as the rollback copy until the next update.
4. **Watchdog** — if `Launcher.exe.old` exists without `update_ok`, the new
   version never confirmed a successful start: the UI offers to restore the
   previous launcher; headless runs log a warning. The failed build is kept
   next to the launcher as `Launcher.exe.failed_<timestamp>`.

Update settings live in `Cache\settings.json` (`updateUrl`,
`autoCheckUpdates`, `autoApplyPendingUpdates`); pass the URL explicitly to
skip the setting. `--allow-insecure-release-urls` is a test-only escape hatch
that permits `http://` URLs for local test servers — signature verification is
never skipped.

## Build

Delphi 12 Athens, Win32 and Win64 targets: open **`src\Portappix.dproj`** (the project file lives
next to the sources so unit paths resolve from the project folder), or build from a command
prompt:

```bash
cd src
dcc32 -B Launcher.dpr                 # Win32
dcc64 -B Launcher.dpr                 # Win64
```

or from the repository root:

```bash
dcc32 -B -Usrc src\Launcher.dpr
dcc64 -B -Usrc src\Launcher.dpr
```

`src\Launcher.dpr` lists its units by name only (no `in '...'` paths), so it resolves from the
project folder or from any `-U` search path you provide. The `.dpr` does not reference
`Launcher.res`, so a clean clone builds without pre-generated resource files (add version
info/icon in the IDE if desired). `*.res`, DCUs and the runtime `Apps`/`Data`/`Cache` folders are
ignored by git.

## Tests

`tests\PortappixTests.dpr` is a console program with a tiny assertion helper (no third-party
framework). It never touches the host registry or user profile: registry interactions use
injected fakes and all file writes go to a temporary directory.

```bash
cd tests
dcc32 -B -U..\src PortappixTests.dpr   # Win32 build, output: tests\PortappixTests.exe
PortappixTests.exe
dcc64 -B -U..\src PortappixTests.dpr   # Win64 build, overwrites tests\PortappixTests.exe
PortappixTests.exe
```

or open `tests\PortappixTests.dproj` (it adds `..\src` to the unit search path). The program
exits with code `0` when everything passes and `1` on any failure, so it can be used in CI.
A prebuilt copy of the launcher and the tests lives in `bin\` after a local build; the
compatibility suite in `tests\suite\` (see "Compatibility suite" below) has its own build and
run instructions and must only be executed in a VM / Windows Sandbox.
Coverage: manifest parsing/validation, token expansion, policy allow/deny, catalog parsing
with atomic swap, zip-slip rejection, subfolder-preserving extraction, SHA-256 reference value,
journal save/recover/corrupt handling, export-before-delete ordering with an injected
registry-ops fake, and the trace engine (noise filter, snapshot caps, snapshot diff,
suggestion generation and report writing) with injected file/registry probes — the trace tests
never launch a process and never touch the host. Update logic is covered too: semantic version
ordering, `dataVersion` handling, the pending-update queue (including corrupt files and disk
persistence), `.prev` rollback, downgrade/data-version protection, settings persistence, and
the launcher self-update swap/confirm/rollback state machine against a local zip (no network).

## Storefront CI

- `catalog.json` — public app catalog (`apps[]` with `id`, `name`, optional `publisher`,
  `manifestSchema`, `version`, `category`, `url` (https only), `sha256`, `size`, and optional
  provenance fields `kind` (`package`|`recipe`) and `recipe` (`recipes/<id>.json`)).
- `recipes/` — pinned recipes for known portable apps (25 apps; see `recipes/README.md`),
  validated against `recipe.schema.json`. Vendor binaries are never committed — recipes
  reference vendor URLs + pinned hashes only.
- `catalog.schema.json` — strict JSON Schema (no extra properties).
- `scripts/validate_catalog.py` — schema validation, duplicate ids, recipe provenance
  cross-checks, streaming download with SHA-256 and byte-size checks, zip inspection
  (root `app.json`, id match, zip-slip, entry/size caps) and the same
  registry/junction/env policy rules as the launcher.
- `scripts/sign_catalog.py` — creates/verifies `catalog.json.sig`.
- `tools/build_recipe.py` — lint (schema + policy, no network), verify (download + hash
  check) and build (inject `app.json`, deterministic re-zip) for recipes.
- `tools/build_catalog.py` — combines built recipes into a signed `catalog.json`.
- `.github/workflows/validate-pr.yml` — PR validation with GitHub Actions pinned to commit SHAs.
- `.github/workflows/recipes.yml` — recipe lint job (schema + policy per recipe, pinned SHAs).

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
the Trace button warning dialog and a full `--trace` report on a real app (VM/Sandbox), and
logoff/shutdown handling.
