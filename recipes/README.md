# Portappix recipes

Recipes pin **known portable Windows apps** (vendor-hosted zip archives) into
reproducible Portappix packages. A recipe references the vendor download URL
plus a **pinned sha256 and byte size** — vendor binaries are never committed
to this repository; `tools/build_recipe.py` downloads, verifies and re-zips
them at build time.

## Layout

| File | Purpose |
| --- | --- |
| `recipes/<id>.json` | One recipe per app, validated against `recipe.schema.json`. |
| `../recipe.schema.json` | JSON Schema for recipe files. |
| `SKIPPED.md` | Popular apps that cannot be wrapped (installer-only, .7z-only, third-party repacks) and why. |

## Commands

```bash
# Lint every recipe (schema + Portappix policy, no network). Runs in CI.
python tools/build_recipe.py recipes/<id>.json --schema recipe.schema.json --lint-only

# Build one package: download the vendor zip, verify the pinned sha256/size,
# inject app.json, re-zip deterministically, write dist/<id>.build.json.
python tools/build_recipe.py recipes/<id>.json --schema recipe.schema.json --out dist

# Combine built packages into catalog.json (optionally signed).
python tools/build_catalog.py --recipes recipes --packages dist \
    --url-base https://packages.example.com/files --out catalog.json \
    --key "$USERPROFILE/.portappix/signing/catalog_signing_key.pem"

# Full catalog validation (downloads every package; used before publishing).
python scripts/validate_catalog.py --catalog catalog.json --schema catalog.schema.json
```

`build_catalog.py` emits catalog entries with `"kind": "recipe"` and
`"recipe": "recipes/<id>.json"`, which `Portappix.Catalog` parses and
`scripts/validate_catalog.py` cross-checks (recipe file exists, schema-valid,
id/version match the catalog entry).

## Current roster (25 recipes)

| Recipe | App | Category | Hash source |
| --- | --- | --- | --- |
| accesschk | AccessChk | Sysinternals | computed from vendor download |
| adexplorer | AD Explorer | Sysinternals | computed from vendor download |
| autoruns | Autoruns | Sysinternals | computed from vendor download |
| autologon | Autologon | Sysinternals | computed from vendor download |
| bginfo | BGInfo | Sysinternals | computed from vendor download |
| desktops | Desktops | Sysinternals | computed from vendor download |
| everything | Everything | Search | vendor checksums page + download |
| fastfetch | Fastfetch | System | computed from vendor download |
| handle | Handle | Sysinternals | computed from vendor download |
| keepassxc | KeePassXC | Security | computed from vendor download |
| mpchc | Media Player Classic HC | Media | computed from vendor download |
| powershell | PowerShell 7 | Development | computed from vendor download |
| procmon | Process Monitor | Sysinternals | computed from vendor download |
| processexplorer | Process Explorer | Sysinternals | computed from vendor download |
| pstools | PsTools | Sysinternals | computed from vendor download |
| rammap | RAMMap | Sysinternals | computed from vendor download |
| sdelete | SDelete | Sysinternals | computed from vendor download |
| sigcheck | Sigcheck | Sysinternals | computed from vendor download |
| strings | Strings | Sysinternals | computed from vendor download |
| tcpview | TCPView | Sysinternals | computed from vendor download |
| telegram | Telegram Desktop | Communication | computed from vendor download |
| vmmap | VMMap | Sysinternals | computed from vendor download |
| winobj | WinObj | Sysinternals | computed from vendor download |
| x64dbg | x64dbg | Development | computed from vendor download |
| zoomit | ZoomIt | Sysinternals | computed from vendor download |

See each recipe's `source.hashSource` for exactly where the pinned hash came
from and when it was verified. Vendor checksum files were preferred where the
vendor publishes them (e.g. voidtools); otherwise the hash was computed from
a fresh vendor download on the pin date and is re-verified on every build.

## Conventions

- **Sysinternals tools** are live-updated by Microsoft without version
  numbers, so the recipe `version` is the **pin date** (`YYYY.MM.DD`); bump it
  whenever you re-pin the hash. Their settings live under
  `HKCU\Software\Sysinternals\<Tool Name>`, so recipes list that key under
  `manifest.registry` — the launcher hijacks it and the tool's settings become
  portable. The key name is best-effort; a wrong name hijacks a nonexistent
  key and is harmless.
- **Nested archives** (KeePassXC, Telegram) reference the executable with its
  folder prefix, e.g. `Telegram/Telegram.exe`.
- **Env overrides** are added only where the app demonstrably writes outside
  its own folder (`TEMP`, `APPDATA`). Prefer no overrides when the app is
  already self-contained — the Trace mode (see README) is the tool for
  finding out.
- **Versions**: recipes pin an exact upstream version. To update, download the
  new release, update `source` (url/sha256/size) and `version`, rebuild, and
  bump the catalog.

## Verifying a recipe on a real machine

Recipe builds and package verification download third-party code — do that in
a **VM or Windows Sandbox**, not on a daily-driver machine. After installing
from a recipe-built package, run **Trace** (see README, "Writing a manifest
with Trace") and compare the report against the recipe's manifest: the trace
should show no unhandled host writes outside the declared surface.
