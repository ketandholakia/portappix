# Real-app checklist (manual, before every release)

Walk this list **by hand** in a clean VM / Windows Sandbox before each release.
Nothing here is downloaded automatically: fetch each app yourself from the
official page, package it (see `recipes\`), trace it with Trace mode if its
behaviour is unknown, and drive it through the launcher.

Legend for *Category coverage*:

- **AppData** — writes under `%APPDATA%` / `%LOCALAPPDATA%` / `%TEMP%`
- **Registry** — writes under `HKCU\Software\<vendor>\<app>`
- **ProgramData** — writes under `C:\ProgramData\<name>` (junction candidate)
- **Stub launcher** — spawns and re-spawns child processes (updaters, helpers)
- **Elevation** — requests UAC elevation for at least one flow

Redistribution status is what **we may ship** in the signed catalog:

- `redistribute` — the vendor license lets us re-zip and re-host the official
  archive (rare; verify the exact license text before flipping a recipe to
  this).
- `vendor-link-only` — we only pin the official URL + SHA-256 and the launcher
  downloads/extracts the vendor file directly. **Default.**
- `no-portable` — no sane portable build exists; documented in
  `recipes\SKIPPED.md`, listed here only for completeness.

| # | App | Official download page | License redistribution | Categories | Manifest notes | Pass | Fail | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 7-Zip | https://www.7-zip.org/download.html | vendor-link-only (LGPL+unRAR) | AppData, Registry | `.7z` sfx archive; `exe` = `App\7zFM.exe`; add `LANG`? no — env `TEMP` only | ☐ | ☐ | |
| 2 | Notepad++ | https://notepad-plus-plus.org/downloads/ | vendor-link-only (GPL-2.0) | AppData, Registry | zip package; `%APPDATA%\Notepad++` → `{data}\AppData` | ☐ | ☐ | |
| 3 | IrfanView | https://www.irfanview.com/ (zips from `irfanview.net`) | vendor-link-only (free for non-commercial; note in recipe) | AppData, Registry | exe-sfx installer NOT portable; use the zip where offered | ☐ | ☐ | |
| 4 | SumatraPDF | https://www.sumatrapdfreader.org/download-free-pdf-viewer | vendor-link-only (GPL-3.0) | AppData | single-exe zip; `%LOCALAPPDATA%\SumatraPDF` | ☐ | ☐ | |
| 5 | VLC | https://www.videolan.org/vlc/download-windows.html | vendor-link-only (GPL-2.0+) | AppData, ProgramData, Stub launcher | 7z portable; VLC writes `%APPDATA%\vlc` and `vlc-qt-interface.ini` | ☐ | ☐ | |
| 6 | Everything | https://www.voidtools.com/downloads/ | vendor-link-only (proprietary, free) | AppData, Registry, Stub launcher | zip; service/elevation flows must stay off in the manifest | ☐ | ☐ | |
| 7 | ShareX | https://getsharex.com/downloads | vendor-link-only (GPL-3.0) | AppData, Registry | zip; `%APPDATA%\ShareX` | ☐ | ☐ | |
| 8 | WinSCP | https://winscp.net/eng/downloads.php | vendor-link-only (GPL-3.0) | AppData, Registry | portable zip; `-ini` not needed with env redirect | ☐ | ☐ | |
| 9 | PuTTY | https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html | vendor-link-only (MIT) | Registry | single exe set; `HKCU\Software\SimonTatham\PuTTY` | ☐ | ☐ | |
| 10 | FileZilla | https://filezilla-project.org/download.php?type=client | vendor-link-only (GPL-2.0+) | AppData, Registry | zip; `%APPDATA%\FileZilla` | ☐ | ☐ | |
| 11 | KeePassXC | https://keepassxc.org/download/ | vendor-link-only (GPL-3.0) | AppData, Stub launcher | msi only officially — use the portable zip from the releases page; document in NOTES | ☐ | ☐ | |
| 12 | foobar2000 | https://www.foobar2000.org/download | vendor-link-only (freeware) | AppData, Registry | installer exe-sfx; prefer the zip build | ☐ | ☐ | |
| 13 | HxD | https://mh-nexus.de/en/hxd/ | vendor-link-only (freeware) | Registry, AppData | zip installer; writes `HKCU\Software\HxD` | ☐ | ☐ | |
| 14 | Greenshot | https://getgreenshot.org/downloads/ | vendor-link-only (GPL-3.0) | AppData, Registry | zip; `%APPDATA%\Greenshot` | ☐ | ☐ | |
| 15 | qBittorrent | https://www.qbittorrent.org/download.php | vendor-link-only (GPL-2.0+) | AppData, ProgramData | zip; `%APPDATA%\qBittorrent` | ☐ | ☐ | |
| 16 | Firefox (portable zip) | https://www.mozilla.org/firefox/all/ | vendor-link-only (MPL-2.0) | AppData, Stub launcher | zip; needs `APPDATA`/`LOCALAPPDATA` redirect; auto-update spawns children | ☐ | ☐ | |
| 17 | WinMerge | https://winmerge.org/downloads/ | vendor-link-only (GPL-2.0+) | AppData, Registry | zip; `%APPDATA%\WinMerge` | ☐ | ☐ | |
| 18 | Inkscape (portable) | https://inkscape.org/release/ | vendor-link-only (GPL-3.0) | AppData, Registry | 7z; `%APPDATA%\inkscape` | ☐ | ☐ | |
| 19 | OBS Studio (portable zip) | https://obsproject.com/download | vendor-link-only (GPL-2.0+) | AppData, Stub launcher | zip; `%APPDATA%\obs-studio`; updater children | ☐ | ☐ | |
| 20 | VS Code (portable zip) | https://code.visualstudio.com/Download | vendor-link-only (MIT) | AppData | zip; `--user-data-dir` alternative; `%APPDATA%\Code` | ☐ | ☐ | |

Skipped on purpose (see `recipes\SKIPPED.md` for the full list and reasons):

- **LibreOffice** — no vendor portable build; the "PortableApps.com" repackage
  is a third-party launcher, not an official archive.
- **Git portable / Python embeddable / Node zip / ffmpeg / GIMP portable** —
  tracked in `recipes\` (CLI/tooling apps) and exercised via the recipe build,
  not this interactive list.

How to run one app by hand (VM only):

1. Package the vendor download with `tools\build_recipe.py` (Part 4) or copy
   the app folder into `Apps\<id>\` and write `app.json`.
2. Trace it once: `Launcher.exe --trace <app-id>` (writes to the host — VM!).
3. Launch normally from the tray; use the app for a few minutes.
4. Check `Data\<id>` grew as expected and the host did not: compare with the
   snapshot from the suite or by hand.
5. Tick Pass/Fail in the table and put a one-line note (crashes, updater
   prompts, tray behaviour).
