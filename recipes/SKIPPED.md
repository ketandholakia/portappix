# Skipped apps

Popular apps that were considered for recipes but **cannot be wrapped safely
with the current recipe format**, and why. Each entry names the blocking
reason; when the vendor ships an official portable zip archive, a recipe can
be added following `README.md`.

## Installer-only on Windows (no official portable zip)

| App | Reason |
| --- | --- |
| VLC media player | Vendor ships Windows installers only; no official portable zip. |
| Audacity | Installer-only; no official portable zip. |
| qBittorrent | Installer-only; no official portable zip. |
| Google Chrome | Installer-only (Google does not distribute a portable zip). |
| Spotify | Installer-only; the app self-updates into `%APPDATA%`. |
| Discord | Installer-only; the app self-updates into `%APPDATA%`. |
| Steam | Installer-only; deep system integration (services, drivers). |
| WhatsApp | Microsoft Store package only; no standalone portable build. |

## Portable archive is not a zip

| App | Reason |
| --- | --- |
| 7-Zip | The GUI app ships as an installer; the "extra" package is a `.7z`, which Portappix cannot extract (zip only). The console tools are 7z too. |
| Notepad++ | Official portable builds are `.7z` archives, not zips. |
| Git for Windows | PortableGit is a self-extracting `.7z.exe`, not a zip. |
| OBS Studio | Zip builds are officially offered for some versions, but the zip is only announced per-release and without published checksums; re-verify availability before adding a recipe. |

## Third-party repacks only

| App | Reason |
| --- | --- |
| LibreOffice (portable) | The vendor ships installers; the well-known portable build is a PortableApps.com repack, which is third-party packaging of the binaries. Recipes must reference vendor URLs. |
| many "portable" aggregators (PortableApps.com, FC Portable, etc.) | Same rule: vendor URLs only. |

## Considered, not yet pinned

These apps **are** wrappable in principle (official portable zip, vendor URL),
but no recipe exists yet because the hash has not been pinned and verified on
a vendor checksum page or a fresh download:

| App | Where the zip lives |
| --- | --- |
| Visual Studio Code | `https://update.code.visualstudio.com/<version>/win32-x64/stable` (no published per-file hash; pin by download) |
| Blender | `https://download.blender.org/release/` (vendor publishes checksums per release) |
| Node.js | `https://nodejs.org/dist/` (vendor publishes `SHASUMS256.txt`) |
| IrfanView | `https://www.irfanview.com/` (zip build exists; plugin zip is separate) |
| Sublime Text | `https://download.sublimetext.com/` (zip build exists) |

Pull requests adding any of these are welcome: pin the hash from the vendor
checksums page when one exists, otherwise from a fresh download of the exact
vendor URL, and fill in `source.hashSource` with where it came from.
