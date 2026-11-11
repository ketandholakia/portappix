# Real Apps Validation Checklist

This guide provides step-by-step, reproducible manual test procedures for the three primary real-world applications evaluated with Portappix: **Notepad++**, **SumatraPDF**, and **WinSCP**.

Execute these verification steps inside a clean VM (Hyper-V / VirtualBox) or Windows Sandbox before approving a release.

---

## 1. Notepad++

### Download & Metadata
- **Official Download URL:** https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.9/npp.8.6.9.portable.x64.zip
- **License / Redistribution:** GPL-2.0 (vendor-link-only in signed catalog)
- **Primary Executable:** `notepad++.exe`
- **Host Storage Targets:**
  - AppData folder: `%APPDATA%\Notepad++`
  - Registry keys: `HKCU\Software\Notepad++`

### Manifest (`Apps\notepadplusplus\app.json`)
```json
{
  "schemaVersion": 1,
  "id": "notepadplusplus",
  "name": "Notepad++",
  "version": "8.6.9",
  "category": "Development",
  "exe": "notepad++.exe",
  "args": "",
  "env": {},
  "junctions": [
    {
      "host": "%APPDATA%\\Notepad++",
      "target": "{data}\\AppData"
    }
  ],
  "registry": [
    "HKCU\\Software\\Notepad++"
  ]
}
```

### Verification Procedure
1. **Initial State Check:**
   - Verify `%APPDATA%\Notepad++` does not exist on the host machine.
   - Verify `HKCU\Software\Notepad++` does not exist in the host registry.
2. **First Run & Configuration:**
   - Launch Notepad++ via Portappix: `Launcher.exe --run notepadplusplus`.
   - In Notepad++, open **Settings -> Preferences... -> Dark Mode**.
   - Enable **Dark mode** and select the **Dark Mode (Default)** theme.
   - Open a new tab, type `Portappix Isolation Verification`, and close Notepad++.
3. **Isolation Verification:**
   - **Data Directory:** Inspect `Data\notepadplusplus\AppData\config.xml`. Verify that dark mode settings and recent session data are saved here.
   - **Host AppData Check:** Verify `%APPDATA%\Notepad++` on the host does NOT exist (junction was safely unmounted and removed by launcher cleanup).
   - **Host Registry Check:** Verify `HKCU\Software\Notepad++` does NOT exist in the host registry (exported to `Data\notepadplusplus\registry.reg` and cleared).
4. **Persistence Verification:**
   - Relaunch: `Launcher.exe --run notepadplusplus`.
   - Verify Notepad++ starts in dark mode and restores the previous session text `Portappix Isolation Verification`.
   - Exit Notepad++.

---

## 2. SumatraPDF

### Download & Metadata
- **Official Download URL:** https://www.sumatrapdfreader.org/dl/rel/3.5.2/SumatraPDF-3.5.2-64.zip
- **License / Redistribution:** GPL-3.0 (vendor-link-only)
- **Primary Executable:** `SumatraPDF.exe`
- **Host Storage Targets:**
  - AppData folder: `%LOCALAPPDATA%\SumatraPDF`
  - Configuration file: `SumatraPDF-settings.txt` (stored under `%LOCALAPPDATA%\SumatraPDF`)

### Manifest (`Apps\sumatrapdf\app.json`)
```json
{
  "schemaVersion": 1,
  "id": "sumatrapdf",
  "name": "SumatraPDF",
  "version": "3.5.2",
  "category": "Productivity",
  "exe": "SumatraPDF.exe",
  "args": "",
  "env": {},
  "junctions": [
    {
      "host": "%LOCALAPPDATA%\\SumatraPDF",
      "target": "{data}\\LocalAppData"
    }
  ],
  "registry": []
}
```

### Verification Procedure
1. **Initial State Check:**
   - Verify `%LOCALAPPDATA%\SumatraPDF` does not exist on the host.
2. **First Run & Configuration:**
   - Launch SumatraPDF: `Launcher.exe --run sumatrapdf`.
   - Open **Settings -> Options...**.
   - Change **Default Zoom** to `150%` and uncheck **Check for updates**.
   - Click **OK**, then close SumatraPDF.
3. **Isolation Verification:**
   - **Data Directory:** Inspect `Data\sumatrapdf\LocalAppData\SumatraPDF-settings.txt`. Verify `Zoom = 150.00` and `CheckForUpdates = false` are recorded inside the file.
   - **Host AppData Check:** Verify `%LOCALAPPDATA%\SumatraPDF` on the host does NOT exist.
4. **Persistence Verification:**
   - Relaunch: `Launcher.exe --run sumatrapdf`.
   - Open **Settings -> Options...** and verify Default Zoom is still `150%`.
   - Exit SumatraPDF.

---

## 3. WinSCP

### Download & Metadata
- **Official Download URL:** https://winscp.net/download/WinSCP-6.3.5-Portable.zip
- **License / Redistribution:** GPL-3.0 (vendor-link-only)
- **Primary Executable:** `WinSCP.exe`
- **Host Storage Targets:**
  - Registry keys: `HKCU\Software\Martin Prikryl\WinSCP 2`
  - AppData folder: `%APPDATA%\WinSCP`

### Manifest (`Apps\winscp\app.json`)
```json
{
  "schemaVersion": 1,
  "id": "winscp",
  "name": "WinSCP",
  "version": "6.3.5",
  "category": "Network",
  "exe": "WinSCP.exe",
  "args": "",
  "env": {},
  "junctions": [
    {
      "host": "%APPDATA%\\WinSCP",
      "target": "{data}\\AppData"
    }
  ],
  "registry": [
    "HKCU\\Software\\Martin Prikryl\\WinSCP 2"
  ]
}
```

### Verification Procedure
1. **Initial State Check:**
   - Verify `HKCU\Software\Martin Prikryl` does not exist in host registry.
   - Verify `%APPDATA%\WinSCP` does not exist on host.
2. **First Run & Configuration:**
   - Launch WinSCP: `Launcher.exe --run winscp`.
   - In Login dialog, configure a new Site:
     - File protocol: `SFTP`
     - Host name: `test.portappix.local`
     - User name: `portappix_tester`
   - Click **Save**, name the site `PortappixTestSite`.
   - Open **Preferences -> Storage** and confirm storage is set to Registry (the default for standard WinSCP).
   - Close WinSCP.
3. **Isolation Verification:**
   - **Data Directory:** Inspect `Data\winscp\registry.reg`. Verify the exported registry file contains `[HKEY_CURRENT_USER\Software\Martin Prikryl\WinSCP 2\Sessions\PortappixTestSite]` with `HostName="test.portappix.local"` and `UserName="portappix_tester"`.
   - **Host Registry Check:** Verify `HKCU\Software\Martin Prikryl` does NOT exist in host registry.
   - **Host AppData Check:** Verify `%APPDATA%\WinSCP` does NOT exist on the host.
4. **Persistence Verification:**
   - Relaunch: `Launcher.exe --run winscp`.
   - Verify `PortappixTestSite` appears in the stored site tree with hostname `test.portappix.local`.
   - Exit WinSCP.
