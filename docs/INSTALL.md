# Building and installing DirShield

## Install (end users)

1. Run `DirShield_1.0.0_x64-setup.exe` (per-user install, no admin prompt). It installs WebView2 if missing (Windows 11 already has it).
2. The installer adds a Start Menu shortcut and the File Explorer right-click menu.
3. Start DirShield, create your master password and **save the recovery key**.

The installer is unsigned, so SmartScreen may warn ("More info → Run anyway"). Sign it with your certificate for distribution (`bundle.windows.certificateThumbprint` in `tauri.conf.json`).

### Uninstall

Settings → Apps → DirShield → Uninstall. The uninstaller removes the program, the context menu and the startup entry. It **never** deletes `%LOCALAPPDATA%\DirShield` (database, vaults, Quick-Locked folders) and tells you where they are. Unlock folders before uninstalling if you no longer need protection; reinstall to regain access. Delete that folder manually only after everything is unlocked.

## Development prerequisites

| Tool | Tested version |
|---|---|
| Windows 10/11 x64 | 11 build 26300 |
| Node.js | 24 |
| Yarn | 1.22 |
| Rust (MSVC) | 1.99 stable |
| Visual Studio Build Tools — "Desktop development with C++" | 2026 |
| Windows SDK | 10.0.26100 |
| WebView2 Runtime | included with Windows 11 |

## Build

```powershell
yarn install
yarn tauri:dev          # development (hot reload)
yarn tauri:build        # release exe + installer
cargo test --manifest-path src-tauri/Cargo.toml
```

Outputs:
* `src-tauri/target/release/dirshield.exe`
* `src-tauri/target/release/bundle/nsis/DirShield_1.0.0_x64-setup.exe`

Icons are generated from `src-tauri/app-icon.svg` with `yarn icons`.

## Safe testing

Use a throwaway data directory and generated folders:

```powershell
$env:DIRSHIELD_DATA_DIR = "D:\dirshield-test-data"
yarn tauri:dev
```

Folders under `%USERPROFILE%\AppData` (including `%TEMP%`) are deliberately refused as lock targets; put test folders elsewhere, such as `D:\dirshield-test`.

## Large-folder testing

Generate data with PowerShell (fast, no RAM pressure):

```powershell
$d = "D:\dirshield-test\big"; New-Item -ItemType Directory -Force $d | Out-Null
fsutil file createnew "$d\zero-100GB.bin" 107374182400            # sparse/zero (fast)
# realistic random data, 10 GB:
$buf = New-Object byte[] (4MB); $r = [Random]::new(); $f = [IO.File]::OpenWrite("$d\random-10GB.bin")
1..2560 | % { $r.NextBytes($buf); $f.Write($buf, 0, $buf.Length) }; $f.Close()
# many small files:
1..200000 | % { Set-Content "$d\small\f$_.txt" $_ }
```

Watch the Active operations page for speed/ETA, use Pause/Resume/Cancel, and kill the process mid-way (Task Manager) to exercise crash recovery. Memory should stay flat (≈ tens of MB) regardless of size. Each byte is read twice during encryption (encrypt + verify) and three times during restore (decrypt, then on-disk verification), so expect throughput of roughly a third to half of raw disk speed. Free space needed ≈ folder size + 0.0004 %.
