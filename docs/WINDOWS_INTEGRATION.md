# Windows integration

## File Explorer context menu

Registered **per user** (no admin) under `HKCU\Software\Classes\Directory\shell\DirShield` as a cascading menu:

| Entry | Command |
|---|---|
| Quick Lock | `"<exe>" --action quick-lock "%1"` |
| Secure Lock (encrypt) | `"<exe>" --action secure-lock "%1"` |
| Unlock Folder | `"<exe>" --action unlock "%1"` |
| Unhide Folder | `"<exe>" --action unhide "%1"` |
| DirShield Settings | `"<exe>" --action settings "%1"` |

* Explorer passes the folder as one argv element; DirShield never builds a shell command from it, so spaces, Unicode, parentheses, `&`, `;` and long paths are safe. Unknown verbs are rejected.
* Works with the app closed: the exe starts, asks for the master password, then runs the action. If DirShield is already running, `tauri-plugin-single-instance` forwards the action to the running window.
* Registered by the installer (NSIS hook) and toggleable in Settings. Removed by the uninstaller. Settings reports whether the registration points to the current exe.

### Windows 11 modern menu

The top-level Windows 11 menu only shows commands from packaged apps implementing `IExplorerCommand` (a COM server DLL plus an MSIX/sparse package with identity, which needs a code-signing certificate). That is out of scope for v1.0; the entries appear under **Show more options** (Shift+F10). The classic registration is the reliable fallback on Windows 10 and 11. Planned path: sparse package + `IExplorerCommand` DLL that launches the same `--action` command line.

## Quick Lock permissions

`winsec.rs` adds a single explicit ACE: **Deny Everyone** — read data/list, write/add file, append/add subfolder, read/write EA, execute/traverse, delete child, delete — inherited by every child (`SUB_CONTAINERS_AND_OBJECTS_INHERIT`). Effects (covered by tests): listing, opening files by full path and deleting all fail.

Recoverability: the owner keeps implicit `READ_CONTROL`/`WRITE_DAC`, so DirShield (same user) can always remove the ACE without elevation; administrators can take ownership. Existing ACEs and the owner are never modified, so removing our ACE restores the original permissions. Manual fallback: `icacls "<folder>" /remove:d *S-1-1-0`.

Limits (shown in the UI): administrators, another OS, offline disk access or backup-privileged software can bypass Quick Lock.

## Windows Search

* `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` on locked folders, vault roots and DirShield's data dir.
* Crawl-scope exclusion via `ISearchManager → ISearchCatalogManager("SystemIndex") → ISearchCrawlScopeManager::AddUserScopeRule(…, fInclude=FALSE)`. Writing rules usually requires administrator rights; DirShield attempts it without elevation and treats failure as non-fatal.
* Quick-Locked folders deny the indexer (SYSTEM is part of Everyone) and are moved under `%LOCALAPPDATA%`, which is excluded from the default index.
* Secure Lock vault directories contain only random names and ciphertext.

Previously indexed items disappear when Windows re-crawls; DirShield does not promise immediate removal, nor protection from third-party indexers, backups or cloud-sync copies made before locking.

## Visual integration

* Native title bar and window controls (snap layouts work); Mica backdrop on build ≥ 22000 via `set_effects(Mica)`; opaque Fluent surfaces on Windows 10.
* Light/dark follow Windows (or a manual choice in Settings); the Windows accent colour is read from `HKCU\Software\Microsoft\Windows\DWM\AccentColor`.
* Native folder pickers (`IFileOpenDialog` via `tauri-plugin-dialog`).

## Launch at startup

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\DirShield = "<exe>" --autostart` (starts minimized).

## Administrator rights

None are required. The only feature that benefits from elevation is the Windows Search crawl-scope rule, which is optional.

## Virtual drive (investigation)

Mounting a vault read-only as a drive needs a user-mode file-system driver; **WinFsp** (GPLv3 with FLOSS exception / commercial licence) is the practical option on Windows (`winfsp` Rust bindings). The vault format already supports it: the manifest maps paths to blobs and chunks are independently decryptable with random access by chunk index (`offset = 28 + i·(chunk+16)`). Not implemented in v1.0 because it requires shipping/installing the WinFsp driver (admin) and careful cache handling; the UI states this and uses Restore instead.
