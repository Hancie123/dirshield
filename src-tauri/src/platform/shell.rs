//! Explorer context menu + launch-at-startup, both per-user (HKCU, no admin).
//!
//! Menu: HKCU\Software\Classes\Directory\shell\DirShield (cascading).
//! Each command is `"<exe>" --action <verb> "%1"`. Explorer passes the folder
//! as a single argv element; we never build a shell command line from it.
//! On Windows 11 these entries appear under "Show more options" (classic menu).
//!
//! Windows 11's top-level menu: builds signed with a code-signing certificate
//! also install `dirshield-shell.msix` and `dirshield_shell.dll` (see
//! `shell-ext/` and `scripts/build-sparse-package.ps1`). Registering that
//! sparse package for the current user (no admin) adds the same entries to
//! the top-level menu; the classic entries stay for Windows 10 and "Show more
//! options". Other builds simply don't ship the package.

use std::path::Path;

use crate::domain::error::{Error, Result};

pub const MENU_KEY: &str = r"Software\Classes\Directory\shell\DirShield";
#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const RUN_VALUE: &str = "DirShield";

pub use super::menu_spec::VERBS;

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ShellAction {
    pub action: String,
    pub path: Option<String>,
}

/// Parses `--action <verb> [path]` from argv (argv[0] excluded).
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Option<ShellAction> {
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--action" {
            let action = it.next()?;
            if !VERBS.iter().any(|(_, _, v)| *v == action) {
                return None;
            }
            // Strip a stray trailing quote produced by `"C:\"`-style argv quirks.
            let path = it.next().map(|p| p.trim_end_matches('"').to_string()).filter(|p| !p.is_empty());
            return Some(ShellAction { action, path });
        }
    }
    None
}

#[cfg(windows)]
fn exe() -> Result<std::path::PathBuf> {
    std::env::current_exe().map_err(Error::Io)
}

#[cfg(windows)]
pub fn register_context_menu() -> Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let exe = exe()?;
    let exe_s = crate::platform::fsutil::display_path(&exe);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    // Start clean so entries from older versions don't linger.
    let _ = hkcu.delete_subkey_all(MENU_KEY);
    let (root, _) = hkcu.create_subkey(MENU_KEY)?;
    root.set_value("MUIVerb", &"DirShield")?;
    root.set_value("Icon", &format!("\"{exe_s}\",0"))?;
    root.set_value("SubCommands", &"")?;
    for (key, label, verb) in VERBS {
        let (k, _) = root.create_subkey(format!(r"shell\{key}"))?;
        k.set_value("MUIVerb", label)?;
        k.set_value("Icon", &format!("\"{exe_s}\",0"))?;
        if super::menu_spec::SEPARATOR_BEFORE.contains(verb) {
            k.set_value("CommandFlags", &0x20u32)?; // separator before
        }
        let (cmd, _) = k.create_subkey("command")?;
        cmd.set_value("", &format!("\"{exe_s}\" --action {verb} \"%1\""))?;
    }
    notify_assoc_changed();
    // Best effort: the classic menu above already works everywhere.
    let _ = register_modern_menu();
    Ok(())
}

#[cfg(windows)]
pub fn unregister_context_menu() -> Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.delete_subkey_all(MENU_KEY) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    notify_assoc_changed();
    unregister_modern_menu()?;
    Ok(())
}

/// Package version for this build: the app version plus a 0 revision, as
/// `scripts/build-sparse-package.ps1` stamps it.
#[cfg(windows)]
fn sparse_version() -> [u16; 4] {
    let mut v = [0u16; 4];
    for (slot, part) in v.iter_mut().zip(env!("CARGO_PKG_VERSION").split(['.', '-', '+']).take(3)) {
        *slot = part.parse().unwrap_or(0);
    }
    v
}

#[cfg(windows)]
fn win(e: windows::core::Error) -> Error {
    Error::Win(e.message().to_string())
}

/// The installed menu package for this user, if any.
#[cfg(windows)]
fn find_sparse_package(pm: &windows::Management::Deployment::PackageManager) -> Result<Option<windows::ApplicationModel::Package>> {
    use super::menu_spec::SPARSE_PACKAGE_NAME;
    // Empty SID: the current user (needs no admin rights).
    for p in pm.FindPackagesByUserSecurityId(&windows::core::HSTRING::new()).map_err(win)? {
        if p.Id().and_then(|id| id.Name()).map(|n| n == SPARSE_PACKAGE_NAME).unwrap_or(false) {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

/// Registers the sparse package that adds DirShield to the top-level
/// Windows 11 menu, pointing it at this install folder. `Ok(false)`: not
/// applicable (Windows 10, or a build without the signed package). Quick when
/// this version is registered already.
#[cfg(windows)]
pub fn register_modern_menu() -> Result<bool> {
    use super::menu_spec::{HANDLER_DLL_FILE, SPARSE_MSIX_FILE};
    use windows::core::HSTRING;
    use windows::Foundation::Uri;
    use windows::Management::Deployment::{AddPackageOptions, PackageManager};

    if windows_build() < 22000 {
        return Ok(false);
    }
    let exe = exe()?;
    let Some(dir) = exe.parent() else { return Ok(false) };
    let msix = dir.join(SPARSE_MSIX_FILE);
    if !msix.is_file() || !dir.join(HANDLER_DLL_FILE).is_file() {
        return Ok(false);
    }
    // Settings saves re-register the menu: check the package once per run.
    if MODERN_REGISTERED.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(true);
    }
    let pm = PackageManager::new().map_err(win)?;
    if let Some(p) = find_sparse_package(&pm)? {
        let v = p.Id().and_then(|id| id.Version()).ok().map(|v| [v.Major, v.Minor, v.Build, v.Revision]);
        let here = p.EffectiveExternalPath().ok().map(|h| crate::platform::fsutil::path_key(Path::new(&h.to_string())));
        if v == Some(sparse_version()) && here == Some(crate::platform::fsutil::path_key(dir)) {
            MODERN_REGISTERED.store(true, std::sync::atomic::Ordering::Relaxed);
            return Ok(true);
        }
    }
    let opts = AddPackageOptions::new().map_err(win)?;
    opts.SetExternalLocationUri(&Uri::CreateUri(&HSTRING::from(file_uri(dir))).map_err(win)?).map_err(win)?;
    // Moves the registration to this folder/version even if it isn't newer.
    opts.SetForceUpdateFromAnyVersion(true).map_err(win)?;
    let op = pm.AddPackageByUriAsync(&Uri::CreateUri(&HSTRING::from(file_uri(&msix))).map_err(win)?, &opts).map_err(win)?;
    let result = op.get().map_err(win)?;
    if let Ok(code) = result.ExtendedErrorCode() {
        if code.is_err() {
            let text = result.ErrorText().map(|t| t.to_string()).unwrap_or_default();
            return Err(Error::Win(format!("Couldn't add DirShield to the Windows 11 menu: {text} ({code})")));
        }
    }
    MODERN_REGISTERED.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(true)
}

/// This process has registered (or found) the current menu package.
#[cfg(windows)]
static MODERN_REGISTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Removes the top-level Windows 11 menu package, if registered.
#[cfg(windows)]
pub fn unregister_modern_menu() -> Result<()> {
    use windows::Management::Deployment::PackageManager;
    MODERN_REGISTERED.store(false, std::sync::atomic::Ordering::Relaxed);
    if windows_build() < 22000 {
        return Ok(());
    }
    let pm = PackageManager::new().map_err(win)?;
    if let Some(p) = find_sparse_package(&pm)? {
        let full = p.Id().and_then(|id| id.FullName()).map_err(win)?;
        pm.RemovePackageAsync(&full).map_err(win)?.get().map_err(win)?;
    }
    Ok(())
}

/// Registered and pointing at this executable?
#[cfg(windows)]
pub fn context_menu_status() -> (bool, bool) {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(k) = hkcu.open_subkey(format!(r"{MENU_KEY}\shell\01lock\command")) else { return (false, false) };
    let cmd: String = k.get_value("").unwrap_or_default();
    let current = exe().map(|e| cmd.to_lowercase().contains(&crate::platform::fsutil::display_path(&e).to_lowercase())).unwrap_or(false);
    (true, current)
}

/// Makes Explorer reload icons (also used after a folder icon changes:
/// Explorer ignores per-item updates for `desktop.ini` icons).
#[cfg(windows)]
pub fn notify_assoc_changed() {
    use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None) };
}

#[cfg(windows)]
pub fn set_autostart(enabled: bool) -> Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (k, _) = hkcu.create_subkey(RUN_KEY)?;
    if enabled {
        let exe = crate::platform::fsutil::display_path(&exe()?);
        k.set_value(RUN_VALUE, &format!("\"{exe}\" --autostart"))?;
    } else {
        match k.delete_value(RUN_VALUE) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn autostart_enabled() -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    RegKey::predef(HKEY_CURRENT_USER).open_subkey(RUN_KEY).and_then(|k| k.get_value::<String, _>(RUN_VALUE)).is_ok()
}

/// Windows accent colour (#RRGGBB) from DWM, if available.
#[cfg(windows)]
pub fn accent_color() -> Option<String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let k = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Microsoft\Windows\DWM").ok()?;
    let v: u32 = k.get_value("AccentColor").ok()?; // 0xAABBGGRR
    Some(format!("#{:02x}{:02x}{:02x}", v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff))
}

/// Windows build number (Mica needs >= 22000).
#[cfg(windows)]
pub fn windows_build() -> u32 {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .and_then(|k| k.get_value::<String, _>("CurrentBuildNumber"))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

#[cfg(not(windows))]
pub fn notify_assoc_changed() {}

#[cfg(not(windows))]
pub fn register_context_menu() -> Result<()> {
    Err(Error::Invalid("Explorer integration is only available on Windows".into()))
}
#[cfg(not(windows))]
pub fn unregister_context_menu() -> Result<()> {
    Ok(())
}
#[cfg(not(windows))]
pub fn context_menu_status() -> (bool, bool) {
    (false, false)
}
#[cfg(not(windows))]
pub fn register_modern_menu() -> Result<bool> {
    Ok(false)
}
#[cfg(not(windows))]
pub fn unregister_modern_menu() -> Result<()> {
    Ok(())
}
#[cfg(not(windows))]
pub fn set_autostart(_e: bool) -> Result<()> {
    Ok(())
}
#[cfg(not(windows))]
pub fn autostart_enabled() -> bool {
    false
}
#[cfg(not(windows))]
pub fn accent_color() -> Option<String> {
    None
}
#[cfg(not(windows))]
pub fn windows_build() -> u32 {
    0
}

pub fn is_valid_shell_path(p: &str) -> bool {
    Path::new(p).is_absolute()
}

/// `file:///` URI for a local path (Windows.Foundation.Uri takes no plain paths).
pub fn file_uri(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    let s = s.strip_prefix("//?/").unwrap_or(&s);
    let mut out = String::from("file:///");
    for b in s.trim_start_matches('/').bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `--register-shell-ext` / `--unregister-shell-ext`, run by the installer:
/// add or remove the Windows 11 menu package, then exit. Returns the exit
/// code, or `None` for any other command line.
pub fn installer_command<I: IntoIterator<Item = String>>(args: I) -> Option<i32> {
    let r = match args.into_iter().next()?.as_str() {
        "--register-shell-ext" => register_modern_menu().map(|_| ()),
        "--unregister-shell-ext" => unregister_modern_menu(),
        _ => return None,
    };
    Some(if r.is_ok() { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_actions_safely() {
        assert_eq!(
            parse_args(v(&["--action", "quick-lock", r"C:\My Files (2024)\Ünïcode & ;rm -rf"])),
            Some(ShellAction { action: "quick-lock".into(), path: Some(r"C:\My Files (2024)\Ünïcode & ;rm -rf".into()) })
        );
        assert_eq!(parse_args(v(&["--action", "lock", r"C:\A"])), Some(ShellAction { action: "lock".into(), path: Some(r"C:\A".into()) }));
        assert_eq!(parse_args(v(&["--action", "evil", "x"])), None);
        assert_eq!(parse_args(v(&["--autostart"])), None);
        assert_eq!(parse_args(v(&["--action", "settings"])), Some(ShellAction { action: "settings".into(), path: None }));
    }

    #[test]
    fn file_uris() {
        assert_eq!(file_uri(Path::new(r"C:\Users\me\AppData\Local\DirShield")), "file:///C:/Users/me/AppData/Local/DirShield");
        assert_eq!(file_uri(Path::new(r"C:\Program Files\Dir Shield\dirshield-shell.msix")), "file:///C:/Program%20Files/Dir%20Shield/dirshield-shell.msix");
        assert_eq!(file_uri(Path::new(r"\\?\D:\Ünï#%")), "file:///D:/%C3%9Cn%C3%AF%23%25");
    }

    #[test]
    fn installer_commands_only() {
        assert_eq!(installer_command(v(&["--action", "lock"])), None);
        assert_eq!(installer_command(v(&[])), None);
    }

    /// The package manifest must declare what the handler and app expect.
    #[test]
    fn sparse_manifest_matches_menu_spec() {
        use crate::platform::menu_spec::*;
        let m = include_str!("../../windows/sparse/AppxManifest.xml");
        assert!(m.contains(&format!(r#"Identity Name="{SPARSE_PACKAGE_NAME}""#)));
        assert_eq!(m.matches(&format!(r#"Clsid="{HANDLER_CLSID}""#)).count(), 1);
        assert_eq!(m.matches(&format!(r#"Class Id="{HANDLER_CLSID}" Path="{HANDLER_DLL_FILE}""#)).count(), 1);
        assert!(m.contains(r#"Executable="dirshield.exe""#));
        for f in [SPARSE_MSIX_FILE, HANDLER_DLL_FILE] {
            assert!(include_str!("../../../scripts/build-sparse-package.ps1").contains(f), "{f}");
        }
    }
}
