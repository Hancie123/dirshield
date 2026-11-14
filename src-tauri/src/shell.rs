//! Explorer context menu + launch-at-startup, both per-user (HKCU, no admin).
//!
//! Menu: HKCU\Software\Classes\Directory\shell\DirShield (cascading).
//! Each command is `"<exe>" --action <verb> "%1"`. Explorer passes the folder
//! as a single argv element; we never build a shell command line from it.
//! On Windows 11 these entries appear under "Show more options" (classic menu);
//! see docs/WINDOWS_INTEGRATION.md for the modern-menu (IExplorerCommand) notes.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

pub const MENU_KEY: &str = r"Software\Classes\Directory\shell\DirShield";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "DirShield";

/// (subkey, label, verb). `lock` locks in place and keeps the folder visible;
/// `quick-lock` (kept for older registrations) locks and hides it.
pub const VERBS: &[(&str, &str, &str)] = &[
    ("01lock", "Lock Folder", "lock"),
    ("02lockhide", "Lock and Hide Folder", "quick-lock"),
    ("03secure", "Secure Lock (encrypt)", "secure-lock"),
    ("04unlock", "Unlock Folder", "unlock"),
    ("05unhide", "Unhide Folder", "unhide"),
    ("06settings", "DirShield Settings", "settings"),
];

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

fn exe() -> Result<PathBuf> {
    std::env::current_exe().map_err(Error::Io)
}

#[cfg(windows)]
pub fn register_context_menu() -> Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let exe = exe()?;
    let exe_s = crate::fsutil::display_path(&exe);
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
        if *verb == "settings" {
            k.set_value("CommandFlags", &0x20u32)?; // separator before
        }
        let (cmd, _) = k.create_subkey("command")?;
        cmd.set_value("", &format!("\"{exe_s}\" --action {verb} \"%1\""))?;
    }
    notify_assoc_changed();
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
    let current = exe().map(|e| cmd.to_lowercase().contains(&crate::fsutil::display_path(&e).to_lowercase())).unwrap_or(false);
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
        let exe = crate::fsutil::display_path(&exe()?);
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
}
