//! "Locked folder" icon for Quick-Locked folders that stay where they are.
//!
//! Explorer shows a custom folder icon when the folder has the ReadOnly or
//! System attribute and contains a `desktop.ini` naming the icon. The folder's
//! deny-Everyone ACE would stop Explorer reading that file, so `desktop.ini`
//! gets its own protected DACL (Everyone: read only). Explorer opens it by full
//! path (traverse checking is bypassed for normal users), while the folder
//! itself still can't be listed and nothing else inside can be opened.
//!
//! A `desktop.ini` the user already had is renamed to `desktop.ini.dirshield`
//! while locked (it stays protected by the deny ACE) and put back on unlock.
//! The icon file lives in DirShield's data folder, so no folder content is
//! needed to draw it.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::fsutil;

const ICON: &[u8] = include_bytes!("../icons/locked-folder.ico");
const INI: &str = "desktop.ini";
const BACKUP: &str = "desktop.ini.dirshield";

/// FILE_GENERIC_READ and FILE_ALL_ACCESS.
const READ_ONLY: u32 = 0x0012_0089;
const FULL: u32 = 0x001F_01FF;

/// Where the icon file is kept, beside the database.
pub fn icon_path(data_dir: &Path) -> PathBuf {
    data_dir.join("icons").join("locked-folder.ico")
}

fn ensure_icon(data_dir: &Path) -> Result<PathBuf> {
    let p = icon_path(data_dir);
    if fs::metadata(&p).map(|m| m.len() != ICON.len() as u64).unwrap_or(true) {
        fs::create_dir_all(p.parent().unwrap())?;
        fs::write(&p, ICON)?;
    }
    Ok(p)
}

fn ini_text(icon: &Path) -> Vec<u8> {
    let icon = fsutil::display_path(icon);
    let text = format!("[.ShellClassInfo]\r\nIconResource={icon},0\r\nIconFile={icon}\r\nIconIndex=0\r\nInfoTip=Locked by DirShield\r\n");
    // UTF-16LE with BOM so any path (Unicode user names) round-trips.
    let mut out = vec![0xFF, 0xFE];
    out.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    out
}

/// Adds the icon. Call before the folder's deny ACE is applied. Returns true
/// if the icon was set up (the caller then keeps ReadOnly on the folder).
pub fn apply(folder: &Path, data_dir: &Path) -> Result<bool> {
    if !cfg!(windows) {
        return Ok(false);
    }
    let ini = folder.join(INI);
    let backup = folder.join(BACKUP);
    if fs::symlink_metadata(&backup).is_ok() {
        return Ok(false); // leftover from an interrupted run; leave it alone
    }
    let icon = ensure_icon(data_dir)?;
    let had_ini = fs::symlink_metadata(&ini).is_ok();
    if had_ini {
        // A rename keeps the original's attributes (read-only renames fine).
        fsutil::rename_noreplace(&ini, &backup)?;
    }
    let written = (|| -> Result<()> {
        fs::write(&ini, ini_text(&icon))?;
        fsutil::set_attrs(&ini, fsutil::FILE_ATTRIBUTE_HIDDEN | fsutil::FILE_ATTRIBUTE_SYSTEM)?;
        crate::winsec::set_protected_everyone(&ini, READ_ONLY)
    })();
    if let Err(e) = written {
        let _ = delete_ini(&ini);
        if had_ini {
            let _ = fsutil::rename_noreplace(&backup, &ini);
        }
        return Err(e);
    }
    Ok(true)
}

fn delete_ini(ini: &Path) -> Result<()> {
    if fs::symlink_metadata(ini).is_err() {
        return Ok(());
    }
    let _ = crate::winsec::set_protected_everyone(ini, FULL);
    let _ = fsutil::set_attrs(ini, 0);
    fs::remove_file(ini)?;
    Ok(())
}

/// Tells Explorer to redraw folder icons. A targeted update for the folder is
/// not enough: Explorer keeps the cached plain-folder icon until it reloads.
pub fn refresh_explorer(folder: &Path) {
    fsutil::notify_shell_changed(folder);
    crate::shell::notify_assoc_changed();
}

/// Removes the icon and restores any original `desktop.ini`. Call after the
/// folder's deny ACE has been removed.
pub fn remove(folder: &Path) -> Result<()> {
    delete_ini(&folder.join(INI))?;
    let backup = folder.join(BACKUP);
    if fs::symlink_metadata(&backup).is_ok() {
        fsutil::rename_noreplace(&backup, &folder.join(INI))?;
    }
    Ok(())
}
