//! Windows file-system helpers. Rust's std already handles long paths for its
//! own APIs; for direct Win32 calls we build `\\?\` verbatim paths ourselves.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

pub const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
pub const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x2000;
/// Attributes we record and restore. Everything else (compression, sparse,
/// reparse, cloud placeholders...) is a property of the storage, not the data.
pub const RESTORABLE_ATTRS: u32 = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

/// Display form of a path: strips `\\?\` / `\\?\UNC\` prefixes added by canonicalize.
pub fn display_path(p: &Path) -> String {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s.into_owned()
    }
}

/// Canonical, absolute, display-form path for user input.
pub fn normalize(p: &Path) -> Result<PathBuf> {
    let c = fs::canonicalize(p).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::NotFound(format!("{}", p.display())),
        _ => Error::Io(e),
    })?;
    Ok(PathBuf::from(display_path(&c)))
}

/// Case-insensitive path equality / containment (NTFS is case-insensitive by default).
pub fn path_key(p: &Path) -> String {
    let mut s = display_path(p).replace('/', "\\").to_lowercase();
    while s.ends_with('\\') && s.len() > 3 {
        s.pop();
    }
    s
}

pub fn is_same_or_inside(child: &Path, parent: &Path) -> bool {
    let c = path_key(child);
    let p = path_key(parent);
    c == p || c.starts_with(&format!("{}\\", p.trim_end_matches('\\')))
}

pub fn mtime_ns(meta: &fs::Metadata) -> Option<i64> {
    meta.modified().ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_nanos() as i64)
}

pub fn system_time(ns: i64) -> Option<SystemTime> {
    if ns < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_nanos(ns as u64))
}

#[cfg(windows)]
pub fn attrs(meta: &fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes()
}
/// Off Windows only the read-only flag has a counterpart: "no write bits set".
#[cfg(not(windows))]
pub fn attrs(meta: &fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        FILE_ATTRIBUTE_READONLY
    } else {
        0
    }
}

#[cfg(windows)]
pub fn wide(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let s = display_path(p).replace('/', "\\");
    let v = if let Some(rest) = s.strip_prefix(r"\\") {
        format!(r"\\?\UNC\{rest}")
    } else if s.len() >= 2 && s.as_bytes()[1] == b':' {
        format!(r"\\?\{s}")
    } else {
        s
    };
    OsStr::new(&v).encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
pub fn wide_str(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
pub fn set_attrs(p: &Path, a: u32) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_FLAGS_AND_ATTRIBUTES};
    let w = wide(p);
    // FILE_ATTRIBUTE_NORMAL (0x80) must be used alone when clearing everything.
    let a = if a == 0 { 0x80 } else { a };
    unsafe { SetFileAttributesW(PCWSTR(w.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(a)) }.map_err(|e| Error::Win(format!("SetFileAttributes: {e}")))
}
/// Off Windows only the read-only flag is applied: read-only clears every write
/// bit; writable restores the owner's write bit. Links are never followed.
#[cfg(not(windows))]
pub fn set_attrs(p: &Path, a: u32) -> Result<()> {
    let meta = fs::symlink_metadata(p)?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    let mut perm = meta.permissions();
    let readonly = a & FILE_ATTRIBUTE_READONLY != 0;
    if perm.readonly() == readonly {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = perm.mode();
        perm.set_mode(if readonly { mode & !0o222 } else { mode | 0o200 });
    }
    #[cfg(not(unix))]
    #[allow(clippy::permissions_set_readonly_false)]
    perm.set_readonly(readonly);
    fs::set_permissions(p, perm)?;
    Ok(())
}

pub fn get_attrs(p: &Path) -> Result<u32> {
    Ok(attrs(&fs::symlink_metadata(p)?))
}

/// Sets the modification time of a file or directory.
pub fn set_mtime(p: &Path, ns: Option<i64>) -> Result<()> {
    let Some(t) = ns.and_then(system_time) else { return Ok(()) };
    let mut o = fs::OpenOptions::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.access_mode(0x100 /* FILE_WRITE_ATTRIBUTES */).custom_flags(0x0200_0000 /* FILE_FLAG_BACKUP_SEMANTICS (dirs) */);
    }
    #[cfg(not(windows))]
    o.write(true);
    let f = o.open(p)?;
    f.set_modified(t)?;
    Ok(())
}

/// Bytes available to the caller on the volume containing `p`.
#[cfg(windows)]
pub fn free_space(p: &Path) -> Result<u64> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut probe = p.to_path_buf();
    while !probe.exists() {
        match probe.parent() {
            Some(pp) => probe = pp.to_path_buf(),
            None => break,
        }
    }
    let w = wide(&probe);
    let mut avail = 0u64;
    unsafe { GetDiskFreeSpaceExW(PCWSTR(w.as_ptr()), Some(&mut avail), None, None) }.map_err(|e| Error::Win(format!("GetDiskFreeSpaceEx: {e}")))?;
    Ok(avail)
}
#[cfg(not(windows))]
pub fn free_space(_p: &Path) -> Result<u64> {
    Ok(u64::MAX)
}

/// Rename that fails instead of replacing an existing target, and fails
/// instead of silently copying across volumes.
#[cfg(windows)]
pub fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
    let f = wide(from);
    let t = wide(to);
    unsafe { MoveFileExW(PCWSTR(f.as_ptr()), PCWSTR(t.as_ptr()), MOVEFILE_WRITE_THROUGH) }.map_err(|e| std::io::Error::from_raw_os_error(e.code().0 & 0xFFFF))
}
#[cfg(not(windows))]
pub fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    if to.exists() {
        return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
    }
    fs::rename(from, to)
}

/// Volume mount point (e.g. `C:\`) for a path.
#[cfg(windows)]
pub fn volume_root(p: &Path) -> String {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetVolumePathNameW;
    let w = wide(p);
    let mut buf = [0u16; 1024];
    if unsafe { GetVolumePathNameW(PCWSTR(w.as_ptr()), &mut buf) }.is_ok() {
        let n = buf.iter().position(|&c| c == 0).unwrap_or(0);
        let s = String::from_utf16_lossy(&buf[..n]);
        return display_path(Path::new(&s)).to_lowercase();
    }
    p.components().next().map(|c| c.as_os_str().to_string_lossy().to_lowercase()).unwrap_or_default()
}
#[cfg(not(windows))]
pub fn volume_root(_p: &Path) -> String {
    "/".into()
}

#[cfg(windows)]
pub fn drive_type(p: &Path) -> &'static str {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    let root = volume_root(p);
    let w = wide_str(&root);
    match unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) } {
        2 => "removable",
        3 => "fixed",
        4 => "network",
        5 => "optical",
        6 => "ramdisk",
        _ => "unknown",
    }
}
#[cfg(not(windows))]
pub fn drive_type(_p: &Path) -> &'static str {
    "fixed"
}

pub fn is_disk_full(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(112) | Some(39)) || e.kind() == std::io::ErrorKind::StorageFull
}

/// Removes the read-only attribute if set (required before deleting on Windows).
pub fn clear_readonly(p: &Path) -> Result<()> {
    let a = get_attrs(p)?;
    if a & FILE_ATTRIBUTE_READONLY != 0 {
        set_attrs(p, a & !FILE_ATTRIBUTE_READONLY & RESTORABLE_ATTRS)?;
    }
    Ok(())
}

/// Tell Explorer something changed so it refreshes without F5.
#[cfg(windows)]
pub fn notify_shell_changed(p: &Path) {
    use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_UPDATEDIR, SHCNE_UPDATEITEM, SHCNF_FLUSHNOWAIT, SHCNF_PATHW};
    // The item itself (refreshes its icon), then its parent's listing.
    let item = wide_str(&display_path(p));
    unsafe { SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, Some(item.as_ptr() as _), None) };
    let target = p.parent().unwrap_or(p);
    let w = wide_str(&display_path(target));
    unsafe { SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, Some(w.as_ptr() as _), None) };
}
#[cfg(not(windows))]
pub fn notify_shell_changed(_p: &Path) {}
