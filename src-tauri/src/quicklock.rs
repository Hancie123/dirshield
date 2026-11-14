//! Quick Lock: convenient privacy, NOT encryption.
//!
//! Steps (each one rolled back if a later one fails):
//! 1. If the folder is on the same volume as the DirShield store, move it into
//!    the store with an atomic rename (never a cross-volume copy).
//! 2. Set Hidden + System + Not-Content-Indexed attributes.
//! 3. Add an inheritable deny-Everyone ACE (see `winsec`).
//! 4. Best-effort Windows Search exclusion for in-place locks.
//!
//! Administrators, other operating systems, offline disk access and
//! sufficiently privileged processes can bypass Quick Lock.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::fsutil::{self, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_SYSTEM, RESTORABLE_ATTRS};
use crate::{search, winsec};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QuickState {
    pub current_path: String,
    pub moved: bool,
    pub prev_attrs: u32,
    pub hidden: bool,
    pub search_rule: bool,
}

const HIDE: u32 = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

fn io_hint(e: std::io::Error) -> Error {
    match e.raw_os_error() {
        Some(5) | Some(32) | Some(33) => Error::Invalid("The folder or a file inside it is in use. Close programs and Explorer windows using it, then try again.".into()),
        Some(183) | Some(80) => Error::Conflict("The destination already exists.".into()),
        _ => Error::Io(e),
    }
}

pub fn lock(original: &Path, store: Option<&Path>, id: &str) -> Result<QuickState> {
    let prev_attrs = fsutil::get_attrs(original)? & RESTORABLE_ATTRS;
    let mut current: PathBuf = original.to_path_buf();
    let mut moved = false;

    if let Some(store) = store {
        fs::create_dir_all(store)?;
        if fsutil::volume_root(original) == fsutil::volume_root(store) {
            let target = store.join(id);
            // Sidecar first: if the database is ever lost, the folder can still be
            // returned to where it came from (see `find_orphans`).
            write_sidecar(store, id, original, prev_attrs)?;
            if let Err(e) = fsutil::rename_noreplace(original, &target) {
                let _ = fs::remove_file(sidecar_path(store, id));
                return Err(io_hint(e));
            }
            current = target;
            moved = true;
        }
    }
    let undo_move = |cur: &Path| {
        if moved && fsutil::rename_noreplace(cur, original).is_ok() {
            if let Some(store) = store {
                let _ = fs::remove_file(sidecar_path(store, id));
            }
        }
    };

    if let Err(e) = fsutil::set_attrs(&current, prev_attrs | HIDE) {
        undo_move(&current);
        return Err(e);
    }
    if let Err(e) = winsec::apply_deny(&current) {
        let _ = fsutil::set_attrs(&current, prev_attrs);
        undo_move(&current);
        return Err(e);
    }
    let search_rule = if moved { false } else { search::exclude(&current) };
    fsutil::notify_shell_changed(original);
    Ok(QuickState { current_path: fsutil::display_path(&current), moved, prev_attrs, hidden: true, search_rule })
}

/// Reverses a Quick Lock. `dest` defaults to the original location; an
/// existing folder at the destination is never overwritten or merged.
pub fn unlock(state: &QuickState, original: &Path, dest: Option<&Path>) -> Result<PathBuf> {
    let current = PathBuf::from(&state.current_path);
    if fs::symlink_metadata(&current).is_err() {
        return Err(Error::NotFound(format!("the locked folder is missing from {}", state.current_path)));
    }
    let target = dest.map(Path::to_path_buf).unwrap_or_else(|| original.to_path_buf());
    if state.moved && fs::symlink_metadata(&target).is_ok() {
        return Err(Error::Conflict(format!("\"{}\" already exists. Choose a different location to restore to.", fsutil::display_path(&target))));
    }
    winsec::remove_deny(&current)?;
    if let Err(e) = fsutil::set_attrs(&current, state.prev_attrs) {
        let _ = winsec::apply_deny(&current);
        return Err(e);
    }
    let final_path = if state.moved {
        if let Some(p) = target.parent() {
            fs::create_dir_all(p)?;
        }
        if let Err(e) = fsutil::rename_noreplace(&current, &target) {
            // Restore the locked state; never leave it half-unlocked.
            let _ = fsutil::set_attrs(&current, state.prev_attrs | HIDE);
            let _ = winsec::apply_deny(&current);
            return Err(io_hint(e));
        }
        if let (Some(store), Some(name)) = (current.parent(), current.file_name()) {
            let _ = fs::remove_file(sidecar_path(store, &name.to_string_lossy()));
        }
        target
    } else {
        current.clone()
    };
    if state.search_rule {
        search::remove_exclusion(&current);
    }
    fsutil::notify_shell_changed(&final_path);
    Ok(final_path)
}

/// Toggle visibility of a Quick-Locked folder (the access restriction stays).
pub fn set_hidden(state: &mut QuickState, hidden: bool) -> Result<()> {
    let current = PathBuf::from(&state.current_path);
    let a = if hidden { state.prev_attrs | HIDE } else { (state.prev_attrs & !(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED };
    fsutil::set_attrs(&current, a)?;
    state.hidden = hidden;
    fsutil::notify_shell_changed(&current);
    Ok(())
}

// ---------------------------------------------------------------------------
// Orphan recovery: moved folders whose database record was lost.
// ---------------------------------------------------------------------------

/// Plain JSON next to the stored folder (outside it). It reveals the original
/// location to someone browsing the hidden store, which is within Quick
/// Lock's threat model (it is not encryption); it never contains file data.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Sidecar {
    pub v: u32,
    pub original_path: String,
    pub prev_attrs: u32,
    pub locked_at: i64,
}

pub fn sidecar_path(store: &Path, id: &str) -> PathBuf {
    store.join(format!("{id}.dirshield-quick.json"))
}

fn write_sidecar(store: &Path, id: &str, original: &Path, prev_attrs: u32) -> Result<()> {
    use std::io::Write;
    let s = Sidecar { v: 1, original_path: fsutil::display_path(original), prev_attrs, locked_at: crate::db::now_ms() };
    let tmp = store.join(format!("{id}.dirshield-quick.tmp"));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec(&s)?)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, sidecar_path(store, id))?;
    Ok(())
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Orphan {
    pub id: String,
    pub stored_path: String,
    pub original_path: Option<String>,
    pub locked_at: Option<i64>,
    #[serde(skip)]
    prev_attrs: u32,
}

/// Folders in the Quick Lock store that are not in `known_ids`.
pub fn find_orphans(store: &Path, known_ids: &[String]) -> Result<Vec<Orphan>> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(store) else { return Ok(out) };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let is_dir = fs::symlink_metadata(e.path()).map(|m| m.is_dir()).unwrap_or(false);
        if !is_dir || name.len() != 32 || !name.chars().all(|c| c.is_ascii_hexdigit()) || known_ids.contains(&name) {
            continue;
        }
        let side: Option<Sidecar> = fs::read(sidecar_path(store, &name)).ok().and_then(|b| serde_json::from_slice(&b).ok());
        out.push(Orphan {
            stored_path: fsutil::display_path(&e.path()),
            original_path: side.as_ref().map(|s| s.original_path.clone()),
            locked_at: side.as_ref().map(|s| s.locked_at),
            prev_attrs: side.map(|s| s.prev_attrs).unwrap_or(0),
            id: name,
        });
    }
    Ok(out)
}

/// Returns an orphaned folder to `dest` (never overwriting anything there).
pub fn recover_orphan(store: &Path, o: &Orphan, dest: &Path) -> Result<PathBuf> {
    let state = QuickState { current_path: o.stored_path.clone(), moved: true, prev_attrs: o.prev_attrs & !FILE_ATTRIBUTE_SYSTEM, hidden: true, search_rule: false };
    let p = unlock(&state, dest, None)?;
    let _ = fs::remove_file(sidecar_path(store, &o.id));
    Ok(p)
}
