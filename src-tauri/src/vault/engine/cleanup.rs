//! Removal of the plaintext originals: an explicit user action after sealing.

use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use std::sync::atomic::Ordering;

use serde::Serialize;

use super::super::header::{VaultHeader, MANIFEST_FILE};
use super::super::manifest::{read_manifest, safe_rel_path, Line};
use super::super::scan::is_link;
use super::*;
use crate::domain::error::{Error, Result};
use crate::platform::fsutil::{self, mtime_ns};

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct CleanupReport {
    pub removed_files: u64,
    pub kept_files: u64,
    pub removed_dirs: u64,
    pub root_removed: bool,
}

/// Deletes only files that are recorded in the verified manifest *and* are
/// unchanged (same size and modification time). New or modified files, and
/// anything excluded from the vault, are left in place and reported.
///
/// Note: this is ordinary deletion. On SSDs and journaling file systems the
/// old plaintext blocks may remain recoverable with forensic tools.
pub fn remove_originals(vault_dir: &Path, vk: &[u8; 32], root: &Path, ctrl: &Control) -> Result<CleanupReport> {
    let header = VaultHeader::read(vault_dir)?;
    header.verify_mac(vk)?;
    if !header.sealed {
        return Err(Error::Integrity("the vault is not complete; originals will not be removed".into()));
    }
    let vid = header.vault_id_bytes()?;
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || is_link(&meta) {
        return Err(Error::Invalid("the original location is no longer a regular folder".into()));
    }
    ctrl.set_phase("Removing originals");
    let mut rep = CleanupReport::default();
    let mut dirs: Vec<String> = Vec::new();
    read_manifest(BufReader::new(File::open(vault_dir.join(MANIFEST_FILE))?), vk, &vid, |l| {
        ctrl.checkpoint()?;
        match l {
            Line::Dir { p, .. } => dirs.push(p),
            Line::File { p, s, m, .. } => {
                let target = root.join(safe_rel_path(&p)?);
                ctrl.set_current(&p);
                match fs::symlink_metadata(&target) {
                    Ok(md) if md.is_file() && md.len() == s && mtime_ns(&md) == m => {
                        let ok = fsutil::clear_readonly(&target).is_ok() && fs::remove_file(&target).is_ok();
                        if ok {
                            rep.removed_files += 1;
                        } else {
                            rep.kept_files += 1;
                        }
                    }
                    Ok(_) => rep.kept_files += 1,
                    Err(_) => {}
                }
                ctrl.processed_files.fetch_add(1, Ordering::Relaxed);
                ctrl.processed_bytes.fetch_add(s, Ordering::Relaxed);
            }
            _ => {}
        }
        Ok(())
    })?;
    dirs.sort_by_key(|d| std::cmp::Reverse(d.matches('/').count()));
    for d in dirs {
        let p = root.join(safe_rel_path(&d)?);
        let _ = fsutil::clear_readonly(&p);
        if fs::remove_dir(&p).is_ok() {
            rep.removed_dirs += 1;
        }
    }
    let _ = fsutil::clear_readonly(root);
    rep.root_removed = fs::remove_dir(root).is_ok();
    Ok(rep)
}
