//! Pre-flight folder scan: size, counts, links/junctions, unreadable items and
//! disk-space estimate. Never follows links. Memory use is constant
//! (only the first few problem paths are kept as samples).

use std::fs;
use std::path::Path;

use serde::Serialize;
use walkdir::WalkDir;

use super::stream::{blob_size, DEFAULT_CHUNK};
use crate::domain::error::{Error, Result};
use crate::platform::fsutil;

const SAMPLES: usize = 50;

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub path: String,
    pub name: String,
    pub total_files: u64,
    pub total_dirs: u64,
    pub total_bytes: u64,
    pub largest_file: u64,
    pub links: u64,
    pub link_samples: Vec<String>,
    pub inaccessible: u64,
    pub inaccessible_samples: Vec<String>,
    /// Files and folders whose names (or a parent folder's name) aren't valid
    /// Unicode. Secure Lock can't store them: they are skipped and left in
    /// place. Not included in the totals.
    pub bad_names: u64,
    pub bad_name_samples: Vec<String>,
    pub estimated_vault_bytes: u64,
    pub drive_type: String,
    pub source_free_bytes: u64,
}

pub fn is_link(meta: &fs::Metadata) -> bool {
    // std reports both symbolic links and junctions (mount points) as symlinks.
    meta.file_type().is_symlink()
}

/// Estimated bytes the vault will need: exact blob sizes + manifest + slack.
pub fn estimate_vault_bytes(files: u64, dirs: u64, bytes: u64) -> u64 {
    let blobs = bytes + files * (blob_size(0, DEFAULT_CHUNK)) + (bytes / DEFAULT_CHUNK as u64 + 1) * 16;
    let manifest = (files + dirs) * 400 + 64 * 1024;
    blobs + manifest + 32 * 1024 * 1024
}

pub fn scan(root: &Path, probe_open: bool) -> Result<ScanReport> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || is_link(&meta) {
        return Err(Error::Invalid("Select a regular folder (not a file, link or junction).".into()));
    }
    let mut r = ScanReport {
        path: fsutil::display_path(root),
        name: root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        drive_type: fsutil::drive_type(root).into(),
        source_free_bytes: fsutil::free_space(root).unwrap_or(0),
        ..Default::default()
    };
    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                r.inaccessible += 1;
                if r.inaccessible_samples.len() < SAMPLES {
                    r.inaccessible_samples.push(e.path().map(fsutil::display_path).unwrap_or_else(|| e.to_string()));
                }
                continue;
            }
        };
        if entry.path().strip_prefix(root).ok().and_then(|p| p.to_str()).is_none() {
            r.bad_names += 1;
            if r.bad_name_samples.len() < SAMPLES {
                // Lossy: the invalid part shows as U+FFFD.
                r.bad_name_samples.push(fsutil::display_path(entry.path()));
            }
            continue;
        }
        let ft = entry.file_type();
        if ft.is_symlink() {
            r.links += 1;
            if r.link_samples.len() < SAMPLES {
                r.link_samples.push(fsutil::display_path(entry.path()));
            }
        } else if ft.is_dir() {
            r.total_dirs += 1;
        } else if ft.is_file() {
            let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
            if probe_open && fs::File::open(entry.path()).is_err() {
                r.inaccessible += 1;
                if r.inaccessible_samples.len() < SAMPLES {
                    r.inaccessible_samples.push(fsutil::display_path(entry.path()));
                }
                continue;
            }
            r.total_files += 1;
            r.total_bytes += len;
            r.largest_file = r.largest_file.max(len);
        }
    }
    r.estimated_vault_bytes = estimate_vault_bytes(r.total_files, r.total_dirs, r.total_bytes);
    Ok(r)
}
