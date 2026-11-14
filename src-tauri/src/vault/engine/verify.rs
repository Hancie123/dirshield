//! Full integrity verification of a sealed vault (no plaintext is written).

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::atomic::Ordering;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::super::header::{VaultHeader, MANIFEST_FILE};
use super::super::manifest::{read_manifest, Line};
use super::super::stream::{decrypt_blob, BlobKind};
use super::*;
use crate::domain::error::{Error, Result};

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
}

pub fn verify_vault(vault_dir: &Path, vk: &[u8; 32], ctrl: &Control) -> Result<VerifyReport> {
    let header = VaultHeader::read(vault_dir)?;
    header.verify_mac(vk)?;
    if !header.sealed {
        return Err(Error::Integrity("this vault was never completed".into()));
    }
    let vid = header.vault_id_bytes()?;
    let mut rep = VerifyReport::default();
    ctrl.set_phase("Verifying");
    read_manifest(BufReader::new(File::open(vault_dir.join(MANIFEST_FILE))?), vk, &vid, |line| {
        match line {
            Line::Dir { .. } => rep.dirs += 1,
            Line::File { p, s, b, h, .. } => {
                ctrl.set_current(&p);
                let fid: [u8; 16] = hex::decode(&b).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| Error::Integrity("bad object id".into()))?;
                let mut hasher = Sha256::new();
                let r = File::open(blob_path(vault_dir, &b)).map_err(|_| Error::Integrity(format!("encrypted object for \"{p}\" is missing")))?;
                let info = decrypt_blob(BufReader::with_capacity(READ_BUF, r), vk, &vid, BlobKind::File, Some(&fid), |c| {
                    ctrl.checkpoint()?;
                    hasher.update(c);
                    ctrl.processed_bytes.fetch_add(c.len() as u64, Ordering::Relaxed);
                    Ok(())
                })
                .map_err(|e| match e {
                    Error::Integrity(m) => Error::Integrity(format!("\"{p}\": {m}")),
                    o => o,
                })?;
                if info.plain_bytes != s || hex::encode(hasher.finalize()) != h {
                    return Err(Error::Integrity(format!("\"{p}\" does not match its recorded checksum")));
                }
                rep.files += 1;
                rep.bytes += s;
                ctrl.processed_files.fetch_add(1, Ordering::Relaxed);
            }
            Line::Head { .. } | Line::End { .. } => {}
        }
        Ok(())
    })?;
    Ok(rep)
}

/// Reads the manifest head and totals (used for vault import and the details view).
pub fn manifest_summary(vault_dir: &Path, vk: &[u8; 32]) -> Result<(String, String, u64, u64)> {
    let header = VaultHeader::read(vault_dir)?;
    header.verify_mac(vk)?;
    let vid = header.vault_id_bytes()?;
    let (mut name, mut path, mut files, mut bytes) = (String::new(), String::new(), 0, 0);
    read_manifest(BufReader::new(File::open(vault_dir.join(MANIFEST_FILE))?), vk, &vid, |l| {
        match l {
            Line::Head { root_name, original_path, .. } => {
                name = root_name;
                path = original_path;
            }
            Line::End { files: f, bytes: b, .. } => {
                files = f;
                bytes = b;
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok((name, path, files, bytes))
}
