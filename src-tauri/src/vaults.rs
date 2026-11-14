//! The `vaults` table: typed rows, loading, and decrypting their metadata.
//!
//! Folder names and original paths are encrypted with the metadata key (from
//! the master key), bound to the vault id and field by the AAD, so a row can't
//! be swapped onto another vault.

use std::path::{Path, PathBuf};

use rusqlite::OptionalExtension;
use serde::Serialize;

use crate::crypto;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::model::{KeyMode, ProtectionMode, VaultStatus};
use crate::quicklock::QuickState;

pub fn aad(id: &str, field: &str) -> Vec<u8> {
    format!("dirshield/v1/vault/{id}/{field}").into_bytes()
}

#[derive(Clone, Debug)]
pub struct VaultRow {
    pub id: String,
    pub name_enc: String,
    pub path_enc: String,
    pub vault_path: String,
    pub mode: ProtectionMode,
    pub key_mode: KeyMode,
    pub status: VaultStatus,
    pub size: i64,
    pub files: i64,
    pub skipped: i64,
    pub quick: Option<String>,
    pub locked_at: Option<i64>,
    pub created_at: i64,
}

impl VaultRow {
    /// Quick Lock state (current location, hidden, moved), if this is a Quick Lock row.
    pub fn quick_state(&self) -> Option<QuickState> {
        self.quick.as_deref().and_then(|s| serde_json::from_str(s).ok())
    }

    pub fn name(&self, mk: &[u8; 32]) -> Result<String> {
        crypto::decrypt_text(&crypto::metadata_key(mk), &self.name_enc, &aad(&self.id, "name"))
    }

    pub fn original_path(&self, mk: &[u8; 32]) -> Result<String> {
        crypto::decrypt_text(&crypto::metadata_key(mk), &self.path_enc, &aad(&self.id, "path"))
    }
}

const VAULT_COLS: &str = "id, name, original_path, vault_path, protection_mode, key_mode, status, size_bytes, file_count, skipped_count, quick_state, locked_at, created_at";

fn map_row(r: &rusqlite::Row) -> rusqlite::Result<VaultRow> {
    Ok(VaultRow {
        id: r.get(0)?,
        name_enc: r.get(1)?,
        path_enc: r.get(2)?,
        vault_path: r.get(3)?,
        mode: r.get(4)?,
        key_mode: r.get(5)?,
        status: r.get(6)?,
        size: r.get(7)?,
        files: r.get(8)?,
        skipped: r.get(9)?,
        quick: r.get(10)?,
        locked_at: r.get(11)?,
        created_at: r.get(12)?,
    })
}

pub fn load(db: &Db, id: &str) -> Result<VaultRow> {
    db.lock().query_row(&format!("SELECT {VAULT_COLS} FROM vaults WHERE id=?1"), [id], map_row).optional()?.ok_or_else(|| Error::NotFound("protected folder".into()))
}

pub fn all(db: &Db) -> Result<Vec<VaultRow>> {
    let c = db.lock();
    let mut s = c.prepare(&format!("SELECT {VAULT_COLS} FROM vaults ORDER BY created_at DESC"))?;
    let rows = s.query_map([], map_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Quick-Locked folder whose *current* location is `path`. That location is
/// stored in plain form, so no key is needed to find it.
pub fn quick_at(db: &Db, path: &str) -> Result<Option<(VaultRow, QuickState)>> {
    let key = crate::fsutil::path_key(Path::new(path));
    for r in all(db)? {
        if r.mode != ProtectionMode::Quick {
            continue;
        }
        if let Some(q) = r.quick_state() {
            if crate::fsutil::path_key(Path::new(&q.current_path)) == key {
                return Ok(Some((r, q)));
            }
        }
    }
    Ok(None)
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub original_path: String,
    pub vault_path: String,
    pub mode: ProtectionMode,
    pub key_mode: KeyMode,
    pub status: VaultStatus,
    pub size_bytes: i64,
    pub file_count: i64,
    pub skipped_count: i64,
    pub locked_at: Option<i64>,
    pub created_at: i64,
    pub hidden: Option<bool>,
    pub moved: Option<bool>,
    pub busy: bool,
}

/// What the UI sees for a row. `busy` comes from the operations manager.
pub fn info(mk: &[u8; 32], r: &VaultRow, busy: bool) -> VaultInfo {
    let q = r.quick_state();
    VaultInfo {
        id: r.id.clone(),
        name: r.name(mk).unwrap_or_else(|_| "(unreadable)".into()),
        original_path: r.original_path(mk).unwrap_or_default(),
        vault_path: r.vault_path.clone(),
        mode: r.mode,
        key_mode: r.key_mode,
        status: r.status,
        size_bytes: r.size,
        file_count: r.files,
        skipped_count: r.skipped,
        locked_at: r.locked_at,
        created_at: r.created_at,
        hidden: q.as_ref().map(|q| q.hidden),
        moved: q.as_ref().map(|q| q.moved),
        busy,
    }
}

/// Already-protected locations, for the overlap rules in [`crate::policy`].
pub fn protected_entries(db: &Db, mk: &[u8; 32]) -> Result<Vec<crate::policy::Protected>> {
    Ok(all(db)?
        .into_iter()
        .filter(|r| r.status != VaultStatus::Restored)
        .map(|r| crate::policy::Protected {
            name: r.name(mk).unwrap_or_else(|_| "(unreadable)".into()),
            original: PathBuf::from(r.original_path(mk).unwrap_or_default()),
            vault_dir: (r.mode == ProtectionMode::Secure).then(|| PathBuf::from(&r.vault_path)),
        })
        .collect())
}
