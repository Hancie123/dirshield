//! Re-lock: update a sealed vault from its folder, re-encrypting only changes.
//!
//! The sealed manifest's file entries are copied into `relock_base`. Each file
//! in the folder is compared with its entry: same size and modification time
//! (or, in thorough mode / when only the time differs, the same SHA-256) means
//! the existing encrypted object is reused as is. Everything else is encrypted
//! into new objects with new random ids, so nothing the live manifest refers
//! to is ever modified.
//!
//! Commit protocol: the new manifest's blob id is recorded in the operation
//! *before* the manifest is renamed over `manifest.dsb`; that rename is the
//! commit point. Whoever finishes the operation (this run, a resume, a discard
//! or crash recovery, which has no key) compares the id on disk with the
//! recorded one to know which side of the commit it is on.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::super::header::{VaultHeader, MANIFEST_FILE, OBJECTS_DIR};
use super::super::manifest::{read_manifest, safe_rel_path, Line};
use super::super::scan::{estimate_vault_bytes, is_link};
use super::super::stream::blob_size;
use super::control::ItemProgress;
use super::encrypt::{encrypt_item, journal_tree, write_manifest};
use super::journal::run_journal;
use super::*;
use crate::domain::error::{Error, Result};
use crate::platform::fsutil::{self, mtime_ns};
use crate::storage::db::{now_ms, Db};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct RelockParams {
    pub source: String,
    /// Compare contents (SHA-256) even when size and modification time match.
    pub thorough: bool,
    /// Vault status to return to if the re-lock is cancelled or discarded.
    pub prev_status: String,
    pub walk_skipped: u64,
    /// Blob id of the new manifest; set just before the commit point.
    pub manifest_id: Option<String>,
    // Summary, filled in on completion.
    pub unchanged_files: u64,
    pub changed_files: u64,
    pub added_files: u64,
    pub removed_files: u64,
}

pub fn load_relock_params(db: &Db, op_id: &str) -> Result<RelockParams> {
    let p: Option<String> = db.lock().query_row("SELECT params FROM operations WHERE id=?1", [op_id], |r| r.get(0))?;
    Ok(serde_json::from_str(p.as_deref().unwrap_or("{}"))?)
}

pub(super) fn save_relock_params(db: &Db, op_id: &str, p: &RelockParams) -> Result<()> {
    db.lock().execute("UPDATE operations SET params=?2, updated_at=?3 WHERE id=?1", params![op_id, serde_json::to_string(p)?, now_ms()])?;
    Ok(())
}

pub(super) fn ensure_relock_open(db: &Db, op_id: &str) -> Result<()> {
    let (ty, status): (String, String) = db.lock().query_row("SELECT operation_type, status FROM operations WHERE id=?1", [op_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if ty != "relock" || status == "completed" {
        return Err(Error::Conflict("this update has already finished".into()));
    }
    Ok(())
}

pub(super) fn relock_committed(p: &RelockParams, vault_dir: &Path) -> bool {
    p.manifest_id.is_some() && p.manifest_id == current_manifest_id(vault_dir)
}

/// Prepares a re-lock of a sealed vault from `params.source`: records the
/// current manifest as the baseline and journals the folder. Returns the
/// operation id. Nothing in the vault changes until `run_relock` commits.
pub fn create_relock(db: &Db, vault_id: &str, vault_dir: &Path, vk: &[u8; 32], mut params: RelockParams, ctrl: &Control) -> Result<String> {
    let header = VaultHeader::read(vault_dir)?;
    header.verify_mac(vk)?;
    if !header.sealed {
        return Err(Error::Integrity("this vault was never completed".into()));
    }
    let vid = header.vault_id_bytes()?;
    let source = PathBuf::from(&params.source);
    let meta = fs::symlink_metadata(&source).map_err(|_| Error::NotFound(format!("folder {}", params.source)))?;
    if !meta.is_dir() || is_link(&meta) {
        return Err(Error::Invalid("Select a regular folder (not a file, link or junction).".into()));
    }
    let op_id = create_operation(db, vault_id, "relock", &serde_json::to_string(&params)?)?;
    let result = (|| -> Result<()> {
        ctrl.set_phase("Reading vault");
        let mut batch: Vec<(String, u64, Option<i64>, String, String, u64)> = Vec::with_capacity(BATCH);
        let flush = |batch: &mut Vec<(String, u64, Option<i64>, String, String, u64)>| -> Result<()> {
            let mut c = db.lock();
            let tx = c.transaction()?;
            {
                let mut st = tx.prepare_cached("INSERT INTO relock_base(operation_id, path, size, mtime, blob_id, sha256, chunks) VALUES(?1,?2,?3,?4,?5,?6,?7)")?;
                for (p, s, m, b, h, c) in batch.drain(..) {
                    st.execute(params![op_id, p, s as i64, m, b, h, c as i64])?;
                }
            }
            tx.commit()?;
            Ok(())
        };
        read_manifest(BufReader::new(File::open(vault_dir.join(MANIFEST_FILE))?), vk, &vid, |l| {
            if ctrl.stopped() {
                return Err(Error::Cancelled);
            }
            if let Line::File { p, s, m, b, h, c, .. } = l {
                batch.push((p, s, m, b, h, c));
                if batch.len() >= BATCH {
                    flush(&mut batch)?;
                }
            }
            Ok(())
        })?;
        flush(&mut batch)?;

        let t = journal_tree(db, &op_id, &source, ctrl, |rel, meta| {
            let base: Option<(i64, Option<i64>)> =
                db.lock().query_row("SELECT size, mtime FROM relock_base WHERE operation_id=?1 AND path=?2", params![op_id, rel], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            Ok(matches!(base, Some((s, m)) if s as u64 == meta.len() && m == mtime_ns(meta)))
        })?;
        let need = estimate_vault_bytes(t.files - t.reusable_files, t.dirs, t.bytes - t.reusable_bytes);
        let free = fsutil::free_space(vault_dir)?;
        if need > free {
            return Err(Error::InsufficientSpace { need, free });
        }
        params.walk_skipped = t.skipped;
        save_relock_params(db, &op_id, &params)?;
        db.lock().execute("UPDATE operations SET total_files=?2, total_bytes=?3 WHERE id=?1", params![op_id, t.files as i64, t.bytes as i64])?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(op_id),
        Err(e) => {
            // Nothing was written to the vault yet.
            let _ = db.lock().execute("DELETE FROM operations WHERE id=?1", [&op_id]);
            Err(e)
        }
    }
}

/// Runs (or resumes) a prepared re-lock. `job.source` is the folder being
/// locked; `job.root_name` / `job.original_path` go into the new manifest.
pub fn run_relock(job: &EncryptJob) -> Result<()> {
    let header = VaultHeader::read(job.vault_dir)?;
    header.verify_mac(job.vk)?;
    if !header.sealed {
        return Err(Error::Integrity("this vault was never completed".into()));
    }
    let vid = header.vault_id_bytes()?;
    let mut p = load_relock_params(job.db, job.op_id)?;
    if relock_committed(&p, job.vault_dir) {
        return complete_relock(job.db, job.op_id, job.vault_id, job.vault_dir);
    }
    if !job.source.is_dir() {
        return Err(Error::NotFound(format!("folder {}", job.source.display())));
    }
    fs::create_dir_all(job.vault_dir.join(OBJECTS_DIR).join("tmp"))?;
    load_counters(job.db, job.op_id, job.ctrl)?;
    job.ctrl.set_phase("Encrypting changes");
    let chunk = header.chunk_size;
    run_journal(job.db, job.op_id, job.ctrl, job.workers, |item| relock_item(job, &vid, chunk, p.thorough, item))?;
    let failed = count_status(job.db, job.op_id, "error")?;
    if failed > 0 {
        return Err(Error::Invalid(format!("{failed} item(s) could not be encrypted. The vault still holds the previous version. Retry, or exclude these items.")));
    }
    job.ctrl.set_phase("Finalizing");
    job.ctrl.set_current("");
    // Leftovers of interrupted attempts: objects neither live nor finished here.
    sweep_objects(job.db, job.op_id, job.vault_dir, true)?;
    let (tmp, manifest_id, _, _) = write_manifest(job, &header, &vid)?;
    p.manifest_id = Some(hex::encode(manifest_id));
    save_relock_params(job.db, job.op_id, &p)?;
    // Commit point.
    fs::rename(&tmp, job.vault_dir.join(MANIFEST_FILE))?;
    complete_relock(job.db, job.op_id, job.vault_id, job.vault_dir)
}

pub(super) fn relock_item(job: &EncryptJob, vid: &[u8; 16], chunk: u32, thorough: bool, item: &Item) -> Result<Outcome> {
    if item.kind == "f" {
        let base: Option<(i64, Option<i64>, String, String, i64)> = job
            .db
            .lock()
            .query_row("SELECT size, mtime, blob_id, sha256, chunks FROM relock_base WHERE operation_id=?1 AND path=?2", params![job.op_id, item.rel], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .optional()?;
        if let Some((size, mtime, blob, sha, chunks)) = base {
            if let Some(o) = try_reuse(job, chunk, thorough, item, size as u64, mtime, blob, sha, chunks as u64)? {
                return Ok(o);
            }
        }
    }
    encrypt_item(job, vid, chunk, item)
}

/// Reuses the existing encrypted object if the file is unchanged.
pub(super) fn try_reuse(job: &EncryptJob, chunk: u32, thorough: bool, item: &Item, size: u64, mtime: Option<i64>, blob: String, sha: String, chunks: u64) -> Result<Option<Outcome>> {
    let src = job.source.join(safe_rel_path(&item.rel)?);
    let Ok(before) = fs::symlink_metadata(&src) else { return Ok(None) };
    if !before.is_file() || is_link(&before) || before.len() != size {
        return Ok(None);
    }
    let object_ok = fs::metadata(blob_path(job.vault_dir, &blob)).map(|m| m.len() == blob_size(size, chunk)).unwrap_or(false);
    if !object_ok {
        return Ok(None);
    }
    let mut prog = ItemProgress::new(job.ctrl);
    if thorough || mtime_ns(&before) != mtime {
        let digest = match hash_file(&src, job.ctrl, &mut prog) {
            Ok(d) => d,
            Err(Error::Cancelled) => {
                prog.rollback();
                return Err(Error::Cancelled);
            }
            Err(_) => {
                prog.rollback();
                return Ok(None); // let encryption report the problem
            }
        };
        let after = fs::symlink_metadata(&src)?;
        if digest != sha || after.len() != before.len() || mtime_ns(&after) != mtime_ns(&before) {
            prog.rollback();
            return Ok(None);
        }
    }
    prog.settle(size);
    Ok(Some(Outcome::Done { blob_id: Some(blob), sha256: Some(sha), chunks: Some(chunks), size, mtime: mtime_ns(&before), attrs: fsutil::attrs(&before) }))
}

pub(super) fn hash_file(p: &Path, ctrl: &Control, prog: &mut ItemProgress) -> Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; READ_BUF];
    loop {
        ctrl.checkpoint()?;
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        h.update(&buf[..n]);
        prog.add(n as u64);
    }
    Ok(hex::encode(h.finalize()))
}

/// Deletes stray files under `objects/`: temp files, and objects that are not
/// referenced by a finished item of this operation (nor, with `keep_base`, by
/// the re-lock baseline, i.e. the live manifest).
pub(super) fn sweep_objects(db: &Db, op_id: &str, vault_dir: &Path, keep_base: bool) -> Result<()> {
    let objects = vault_dir.join(OBJECTS_DIR);
    for e in WalkDir::new(&objects).min_depth(1).into_iter().filter_map(|e| e.ok()) {
        if !e.file_type().is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy();
        let keep = match name.strip_suffix(".dsb") {
            Some(id) => {
                let c = db.lock();
                let done = c.query_row("SELECT 1 FROM operation_journal WHERE operation_id=?1 AND blob_id=?2 AND status='done' LIMIT 1", params![op_id, id], |_| Ok(())).optional()?.is_some();
                done || (keep_base && c.query_row("SELECT 1 FROM relock_base WHERE operation_id=?1 AND blob_id=?2 LIMIT 1", params![op_id, id], |_| Ok(())).optional()?.is_some())
            }
            None => false,
        };
        if !keep {
            fs::remove_file(e.path())?;
        }
    }
    let _ = fs::remove_dir(objects.join("tmp"));
    Ok(())
}

/// Finishes a re-lock whose new manifest is in place: removes objects only
/// the old manifest used and records the result. Needs no key, so crash
/// recovery can run it.
pub fn complete_relock(db: &Db, op_id: &str, vault_id: &str, vault_dir: &Path) -> Result<()> {
    // The sweep keeps only objects named by this operation's journal, which is
    // purged on completion: never run it twice.
    ensure_relock_open(db, op_id)?;
    sweep_objects(db, op_id, vault_dir, false)?;
    let mut p = load_relock_params(db, op_id)?;
    let (files, bytes, unchanged, changed, gone, skipped): (i64, i64, i64, i64, i64, i64) = db.lock().query_row(
        "SELECT
           (SELECT COUNT(*) FROM operation_journal WHERE operation_id=?1 AND kind='f' AND status='done'),
           (SELECT COALESCE(SUM(size),0) FROM operation_journal WHERE operation_id=?1 AND kind='f' AND status='done'),
           (SELECT COUNT(*) FROM operation_journal j WHERE j.operation_id=?1 AND j.kind='f' AND j.status='done'
              AND EXISTS(SELECT 1 FROM relock_base b WHERE b.operation_id=?1 AND b.blob_id=j.blob_id)),
           (SELECT COUNT(*) FROM operation_journal j WHERE j.operation_id=?1 AND j.kind='f' AND j.status='done'
              AND NOT EXISTS(SELECT 1 FROM relock_base b WHERE b.operation_id=?1 AND b.blob_id=j.blob_id)
              AND EXISTS(SELECT 1 FROM relock_base b WHERE b.operation_id=?1 AND b.path=j.item_path_reference)),
           (SELECT COUNT(*) FROM relock_base b WHERE b.operation_id=?1
              AND NOT EXISTS(SELECT 1 FROM operation_journal j WHERE j.operation_id=?1 AND j.status='done' AND j.blob_id=b.blob_id)),
           (SELECT COUNT(*) FROM operation_journal WHERE operation_id=?1 AND status='skipped')",
        [op_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    )?;
    p.unchanged_files = unchanged as u64;
    p.changed_files = changed as u64;
    p.added_files = (files - unchanged - changed).max(0) as u64;
    p.removed_files = (gone - changed).max(0) as u64;
    let now = now_ms();
    let mut c = db.lock();
    let tx = c.transaction()?;
    tx.execute(
        "UPDATE vaults SET status='encrypted', size_bytes=?2, file_count=?3, skipped_count=?4, restored_path=NULL, locked_at=?5, updated_at=?5 WHERE id=?1",
        params![vault_id, bytes, files, skipped + p.walk_skipped as i64, now],
    )?;
    tx.execute(
        "UPDATE operations SET status='completed', processed_bytes=total_bytes, processed_files=?2, params=?3, error=NULL, updated_at=?4 WHERE id=?1",
        params![op_id, files, serde_json::to_string(&p)?, now],
    )?;
    tx.execute("DELETE FROM operation_journal WHERE operation_id=?1", [op_id])?;
    tx.execute("DELETE FROM relock_base WHERE operation_id=?1", [op_id])?;
    tx.commit()?;
    Ok(())
}

/// Abandons an unfinished re-lock. Before the commit point the objects it
/// wrote are deleted and the vault keeps its previous version; after it the
/// update already took effect and is completed instead. Returns true if the
/// vault was updated. The caller removes the operation row afterwards.
pub fn discard_relock(db: &Db, op_id: &str, vault_id: &str, vault_dir: &Path) -> Result<bool> {
    ensure_relock_open(db, op_id)?;
    let p = load_relock_params(db, op_id)?;
    if relock_committed(&p, vault_dir) {
        complete_relock(db, op_id, vault_id, vault_dir)?;
        return Ok(true);
    }
    // Keep exactly what the live manifest uses.
    let objects = vault_dir.join(OBJECTS_DIR);
    for e in WalkDir::new(&objects).min_depth(1).into_iter().filter_map(|e| e.ok()) {
        if !e.file_type().is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy();
        let live = match name.strip_suffix(".dsb") {
            Some(id) => db.lock().query_row("SELECT 1 FROM relock_base WHERE operation_id=?1 AND blob_id=?2 LIMIT 1", params![op_id, id], |_| Ok(())).optional()?.is_some(),
            None => false,
        };
        if !live {
            fs::remove_file(e.path())?;
        }
    }
    let _ = fs::remove_dir(objects.join("tmp"));
    let _ = fs::remove_file(vault_dir.join(format!("{MANIFEST_FILE}.tmp")));
    set_vault_status(db, vault_id, if p.prev_status.is_empty() { "encrypted" } else { &p.prev_status })?;
    Ok(false)
}
