//! Secure Lock: create a vault, journal the folder, encrypt every item and
//! seal the vault once everything has been written and verified.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::super::header::{KeyWrapper, VaultHeader, ALGORITHM, FORMAT_VERSION, HEADER_FILE, MANIFEST_FILE, OBJECTS_DIR};
use super::super::manifest::{self, read_manifest, rel_string, safe_rel_path, Line};
use super::super::scan::{estimate_vault_bytes, is_link};
use super::super::stream::{blob_size, decrypt_blob, BlobKind, BlobWriter};
use super::control::ItemProgress;
use super::journal::{insert_items, run_journal};
use super::*;
use crate::domain::error::{Error, Result};
use crate::platform::fsutil::{self, mtime_ns, RESTORABLE_ATTRS};
use crate::security::crypto;
use crate::storage::db::{now_ms, Db};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct EncryptParams {
    pub walk_skipped: u64,
}

pub struct NewVaultSpec<'a> {
    pub vault_id: &'a str,
    pub source: &'a Path,
    pub vault_root: &'a Path,
    /// Folder name for the vault inside `vault_root`; defaults to the vault id.
    pub dir_name: Option<&'a str>,
    pub vk: &'a [u8; 32],
    pub wrappers: Vec<KeyWrapper>,
    pub name_enc: String,
    pub path_enc: String,
    pub key_mode: &'a str,
    pub chunk: u32,
}

pub struct NewVault {
    pub op_id: String,
    pub vault_dir: PathBuf,
}

pub fn create_secure_vault(db: &Db, spec: NewVaultSpec, ctrl: &Control) -> Result<NewVault> {
    let vault_dir = spec.vault_root.join(spec.dir_name.unwrap_or(spec.vault_id));
    if vault_dir.exists() {
        return Err(Error::Conflict("vault directory already exists".into()));
    }
    fs::create_dir_all(vault_dir.join(OBJECTS_DIR).join("tmp"))?;
    let result = (|| -> Result<String> {
        let mut header = VaultHeader {
            format_version: FORMAT_VERSION,
            algorithm: ALGORITHM.into(),
            vault_id: spec.vault_id.into(),
            chunk_size: spec.chunk,
            created_utc: now_ms(),
            wrappers: spec.wrappers.clone(),
            sealed: false,
            mac: String::new(),
        };
        header.compute_mac(spec.vk)?;
        header.write_atomic(&vault_dir)?;

        let now = now_ms();
        let op_id = crypto::random_id();
        {
            let mut c = db.lock();
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO vaults(id, name, original_path, vault_path, protection_mode, key_mode, status, created_at, updated_at)
                 VALUES(?1,?2,?3,?4,'secure',?5,'encrypting',?6,?6)",
                params![spec.vault_id, spec.name_enc, spec.path_enc, fsutil::display_path(&vault_dir), spec.key_mode, now],
            )?;
            for w in &spec.wrappers {
                let (salt, kdfp) = match w {
                    KeyWrapper::Password { kdf, .. } => (Some(crypto_b64(&kdf.salt)), Some(serde_json::to_string(kdf)?)),
                    _ => (None, None),
                };
                tx.execute(
                    "INSERT INTO vault_key_wrappers(vault_id, wrapper_type, kdf_salt, kdf_parameters, wrapped_vault_key, created_at) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![spec.vault_id, w.kind(), salt, kdfp, serde_json::to_string(w)?, now],
                )?;
            }
            tx.execute(
                "INSERT INTO operations(id, vault_id, operation_type, status, params, created_at, updated_at) VALUES(?1,?2,'encrypt','running','{}',?3,?3)",
                params![op_id, spec.vault_id, now],
            )?;
            tx.commit()?;
        }

        // Journal every item up front so the operation is resumable.
        let t = journal_tree(db, &op_id, spec.source, ctrl, |_, _| Ok(false))?;
        let need = estimate_vault_bytes(t.files, t.dirs, t.bytes);
        let free = fsutil::free_space(&vault_dir)?;
        if need > free {
            return Err(Error::InsufficientSpace { need, free });
        }
        let p = serde_json::to_string(&EncryptParams { walk_skipped: t.skipped })?;
        db.lock().execute("UPDATE operations SET total_files=?2, total_bytes=?3, params=?4 WHERE id=?1", params![op_id, t.files as i64, t.bytes as i64, p])?;
        db.lock().execute("UPDATE vaults SET size_bytes=?2, file_count=?3 WHERE id=?1", params![spec.vault_id, t.bytes as i64, t.files as i64])?;
        Ok(op_id)
    })();
    match result {
        Ok(op_id) => Ok(NewVault { op_id, vault_dir }),
        Err(e) => {
            // Nothing has been encrypted yet and originals were never touched: roll back fully.
            discard_vault_storage(&vault_dir);
            let _ = db.lock().execute("DELETE FROM operations WHERE vault_id=?1", [spec.vault_id]);
            let _ = db.lock().execute("DELETE FROM vaults WHERE id=?1", [spec.vault_id]);
            Err(e)
        }
    }
}

#[derive(Default)]
pub(super) struct WalkTotals {
    pub(super) files: u64,
    pub(super) dirs: u64,
    pub(super) bytes: u64,
    pub(super) skipped: u64,
    /// Files (and their bytes) `reusable` expects to need no new encryption.
    pub(super) reusable_files: u64,
    pub(super) reusable_bytes: u64,
}

/// Walks `source` (never following links) and journals every folder and
/// regular file as a pending item. `reusable(rel, meta)` says whether a file
/// will probably reuse an existing encrypted object (used for the space estimate).
pub(super) fn journal_tree(db: &Db, op_id: &str, source: &Path, ctrl: &Control, mut reusable: impl FnMut(&str, &fs::Metadata) -> Result<bool>) -> Result<WalkTotals> {
    ctrl.set_phase("Preparing");
    let mut batch = Vec::with_capacity(BATCH);
    let mut next_id = 0i64;
    let mut t = WalkTotals::default();
    for entry in WalkDir::new(source).follow_links(false).min_depth(1) {
        if ctrl.stopped() {
            return Err(Error::Cancelled);
        }
        let Ok(entry) = entry else {
            t.skipped += 1;
            continue;
        };
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            t.skipped += 1;
            continue;
        };
        if is_link(&meta) || !(meta.is_dir() || meta.is_file()) {
            t.skipped += 1;
            continue;
        }
        let rel = rel_string(source, entry.path())?;
        let kind = if meta.is_dir() { "d" } else { "f" };
        if kind == "d" {
            t.dirs += 1;
        } else {
            t.files += 1;
            t.bytes += meta.len();
            if reusable(&rel, &meta)? {
                t.reusable_files += 1;
                t.reusable_bytes += meta.len();
            }
        }
        batch.push(Item { item_id: next_id, rel, kind: kind.into(), size: if kind == "f" { meta.len() } else { 0 }, mtime: mtime_ns(&meta), attrs: fsutil::attrs(&meta), blob_id: None, sha256: None });
        next_id += 1;
        if batch.len() >= BATCH {
            insert_items(db, op_id, &batch)?;
            batch.clear();
        }
    }
    insert_items(db, op_id, &batch)?;
    Ok(t)
}

pub(super) fn crypto_b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Deletes a vault directory. Only ever called on DirShield-owned vault
/// directories (verified by the presence of our header file).
pub fn discard_vault_storage(vault_dir: &Path) {
    if vault_dir.join(HEADER_FILE).exists() || vault_dir.join(OBJECTS_DIR).exists() {
        let _ = fs::remove_dir_all(vault_dir);
    }
}

// ---------------------------------------------------------------------------
// Secure Lock: run (and resume)
// ---------------------------------------------------------------------------

pub struct EncryptJob<'a> {
    pub db: &'a Db,
    pub op_id: &'a str,
    pub vault_id: &'a str,
    pub vault_dir: &'a Path,
    pub source: &'a Path,
    pub root_name: &'a str,
    pub original_path: &'a str,
    pub vk: &'a [u8; 32],
    pub workers: usize,
    pub ctrl: &'a Control,
}

pub fn run_encrypt(job: &EncryptJob) -> Result<()> {
    let header = VaultHeader::read(job.vault_dir)?;
    header.verify_mac(job.vk)?;
    if header.sealed {
        return Err(Error::Conflict("vault is already sealed".into()));
    }
    let vid = header.vault_id_bytes()?;
    let chunk = header.chunk_size;
    if !job.source.is_dir() {
        return Err(Error::NotFound(format!("original folder {}", job.source.display())));
    }
    fs::create_dir_all(job.vault_dir.join(OBJECTS_DIR).join("tmp"))?;
    load_counters(job.db, job.op_id, job.ctrl)?;
    job.ctrl.set_phase("Encrypting");
    run_journal(job.db, job.op_id, job.ctrl, job.workers, |item| encrypt_item(job, &vid, chunk, item))?;
    let failed = count_status(job.db, job.op_id, "error")?;
    if failed > 0 {
        return Err(Error::Invalid(format!("{failed} item(s) could not be encrypted. The original folder is untouched. Retry, or exclude these items.")));
    }
    finalize_encrypt(job, header, &vid)
}

pub(super) fn encrypt_item(job: &EncryptJob, vid: &[u8; 16], chunk: u32, item: &Item) -> Result<Outcome> {
    let src = job.source.join(safe_rel_path(&item.rel)?);
    let meta = fs::symlink_metadata(&src).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::Invalid("item no longer exists".into()),
        _ => Error::Io(e),
    })?;
    if is_link(&meta) {
        return Err(Error::Invalid("item was replaced by a link".into()));
    }
    if item.kind == "d" {
        if !meta.is_dir() {
            return Err(Error::Invalid("folder was replaced by a file".into()));
        }
        return Ok(Outcome::Done { blob_id: None, sha256: None, chunks: None, size: 0, mtime: mtime_ns(&meta), attrs: fsutil::attrs(&meta) });
    }
    if !meta.is_file() {
        return Err(Error::Invalid("file was replaced by a folder".into()));
    }
    // One retry if the file changes while being read.
    match encrypt_file_once(job, vid, chunk, item, &src) {
        Err(Error::Conflict(_)) => encrypt_file_once(job, vid, chunk, item, &src),
        r => r,
    }
}

pub(super) fn encrypt_file_once(job: &EncryptJob, vid: &[u8; 16], chunk: u32, item: &Item, src: &Path) -> Result<Outcome> {
    let ctrl = job.ctrl;
    let before = fs::metadata(src)?;
    let (len0, m0) = (before.len(), mtime_ns(&before));
    let mut input = File::open(src)?;
    let tmp = job.vault_dir.join(OBJECTS_DIR).join("tmp").join(format!("{}.part", item.item_id));
    let _ = fs::remove_file(&tmp);
    let mut prog = ItemProgress::new(ctrl);
    let result = (|| -> Result<Outcome> {
        let out = File::create(&tmp)?;
        let (mut w, fid) = BlobWriter::new(BufWriter::with_capacity(READ_BUF, out), job.vk, vid, BlobKind::File, chunk)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; READ_BUF];
        loop {
            ctrl.checkpoint()?;
            let n = match input.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            hasher.update(&buf[..n]);
            w.write_all(&buf[..n])?;
            prog.add(n as u64 / 2);
        }
        drop(input);
        let (bw, n, chunks) = w.finish()?;
        let file = bw.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        drop(file);
        let after = fs::metadata(src)?;
        if after.len() != len0 || mtime_ns(&after) != m0 || n != len0 {
            return Err(Error::Conflict("file changed while it was being encrypted".into()));
        }
        let digest = hasher.finalize();

        // Verify: re-read the encrypted object from disk, authenticate every chunk, compare hashes.
        let mut vh = Sha256::new();
        let info = decrypt_blob(BufReader::with_capacity(READ_BUF, File::open(&tmp)?), job.vk, vid, BlobKind::File, Some(&fid), |b| {
            ctrl.checkpoint()?;
            vh.update(b);
            prog.add(b.len() as u64 / 2);
            Ok(())
        })?;
        if info.plain_bytes != n || vh.finalize() != digest {
            return Err(Error::Integrity("verification of the encrypted copy failed".into()));
        }
        let blob_id = hex::encode(fid);
        let final_path = blob_path(job.vault_dir, &blob_id);
        fs::create_dir_all(final_path.parent().unwrap())?;
        fs::rename(&tmp, &final_path)?;
        prog.settle(len0);
        Ok(Outcome::Done { blob_id: Some(blob_id), sha256: Some(hex::encode(digest)), chunks: Some(chunks), size: n, mtime: m0, attrs: fsutil::attrs(&after) })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        prog.rollback();
    }
    result
}

pub(super) fn finalize_encrypt(job: &EncryptJob, mut header: VaultHeader, vid: &[u8; 16]) -> Result<()> {
    let db = job.db;
    job.ctrl.set_phase("Finalizing");
    job.ctrl.set_current("");

    // 1. Remove temp files and orphaned objects from interrupted attempts.
    let objects = job.vault_dir.join(OBJECTS_DIR);
    for e in WalkDir::new(&objects).min_depth(1).into_iter().filter_map(|e| e.ok()) {
        if !e.file_type().is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy();
        let keep = match name.strip_suffix(".dsb") {
            Some(id) => db.lock().query_row("SELECT 1 FROM operation_journal WHERE operation_id=?1 AND blob_id=?2 AND status='done'", params![job.op_id, id], |_| Ok(())).optional()?.is_some(),
            None => false,
        };
        if !keep {
            fs::remove_file(e.path())?;
        }
    }
    let _ = fs::remove_dir(objects.join("tmp"));

    // 2 + 3. Encrypted manifest from the journal, verified against the objects.
    let (tmp, _, files, bytes) = write_manifest(job, &header, vid)?;
    fs::rename(&tmp, job.vault_dir.join(MANIFEST_FILE))?;

    // 4. Commit point: atomically rewrite the header with sealed = true.
    header.sealed = true;
    header.compute_mac(job.vk)?;
    header.write_atomic(job.vault_dir)?;

    // 5. Record success and purge plaintext paths from the journal.
    let walk_skipped: u64 = db
        .lock()
        .query_row("SELECT params FROM operations WHERE id=?1", [job.op_id], |r| r.get::<_, Option<String>>(0))?
        .and_then(|p| serde_json::from_str::<EncryptParams>(&p).ok())
        .map(|p| p.walk_skipped)
        .unwrap_or(0);
    let skipped = count_status(db, job.op_id, "skipped")? + walk_skipped;
    let now = now_ms();
    let mut c = db.lock();
    let tx = c.transaction()?;
    tx.execute(
        "UPDATE vaults SET status='encrypted', size_bytes=?2, file_count=?3, skipped_count=?4, locked_at=?5, updated_at=?5 WHERE id=?1",
        params![job.vault_id, bytes as i64, files as i64, skipped as i64, now],
    )?;
    tx.execute("UPDATE operations SET status='completed', processed_bytes=total_bytes, processed_files=?2, error=NULL, updated_at=?3 WHERE id=?1", params![job.op_id, files as i64, now])?;
    tx.execute("DELETE FROM operation_journal WHERE operation_id=?1", [job.op_id])?;
    tx.commit()?;
    Ok(())
}

/// Writes `manifest.dsb.tmp` from the journal's finished items (streamed,
/// bounded memory), then re-reads it and checks that every object it names
/// exists with the exact expected size. Returns (temp path, manifest blob id,
/// files, bytes).
pub(super) fn write_manifest(job: &EncryptJob, header: &VaultHeader, vid: &[u8; 16]) -> Result<(PathBuf, [u8; 16], u64, u64)> {
    let db = job.db;
    let tmp = job.vault_dir.join(format!("{MANIFEST_FILE}.tmp"));
    let (mut w, manifest_id) = BlobWriter::new(BufWriter::with_capacity(READ_BUF, File::create(&tmp)?), job.vk, vid, BlobKind::Manifest, header.chunk_size)?;
    manifest::write_line(&mut w, &Line::Head { v: 1, root_name: job.root_name.into(), original_path: job.original_path.into(), created_utc: header.created_utc })?;
    let (mut dirs, mut files, mut bytes) = (0u64, 0u64, 0u64);
    let mut last = -1i64;
    loop {
        let rows: Vec<(i64, String, String, i64, Option<i64>, u32, Option<String>, Option<String>, Option<i64>)> = {
            let c = db.lock();
            let mut st = c.prepare_cached(
                "SELECT item_id, item_path_reference, kind, size, mtime, attrs, blob_id, sha256, chunks FROM operation_journal
                 WHERE operation_id=?1 AND status='done' AND item_id>?2 ORDER BY item_id LIMIT ?3",
            )?;
            let r = st
                .query_map(params![job.op_id, last, PAGE], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            r
        };
        if rows.is_empty() {
            break;
        }
        for (id, rel, kind, size, mtime, attrs, blob, sha, chunks) in rows {
            last = id;
            let line = if kind == "d" {
                dirs += 1;
                Line::Dir { p: rel, a: attrs & RESTORABLE_ATTRS, m: mtime }
            } else {
                files += 1;
                bytes += size as u64;
                Line::File {
                    p: rel,
                    s: size as u64,
                    a: attrs & RESTORABLE_ATTRS,
                    m: mtime,
                    b: blob.ok_or_else(|| Error::Integrity("journal entry without object".into()))?,
                    h: sha.ok_or_else(|| Error::Integrity("journal entry without hash".into()))?,
                    c: chunks.unwrap_or(0) as u64,
                }
            };
            manifest::write_line(&mut w, &line)?;
        }
    }
    manifest::write_line(&mut w, &Line::End { dirs, files, bytes })?;
    let (bw, _, _) = w.finish()?;
    let f = bw.into_inner().map_err(|e| e.into_error())?;
    f.sync_all()?;
    drop(f);

    // 3. Verify the manifest and that every referenced object exists with the exact expected size.
    let mut seen = 0u64;
    read_manifest(BufReader::new(File::open(&tmp)?), job.vk, vid, |l| {
        if let Line::File { s, b, .. } = &l {
            let len = fs::metadata(blob_path(job.vault_dir, b)).map(|m| m.len()).unwrap_or(u64::MAX);
            if len != blob_size(*s, header.chunk_size) {
                return Err(Error::Integrity("an encrypted object is missing or has the wrong size".into()));
            }
            seen += 1;
        }
        Ok(())
    })?;
    if seen != files {
        return Err(Error::Integrity("manifest verification failed".into()));
    }
    Ok((tmp, manifest_id, files, bytes))
}

/// Id of the blob currently stored as the vault's manifest (read from its
/// plaintext blob header; no key needed). Used to detect whether a re-lock
/// reached its commit point.
pub fn current_manifest_id(vault_dir: &Path) -> Option<String> {
    let mut h = [0u8; super::super::stream::HEADER_LEN];
    File::open(vault_dir.join(MANIFEST_FILE)).ok()?.read_exact(&mut h).ok()?;
    (&h[0..4] == super::super::stream::BLOB_MAGIC).then(|| hex::encode(&h[12..28]))
}
