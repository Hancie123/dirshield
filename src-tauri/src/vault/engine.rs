//! Journaled, resumable vault operations.
//!
//! Every operation is backed by rows in `operations` + `operation_journal`, so
//! a crash, power loss or cancellation leaves a state that can be resumed or
//! rolled back. Content is processed in bounded memory: each worker holds one
//! 1 MiB read buffer and one 4 MiB chunk; at most `workers` files are open.
//!
//! Encryption never touches the originals. A vault is only marked sealed after
//! every journaled item has been encrypted, written, flushed, re-read and
//! verified, and the encrypted manifest has itself been verified.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::header::{KeyWrapper, VaultHeader, ALGORITHM, FORMAT_VERSION, HEADER_FILE, MANIFEST_FILE, OBJECTS_DIR};
use super::manifest::{self, read_manifest, rel_string, safe_rel_path, Line};
use super::scan::{estimate_vault_bytes, is_link};
use super::stream::{blob_size, decrypt_blob, BlobKind, BlobWriter};
use crate::crypto;
use crate::db::{now_ms, Db};
use crate::error::{Error, Result};
use crate::fsutil::{self, mtime_ns, RESTORABLE_ATTRS};

const READ_BUF: usize = 1024 * 1024;
const PAGE: i64 = 1000;
const BATCH: usize = 2000;

// ---------------------------------------------------------------------------
// Control / progress shared with the UI thread
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Control {
    pub pause: AtomicBool,
    pub cancel: AtomicBool,
    abort: AtomicBool,
    pub processed_bytes: AtomicU64,
    pub processed_files: AtomicU64,
    pub failed_files: AtomicU64,
    pub total_bytes: AtomicU64,
    pub total_files: AtomicU64,
    pub current: Mutex<String>,
    pub phase: Mutex<String>,
}

impl Control {
    pub fn stopped(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || self.abort.load(Ordering::Relaxed)
    }

    /// Called between chunks: blocks while paused, errors when cancelled.
    pub fn checkpoint(&self) -> Result<()> {
        loop {
            if self.stopped() {
                return Err(Error::Cancelled);
            }
            if !self.pause.load(Ordering::Relaxed) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn set_phase(&self, p: &str) {
        *self.phase.lock().unwrap() = p.to_string();
    }

    fn set_current(&self, c: &str) {
        *self.current.lock().unwrap() = c.to_string();
    }
}

/// Tracks progress contributed by one item so it can be rolled back on failure.
struct ItemProgress<'a> {
    ctrl: &'a Control,
    added: u64,
}

impl<'a> ItemProgress<'a> {
    fn new(ctrl: &'a Control) -> Self {
        Self { ctrl, added: 0 }
    }
    fn add(&mut self, n: u64) {
        self.added += n;
        self.ctrl.processed_bytes.fetch_add(n, Ordering::Relaxed);
    }
    fn settle(&mut self, total: u64) {
        if total > self.added {
            self.add(total - self.added);
        } else if total < self.added {
            self.ctrl.processed_bytes.fetch_sub(self.added - total, Ordering::Relaxed);
            self.added = total;
        }
    }
    fn rollback(&mut self) {
        self.ctrl.processed_bytes.fetch_sub(self.added, Ordering::Relaxed);
        self.added = 0;
    }
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Item {
    pub item_id: i64,
    pub rel: String,
    pub kind: String,
    pub size: u64,
    pub mtime: Option<i64>,
    pub attrs: u32,
    pub blob_id: Option<String>,
    pub sha256: Option<String>,
}

pub enum Outcome {
    Done { blob_id: Option<String>, sha256: Option<String>, chunks: Option<u64>, size: u64, mtime: Option<i64>, attrs: u32 },
    Skipped(String),
}

fn insert_items(db: &Db, op_id: &str, items: &[Item]) -> Result<()> {
    let mut c = db.lock();
    let tx = c.transaction()?;
    {
        let mut st = tx.prepare_cached(
            "INSERT INTO operation_journal(operation_id, item_id, item_path_reference, kind, size, mtime, attrs, status, blob_id, sha256, updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,'pending',?8,?9,?10)",
        )?;
        let now = now_ms();
        for it in items {
            st.execute(params![op_id, it.item_id, it.rel, it.kind, it.size as i64, it.mtime, it.attrs, it.blob_id, it.sha256, now])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn load_pending(db: &Db, op_id: &str, after: i64) -> Result<Vec<Item>> {
    let c = db.lock();
    let mut st = c.prepare_cached(
        "SELECT item_id, item_path_reference, kind, size, mtime, attrs, blob_id, sha256 FROM operation_journal
         WHERE operation_id=?1 AND status='pending' AND item_id>?2 ORDER BY item_id LIMIT ?3",
    )?;
    let rows = st
        .query_map(params![op_id, after, PAGE], |r| {
            Ok(Item {
                item_id: r.get(0)?,
                rel: r.get(1)?,
                kind: r.get(2)?,
                size: r.get::<_, i64>(3)? as u64,
                mtime: r.get(4)?,
                attrs: r.get(5)?,
                blob_id: r.get(6)?,
                sha256: r.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn mark(db: &Db, op_id: &str, item: &Item, outcome: &Outcome) -> Result<()> {
    let c = db.lock();
    match outcome {
        Outcome::Done { blob_id, sha256, chunks, size, mtime, attrs } => {
            c.execute(
                "UPDATE operation_journal SET status='done', blob_id=COALESCE(?3, blob_id), sha256=COALESCE(?4, sha256), chunks=?5,
                 size=?6, mtime=?7, attrs=?8, processed_bytes=?6, error=NULL, updated_at=?9 WHERE operation_id=?1 AND item_id=?2",
                params![op_id, item.item_id, blob_id, sha256, chunks.map(|c| c as i64), *size as i64, mtime, attrs, now_ms()],
            )?;
        }
        Outcome::Skipped(reason) => {
            c.execute(
                "UPDATE operation_journal SET status='skipped', error=?3, updated_at=?4 WHERE operation_id=?1 AND item_id=?2",
                params![op_id, item.item_id, reason, now_ms()],
            )?;
        }
    }
    c.execute("UPDATE operations SET last_processed_item=MAX(COALESCE(last_processed_item,-1), ?2), updated_at=?3 WHERE id=?1", params![op_id, item.item_id, now_ms()])?;
    Ok(())
}

fn mark_error(db: &Db, op_id: &str, item: &Item, msg: &str) {
    let _ = db.lock().execute(
        "UPDATE operation_journal SET status='error', error=?3, updated_at=?4 WHERE operation_id=?1 AND item_id=?2",
        params![op_id, item.item_id, msg, now_ms()],
    );
}

pub fn count_status(db: &Db, op_id: &str, status: &str) -> Result<u64> {
    Ok(db.lock().query_row("SELECT COUNT(*) FROM operation_journal WHERE operation_id=?1 AND status=?2", params![op_id, status], |r| r.get::<_, i64>(0))? as u64)
}

/// Resets failed items so a retry processes them again.
pub fn retry_failed(db: &Db, op_id: &str) -> Result<()> {
    db.lock().execute("UPDATE operation_journal SET status='pending', error=NULL WHERE operation_id=?1 AND status='error'", [op_id])?;
    Ok(())
}

/// Explicit user decision: leave failed files out of the vault (they stay in the original folder).
pub fn skip_failed(db: &Db, op_id: &str) -> Result<()> {
    db.lock().execute("UPDATE operation_journal SET status='skipped' WHERE operation_id=?1 AND status='error'", [op_id])?;
    Ok(())
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ItemError {
    pub path: String,
    pub error: String,
}

pub fn list_errors(db: &Db, op_id: &str, limit: i64) -> Result<Vec<ItemError>> {
    let c = db.lock();
    let mut st = c.prepare("SELECT item_path_reference, COALESCE(error,'') FROM operation_journal WHERE operation_id=?1 AND status='error' ORDER BY item_id LIMIT ?2")?;
    let rows = st.query_map(params![op_id, limit], |r| Ok(ItemError { path: r.get(0)?, error: r.get(1)? }))?.collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

/// Re-derives progress counters from the journal (used when resuming).
pub fn load_counters(db: &Db, op_id: &str, ctrl: &Control) -> Result<()> {
    let c = db.lock();
    let (files, bytes, tf, tb): (i64, i64, i64, i64) = c.query_row(
        "SELECT
           COALESCE(SUM(CASE WHEN status IN ('done','skipped') AND kind='f' THEN 1 ELSE 0 END),0),
           COALESCE(SUM(CASE WHEN status IN ('done','skipped') AND kind='f' THEN size ELSE 0 END),0),
           COALESCE(SUM(CASE WHEN kind='f' THEN 1 ELSE 0 END),0),
           COALESCE(SUM(CASE WHEN kind='f' THEN size ELSE 0 END),0)
         FROM operation_journal WHERE operation_id=?1",
        [op_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    ctrl.processed_files.store(files as u64, Ordering::Relaxed);
    ctrl.processed_bytes.store(bytes as u64, Ordering::Relaxed);
    ctrl.total_files.store(tf as u64, Ordering::Relaxed);
    ctrl.total_bytes.store(tb as u64, Ordering::Relaxed);
    ctrl.failed_files.store(0, Ordering::Relaxed);
    Ok(())
}

/// Runs `f` over all pending journal items with a bounded worker pool.
fn run_journal<F>(db: &Db, op_id: &str, ctrl: &Control, workers: usize, f: F) -> Result<()>
where
    F: Fn(&Item) -> Result<Outcome> + Sync,
{
    let workers = workers.clamp(1, 16);
    let (tx, rx) = sync_channel::<Item>(workers * 2);
    let rx = Mutex::new(rx);
    let fatal: Mutex<Option<Error>> = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let item = match rx.lock().unwrap().recv() {
                    Ok(i) => i,
                    Err(_) => break,
                };
                if ctrl.stopped() {
                    continue; // drain
                }
                ctrl.set_current(&item.rel);
                match f(&item) {
                    Ok(outcome) => {
                        if let Err(e) = mark(db, op_id, &item, &outcome) {
                            *fatal.lock().unwrap() = Some(e);
                            ctrl.abort.store(true, Ordering::Relaxed);
                            continue;
                        }
                        if item.kind == "f" {
                            ctrl.processed_files.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(Error::Cancelled) => {}
                    Err(e) => {
                        mark_error(db, op_id, &item, &e.to_string());
                        ctrl.failed_files.fetch_add(1, Ordering::Relaxed);
                        if let Error::Io(io) = &e {
                            if fsutil::is_disk_full(io) {
                                *fatal.lock().unwrap() = Some(Error::Invalid("The destination drive is full. Free up space, then resume the operation.".into()));
                                ctrl.abort.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                }
            });
        }
        let mut last = -1i64;
        'feed: loop {
            let page = match load_pending(db, op_id, last) {
                Ok(p) => p,
                Err(e) => {
                    *fatal.lock().unwrap() = Some(e);
                    ctrl.abort.store(true, Ordering::Relaxed);
                    break;
                }
            };
            if page.is_empty() {
                break;
            }
            for it in page {
                last = it.item_id;
                if ctrl.stopped() || tx.send(it).is_err() {
                    break 'feed;
                }
            }
        }
        drop(tx);
    });
    ctrl.abort.store(false, Ordering::Relaxed);
    if let Some(e) = fatal.into_inner().unwrap() {
        return Err(e);
    }
    if ctrl.cancel.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Operations table helpers
// ---------------------------------------------------------------------------

pub fn create_operation(db: &Db, vault_id: &str, op_type: &str, params_json: &str) -> Result<String> {
    let id = crypto::random_id();
    let now = now_ms();
    db.lock().execute(
        "INSERT INTO operations(id, vault_id, operation_type, status, params, created_at, updated_at) VALUES(?1,?2,?3,'running',?4,?5,?5)",
        params![id, vault_id, op_type, params_json, now],
    )?;
    Ok(id)
}

pub fn set_op_status(db: &Db, op_id: &str, status: &str, error: Option<&str>) -> Result<()> {
    db.lock().execute("UPDATE operations SET status=?2, error=?3, updated_at=?4 WHERE id=?1", params![op_id, status, error, now_ms()])?;
    Ok(())
}

pub fn save_op_progress(db: &Db, op_id: &str, ctrl: &Control) -> Result<()> {
    db.lock().execute(
        "UPDATE operations SET processed_bytes=?2, processed_files=?3, total_bytes=?4, total_files=?5, failed_files=?6, updated_at=?7 WHERE id=?1",
        params![
            op_id,
            ctrl.processed_bytes.load(Ordering::Relaxed) as i64,
            ctrl.processed_files.load(Ordering::Relaxed) as i64,
            ctrl.total_bytes.load(Ordering::Relaxed) as i64,
            ctrl.total_files.load(Ordering::Relaxed) as i64,
            ctrl.failed_files.load(Ordering::Relaxed) as i64,
            now_ms()
        ],
    )?;
    Ok(())
}

pub fn set_vault_status(db: &Db, vault_id: &str, status: &str) -> Result<()> {
    db.lock().execute("UPDATE vaults SET status=?2, updated_at=?3 WHERE id=?1", params![vault_id, status, now_ms()])?;
    Ok(())
}

pub fn blob_path(vault_dir: &Path, blob_id: &str) -> PathBuf {
    vault_dir.join(OBJECTS_DIR).join(&blob_id[..2]).join(format!("{blob_id}.dsb"))
}

// ---------------------------------------------------------------------------
// Secure Lock: create vault + journal
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct EncryptParams {
    pub walk_skipped: u64,
}

pub struct NewVaultSpec<'a> {
    pub vault_id: &'a str,
    pub source: &'a Path,
    pub vault_root: &'a Path,
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
    let vault_dir = spec.vault_root.join(spec.vault_id);
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
        ctrl.set_phase("Preparing");
        let mut batch = Vec::with_capacity(BATCH);
        let mut next_id = 0i64;
        let (mut files, mut dirs, mut bytes, mut skipped) = (0u64, 0u64, 0u64, 0u64);
        for entry in WalkDir::new(spec.source).follow_links(false).min_depth(1) {
            if ctrl.stopped() {
                return Err(Error::Cancelled);
            }
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            let meta = match fs::symlink_metadata(entry.path()) {
                Ok(m) => m,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            if is_link(&meta) || !(meta.is_dir() || meta.is_file()) {
                skipped += 1;
                continue;
            }
            let rel = rel_string(spec.source, entry.path())?;
            let kind = if meta.is_dir() { "d" } else { "f" };
            if kind == "d" {
                dirs += 1;
            } else {
                files += 1;
                bytes += meta.len();
            }
            batch.push(Item { item_id: next_id, rel, kind: kind.into(), size: if kind == "f" { meta.len() } else { 0 }, mtime: mtime_ns(&meta), attrs: fsutil::attrs(&meta), blob_id: None, sha256: None });
            next_id += 1;
            if batch.len() >= BATCH {
                insert_items(db, &op_id, &batch)?;
                batch.clear();
            }
        }
        insert_items(db, &op_id, &batch)?;

        let need = estimate_vault_bytes(files, dirs, bytes);
        let free = fsutil::free_space(&vault_dir)?;
        if need > free {
            return Err(Error::InsufficientSpace { need, free });
        }
        let p = serde_json::to_string(&EncryptParams { walk_skipped: skipped })?;
        db.lock().execute(
            "UPDATE operations SET total_files=?2, total_bytes=?3, params=?4 WHERE id=?1",
            params![op_id, files as i64, bytes as i64, p],
        )?;
        db.lock().execute("UPDATE vaults SET size_bytes=?2, file_count=?3 WHERE id=?1", params![spec.vault_id, bytes as i64, files as i64])?;
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

fn crypto_b64(b: &[u8]) -> String {
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

fn encrypt_item(job: &EncryptJob, vid: &[u8; 16], chunk: u32, item: &Item) -> Result<Outcome> {
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

fn encrypt_file_once(job: &EncryptJob, vid: &[u8; 16], chunk: u32, item: &Item, src: &Path) -> Result<Outcome> {
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

fn finalize_encrypt(job: &EncryptJob, mut header: VaultHeader, vid: &[u8; 16]) -> Result<()> {
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
            Some(id) => db
                .lock()
                .query_row("SELECT 1 FROM operation_journal WHERE operation_id=?1 AND blob_id=?2 AND status='done'", params![job.op_id, id], |_| Ok(()))
                .optional()?
                .is_some(),
            None => false,
        };
        if !keep {
            fs::remove_file(e.path())?;
        }
    }
    let _ = fs::remove_dir(objects.join("tmp"));

    // 2. Write the encrypted manifest from the journal (streamed, bounded memory).
    let tmp = job.vault_dir.join(format!("{MANIFEST_FILE}.tmp"));
    let (mut w, _) = BlobWriter::new(BufWriter::with_capacity(READ_BUF, File::create(&tmp)?), job.vk, vid, BlobKind::Manifest, header.chunk_size)?;
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
    tx.execute(
        "UPDATE operations SET status='completed', processed_bytes=total_bytes, processed_files=?2, error=NULL, updated_at=?3 WHERE id=?1",
        params![job.op_id, files as i64, now],
    )?;
    tx.execute("DELETE FROM operation_journal WHERE operation_id=?1", [job.op_id])?;
    tx.commit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Restore (decrypt)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DecryptParams {
    pub dest: String,
    /// "fail" | "skip" | "rename" – existing files are never overwritten.
    pub conflict: String,
    pub prev_status: String,
}

pub fn prepare_decrypt(db: &Db, op_id: &str, vault_dir: &Path, vk: &[u8; 32], p: &DecryptParams, ctrl: &Control) -> Result<()> {
    ctrl.set_phase("Verifying vault");
    let header = VaultHeader::read(vault_dir)?;
    header.verify_mac(vk)?;
    if !header.sealed {
        return Err(Error::Integrity("this vault was never completed".into()));
    }
    let vid = header.vault_id_bytes()?;
    let dest = PathBuf::from(&p.dest);
    if let Ok(m) = fs::symlink_metadata(&dest) {
        if !m.is_dir() || is_link(&m) {
            return Err(Error::Conflict("the destination exists and is not a folder".into()));
        }
    }
    let mut batch = Vec::with_capacity(BATCH);
    let mut next = 0i64;
    let (mut missing, mut conflicts, mut files, mut bytes) = (0u64, 0u64, 0u64, 0u64);
    let mut conflict_sample = String::new();
    read_manifest(BufReader::new(File::open(vault_dir.join(MANIFEST_FILE))?), vk, &vid, |line| {
        if ctrl.stopped() {
            return Err(Error::Cancelled);
        }
        let item = match line {
            Line::Dir { p: rel, a, m } => Item { item_id: next, rel, kind: "d".into(), size: 0, mtime: m, attrs: a, blob_id: None, sha256: None },
            Line::File { p: rel, s, a, m, b, h, .. } => {
                let ok = hex::decode(&b).map(|v| v.len() == 16).unwrap_or(false)
                    && fs::metadata(blob_path(vault_dir, &b)).map(|md| md.len() == blob_size(s, header.chunk_size)).unwrap_or(false);
                if !ok {
                    missing += 1;
                }
                if p.conflict == "fail" && fs::symlink_metadata(dest.join(safe_rel_path(&rel)?)).is_ok() {
                    conflicts += 1;
                    if conflict_sample.is_empty() {
                        conflict_sample = rel.clone();
                    }
                }
                files += 1;
                bytes += s;
                Item { item_id: next, rel, kind: "f".into(), size: s, mtime: m, attrs: a, blob_id: Some(b), sha256: Some(h) }
            }
            _ => return Ok(()),
        };
        next += 1;
        batch.push(item);
        if batch.len() >= BATCH {
            insert_items(db, op_id, &batch)?;
            batch.clear();
        }
        Ok(())
    })?;
    insert_items(db, op_id, &batch)?;
    if missing > 0 {
        return Err(Error::Integrity(format!("{missing} encrypted object(s) are missing or damaged; nothing was restored")));
    }
    if conflicts > 0 {
        return Err(Error::Conflict(format!("{conflicts} file(s) already exist at the destination (for example \"{conflict_sample}\"). Choose another location or a conflict option; files are never overwritten.")));
    }
    let free = fsutil::free_space(&dest)?;
    if bytes > free {
        return Err(Error::InsufficientSpace { need: bytes, free });
    }
    db.lock().execute("UPDATE operations SET total_files=?2, total_bytes=?3 WHERE id=?1", params![op_id, files as i64, bytes as i64])?;
    Ok(())
}

pub struct DecryptJob<'a> {
    pub db: &'a Db,
    pub op_id: &'a str,
    pub vault_id: &'a str,
    pub vault_dir: &'a Path,
    pub vk: &'a [u8; 32],
    pub params: &'a DecryptParams,
    pub workers: usize,
    pub ctrl: &'a Control,
}

pub fn run_decrypt(job: &DecryptJob) -> Result<()> {
    let header = VaultHeader::read(job.vault_dir)?;
    header.verify_mac(job.vk)?;
    let vid = header.vault_id_bytes()?;
    let dest = PathBuf::from(&job.params.dest);
    fs::create_dir_all(&dest)?;
    load_counters(job.db, job.op_id, job.ctrl)?;
    job.ctrl.set_phase("Decrypting");
    run_journal(job.db, job.op_id, job.ctrl, job.workers, |item| decrypt_item(job, &vid, &dest, item))?;
    let failed = count_status(job.db, job.op_id, "error")?;
    if failed > 0 {
        return Err(Error::Invalid(format!("{failed} item(s) could not be restored. The vault is intact; retry after fixing the cause.")));
    }
    job.ctrl.set_phase("Restoring folder attributes");
    // Directory timestamps/attributes last (adding files changes a folder's mtime). Deepest first.
    let mut last = i64::MAX;
    loop {
        let rows: Vec<(i64, String, Option<i64>, u32)> = {
            let c = job.db.lock();
            let mut st = c.prepare_cached(
                "SELECT item_id, item_path_reference, mtime, attrs FROM operation_journal WHERE operation_id=?1 AND kind='d' AND item_id<?2 ORDER BY item_id DESC LIMIT ?3",
            )?;
            let r = st.query_map(params![job.op_id, last, PAGE], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            r
        };
        if rows.is_empty() {
            break;
        }
        for (id, rel, mtime, attrs) in rows {
            last = id;
            let p = dest.join(safe_rel_path(&rel)?);
            let _ = fsutil::set_mtime(&p, mtime);
            if attrs & RESTORABLE_ATTRS & !fsutil::FILE_ATTRIBUTE_ARCHIVE != 0 {
                let _ = fsutil::set_attrs(&p, attrs & RESTORABLE_ATTRS);
            }
        }
    }
    let now = now_ms();
    let mut c = job.db.lock();
    let tx = c.transaction()?;
    tx.execute("UPDATE vaults SET status='restored', updated_at=?2 WHERE id=?1", params![job.vault_id, now])?;
    tx.execute("UPDATE operations SET status='completed', processed_bytes=total_bytes, error=NULL, updated_at=?2 WHERE id=?1", params![job.op_id, now])?;
    tx.execute("DELETE FROM operation_journal WHERE operation_id=?1", [job.op_id])?;
    tx.commit()?;
    Ok(())
}

fn unique_target(target: &Path) -> Result<PathBuf> {
    let stem = target.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = target.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    for n in 1..10_000 {
        let label = if n == 1 { " (restored)".to_string() } else { format!(" (restored {n})") };
        let c = target.with_file_name(format!("{stem}{label}{ext}"));
        if fs::symlink_metadata(&c).is_err() {
            return Ok(c);
        }
    }
    Err(Error::Conflict("could not find a free file name".into()))
}

fn decrypt_item(job: &DecryptJob, vid: &[u8; 16], dest: &Path, item: &Item) -> Result<Outcome> {
    let rel = safe_rel_path(&item.rel)?;
    let target = dest.join(&rel);
    if item.kind == "d" {
        if let Ok(m) = fs::symlink_metadata(&target) {
            if !m.is_dir() || is_link(&m) {
                return Err(Error::Conflict("a file with this folder's name already exists".into()));
            }
        }
        fs::create_dir_all(&target)?;
        return Ok(Outcome::Done { blob_id: None, sha256: None, chunks: None, size: 0, mtime: item.mtime, attrs: item.attrs });
    }
    let parent = target.parent().ok_or_else(|| Error::Invalid("bad target".into()))?;
    fs::create_dir_all(parent)?;
    let final_target = match fs::symlink_metadata(&target) {
        Ok(_) => match job.params.conflict.as_str() {
            "skip" => return Ok(Outcome::Skipped("already exists at destination".into())),
            "rename" => unique_target(&target)?,
            _ => return Err(Error::Conflict("file already exists at destination".into())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => target.clone(),
        Err(e) => return Err(e.into()),
    };
    let blob_id = item.blob_id.as_deref().ok_or_else(|| Error::Integrity("missing object id".into()))?;
    let fid: [u8; 16] = hex::decode(blob_id).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| Error::Integrity("bad object id".into()))?;
    let expect_sha = item.sha256.as_deref().unwrap_or("");
    let tmp = parent.join(format!("~dirshield-{}-{}.tmp", &job.op_id[..8], item.item_id));
    let _ = fs::remove_file(&tmp); // leftover from an interrupted attempt (our own temp name)
    let ctrl = job.ctrl;
    let mut prog = ItemProgress::new(ctrl);
    let result = (|| -> Result<Outcome> {
        let mut out = BufWriter::with_capacity(READ_BUF, fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?);
        let mut h = Sha256::new();
        let blob = BufReader::with_capacity(READ_BUF, File::open(blob_path(job.vault_dir, blob_id))?);
        let info = decrypt_blob(blob, job.vk, vid, BlobKind::File, Some(&fid), |b| {
            ctrl.checkpoint()?;
            h.update(b);
            out.write_all(b)?;
            prog.add(b.len() as u64 / 2);
            Ok(())
        })?;
        let f = out.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        drop(f);
        if info.plain_bytes != item.size || hex::encode(h.finalize()) != expect_sha {
            return Err(Error::Integrity("decrypted data does not match the recorded checksum".into()));
        }
        // Verify what actually landed on disk.
        let mut vh = Sha256::new();
        let mut r = File::open(&tmp)?;
        let mut buf = vec![0u8; READ_BUF];
        loop {
            ctrl.checkpoint()?;
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            vh.update(&buf[..n]);
            prog.add(n as u64 / 2);
        }
        drop(r);
        if hex::encode(vh.finalize()) != expect_sha {
            return Err(Error::Integrity("restored file failed verification on disk".into()));
        }
        fsutil::set_mtime(&tmp, item.mtime)?;
        fsutil::rename_noreplace(&tmp, &final_target).map_err(|e| {
            if e.raw_os_error() == Some(183) || e.raw_os_error() == Some(80) {
                Error::Conflict("file appeared at destination during restore".into())
            } else {
                Error::Io(e)
            }
        })?;
        let a = item.attrs & RESTORABLE_ATTRS & !fsutil::FILE_ATTRIBUTE_ARCHIVE;
        if a != 0 {
            let _ = fsutil::set_attrs(&final_target, item.attrs & RESTORABLE_ATTRS);
        }
        prog.settle(item.size);
        Ok(Outcome::Done { blob_id: None, sha256: None, chunks: None, size: item.size, mtime: item.mtime, attrs: item.attrs })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        prog.rollback();
    }
    result
}

// ---------------------------------------------------------------------------
// Full integrity verification (no plaintext written)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Removal of plaintext originals (explicit user action, after sealing)
// ---------------------------------------------------------------------------

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
