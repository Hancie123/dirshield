//! The operation journal (`operation_journal`) and the `operations` table:
//! every item of an operation is recorded before work starts, so it can be
//! resumed after a crash, and a bounded worker pool processes pending items.

use parking_lot::Mutex;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::sync_channel;

use rusqlite::params;
use serde::Serialize;

use super::super::header::OBJECTS_DIR;
use super::*;
use crate::domain::error::{Error, Result};
use crate::platform::fsutil::{self};
use crate::security::crypto;
use crate::storage::db::{now_ms, Db};

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

pub(super) fn insert_items(db: &Db, op_id: &str, items: &[Item]) -> Result<()> {
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

pub(super) fn load_pending(db: &Db, op_id: &str, after: i64) -> Result<Vec<Item>> {
    let c = db.lock();
    let mut st = c.prepare_cached(
        "SELECT item_id, item_path_reference, kind, size, mtime, attrs, blob_id, sha256 FROM operation_journal
         WHERE operation_id=?1 AND status='pending' AND item_id>?2 ORDER BY item_id LIMIT ?3",
    )?;
    let rows = st
        .query_map(params![op_id, after, PAGE], |r| {
            Ok(Item { item_id: r.get(0)?, rel: r.get(1)?, kind: r.get(2)?, size: r.get::<_, i64>(3)? as u64, mtime: r.get(4)?, attrs: r.get(5)?, blob_id: r.get(6)?, sha256: r.get(7)? })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(super) fn mark(db: &Db, op_id: &str, item: &Item, outcome: &Outcome) -> Result<()> {
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
            c.execute("UPDATE operation_journal SET status='skipped', error=?3, updated_at=?4 WHERE operation_id=?1 AND item_id=?2", params![op_id, item.item_id, reason, now_ms()])?;
        }
    }
    c.execute("UPDATE operations SET last_processed_item=MAX(COALESCE(last_processed_item,-1), ?2), updated_at=?3 WHERE id=?1", params![op_id, item.item_id, now_ms()])?;
    Ok(())
}

pub(super) fn mark_error(db: &Db, op_id: &str, item: &Item, msg: &str) {
    let _ = db.lock().execute("UPDATE operation_journal SET status='error', error=?3, updated_at=?4 WHERE operation_id=?1 AND item_id=?2", params![op_id, item.item_id, msg, now_ms()]);
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
pub(super) fn run_journal<F>(db: &Db, op_id: &str, ctrl: &Control, workers: usize, f: F) -> Result<()>
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
                let item = match rx.lock().recv() {
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
                            *fatal.lock() = Some(e);
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
                                *fatal.lock() = Some(Error::Invalid("The destination drive is full. Free up space, then resume the operation.".into()));
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
                    *fatal.lock() = Some(e);
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
    if let Some(e) = fatal.into_inner() {
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
