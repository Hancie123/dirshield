//! Background operation manager. Each operation runs on its own thread with a
//! shared `Control`; a ticker emits `op-progress` events to the UI and
//! persists counters so a crash loses at most a couple of seconds of progress
//! bookkeeping (the journal itself is authoritative).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::vault::engine::{self, Control};

pub struct ActiveOp {
    pub id: String,
    pub vault_id: String,
    pub op_type: String,
    pub ctrl: Control,
    started: Instant,
    sample: Mutex<(Instant, u64, f64)>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub id: String,
    pub vault_id: String,
    pub op_type: String,
    pub status: String,
    pub phase: String,
    pub current: String,
    pub processed_bytes: u64,
    pub total_bytes: u64,
    pub processed_files: u64,
    pub total_files: u64,
    pub failed_files: u64,
    pub speed_bps: f64,
    pub eta_secs: Option<f64>,
    pub elapsed_secs: f64,
}

impl ActiveOp {
    pub fn snapshot(&self) -> Progress {
        let c = &self.ctrl;
        let processed = c.processed_bytes.load(Ordering::Relaxed);
        let total = c.total_bytes.load(Ordering::Relaxed);
        let paused = c.pause.load(Ordering::Relaxed);
        let speed = {
            let mut s = self.sample.lock().unwrap();
            let dt = s.0.elapsed().as_secs_f64();
            if dt >= 1.0 {
                let inst = processed.saturating_sub(s.1) as f64 / dt;
                // exponential smoothing for a stable readout
                s.2 = if s.2 == 0.0 { inst } else { s.2 * 0.7 + inst * 0.3 };
                *s = (Instant::now(), processed, s.2);
            }
            if paused {
                0.0
            } else {
                s.2
            }
        };
        let eta = if speed > 1.0 && total > processed { Some((total - processed) as f64 / speed) } else { None };
        Progress {
            id: self.id.clone(),
            vault_id: self.vault_id.clone(),
            op_type: self.op_type.clone(),
            status: if paused { "paused".into() } else { "running".into() },
            phase: c.phase.lock().unwrap().clone(),
            current: c.current.lock().unwrap().clone(),
            processed_bytes: processed,
            total_bytes: total,
            processed_files: c.processed_files.load(Ordering::Relaxed),
            total_files: c.total_files.load(Ordering::Relaxed),
            failed_files: c.failed_files.load(Ordering::Relaxed),
            speed_bps: speed,
            eta_secs: eta,
            elapsed_secs: self.started.elapsed().as_secs_f64(),
        }
    }
}

#[derive(Default)]
pub struct OpsManager {
    active: Mutex<HashMap<String, Arc<ActiveOp>>>,
}

impl OpsManager {
    pub fn get(&self, id: &str) -> Option<Arc<ActiveOp>> {
        self.active.lock().unwrap().get(id).cloned()
    }

    pub fn is_vault_busy(&self, vault_id: &str) -> bool {
        self.active.lock().unwrap().values().any(|o| o.vault_id == vault_id)
    }

    pub fn snapshots(&self) -> Vec<Progress> {
        self.active.lock().unwrap().values().map(|o| o.snapshot()).collect()
    }

    pub fn any_active(&self) -> bool {
        !self.active.lock().unwrap().is_empty()
    }

    /// Spawns `work` on a background thread. `done` runs on that thread after
    /// `work` finishes to record final status (it receives the result).
    pub fn spawn<W, D>(self: &Arc<Self>, app: AppHandle, db: Db, op_id: String, vault_id: String, op_type: &str, total_files: u64, total_bytes: u64, work: W, done: D) -> Result<()>
    where
        W: FnOnce(&Control) -> Result<()> + Send + 'static,
        D: FnOnce(&Result<()>) + Send + 'static,
    {
        if self.is_vault_busy(&vault_id) {
            return Err(Error::Conflict("Another operation is already running for this folder.".into()));
        }
        let op = Arc::new(ActiveOp {
            id: op_id.clone(),
            vault_id,
            op_type: op_type.into(),
            ctrl: Control::default(),
            started: Instant::now(),
            sample: Mutex::new((Instant::now(), 0, 0.0)),
        });
        op.ctrl.total_files.store(total_files, Ordering::Relaxed);
        op.ctrl.total_bytes.store(total_bytes, Ordering::Relaxed);
        self.active.lock().unwrap().insert(op_id.clone(), op.clone());
        let me = self.clone();
        let _ = app.emit("ops-changed", ());
        std::thread::Builder::new()
            .name(format!("op-{}", &op_id[..8]))
            .spawn(move || {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&op.ctrl)))
                    .unwrap_or_else(|_| Err(Error::Invalid("internal error (the operation stopped safely; originals are untouched)".into())));
                let _ = engine::save_op_progress(&db, &op_id, &op.ctrl);
                match &r {
                    Ok(()) => {
                        let _ = engine::set_op_status(&db, &op_id, "completed", None);
                    }
                    Err(Error::Cancelled) => {
                        let _ = engine::set_op_status(&db, &op_id, "cancelled", None);
                    }
                    Err(e) => {
                        let _ = engine::set_op_status(&db, &op_id, "failed", Some(&e.to_string()));
                    }
                }
                done(&r);
                me.active.lock().unwrap().remove(&op_id);
                let _ = app.emit("ops-changed", ());
            })
            .map_err(Error::Io)?;
        Ok(())
    }

    /// Ticker: emits progress and persists counters while work is active.
    pub fn start_ticker(self: &Arc<Self>, app: AppHandle, db: Db) {
        let me = self.clone();
        std::thread::spawn(move || {
            let mut n = 0u64;
            loop {
                std::thread::sleep(Duration::from_millis(400));
                if !me.any_active() {
                    continue;
                }
                let snaps = me.snapshots();
                let _ = app.emit("op-progress", &snaps);
                n += 1;
                if n % 5 == 0 {
                    for op in me.active.lock().unwrap().values() {
                        let _ = engine::save_op_progress(&db, &op.id, &op.ctrl);
                        let status = if op.ctrl.pause.load(Ordering::Relaxed) { "paused" } else { "running" };
                        let _ = db.lock().execute("UPDATE operations SET status=?2 WHERE id=?1 AND status IN ('running','paused')", rusqlite::params![op.id, status]);
                    }
                }
            }
        });
    }
}
