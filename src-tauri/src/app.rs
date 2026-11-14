//! Application state, data directories and startup crash recovery.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use rusqlite::params;

use crate::auth::Session;
use crate::db::{now_ms, Db};
use crate::error::Result;
use crate::ops::OpsManager;
use crate::shell::ShellAction;
use crate::vault::header::{VaultHeader, MANIFEST_FILE};
use crate::{fsutil, search};

pub struct Dirs {
    /// %LOCALAPPDATA%\DirShield – never removed by the uninstaller.
    pub base: PathBuf,
    pub db: PathBuf,
    pub vaults: PathBuf,
    pub quick_store: PathBuf,
}

impl Dirs {
    pub fn from_env() -> Self {
        let base = std::env::var_os("DIRSHIELD_DATA_DIR")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("DirShield")))
            .unwrap_or_else(|| PathBuf::from("DirShield"));
        Self { db: base.join("data").join("dirshield.db"), vaults: base.join("Vaults"), quick_store: base.join("QuickStore"), base }
    }

    pub fn prepare(&self) -> Result<()> {
        for d in [&self.vaults, &self.quick_store, &self.base.join("data")] {
            std::fs::create_dir_all(d)?;
        }
        // Keep DirShield storage out of Explorer and the search index.
        let _ = search::mark_not_indexed(&self.base);
        for d in [&self.vaults, &self.quick_store] {
            let _ = search::mark_not_indexed(d);
            let a = fsutil::get_attrs(d).unwrap_or(0) & fsutil::RESTORABLE_ATTRS;
            let _ = fsutil::set_attrs(d, a | fsutil::FILE_ATTRIBUTE_HIDDEN | fsutil::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
        }
        Ok(())
    }
}

pub struct AppState {
    pub db: Db,
    pub session: Session,
    pub dirs: Dirs,
    pub ops: Arc<OpsManager>,
    pub pending: Mutex<Option<ShellAction>>,
    pub mica: AtomicBool,
}

impl AppState {
    pub fn new() -> Result<Self> {
        let dirs = Dirs::from_env();
        dirs.prepare()?;
        let db = Db::open(&dirs.db)?;
        reconcile(&db)?;
        let st = Self { db, session: Session::default(), dirs, ops: Arc::new(OpsManager::default()), pending: Mutex::new(None), mica: AtomicBool::new(false) };
        if let Some(m) = st.db.get_setting("autoLockMinutes")?.and_then(|v| v.parse::<u64>().ok()) {
            st.session.set_timeout(std::time::Duration::from_secs(m * 60));
        }
        // One-time, best-effort: ask Windows Search to exclude DirShield storage (needs admin to succeed).
        if st.db.get_setting("searchExclusionApplied")?.is_none() {
            let ok = search::exclude(&st.dirs.base);
            st.db.set_setting("searchExclusionApplied", if ok { "1" } else { "0" })?;
        }
        Ok(st)
    }
}

/// Crash recovery: anything that was running when the process died is marked
/// interrupted; vaults whose commit point (sealed header) was reached are
/// completed; everything else is left resumable. Nothing is deleted here.
pub fn reconcile(db: &Db) -> Result<()> {
    let now = now_ms();
    db.lock().execute("UPDATE operations SET status='interrupted', updated_at=?1 WHERE status IN ('running','paused')", [now])?;
    let rows: Vec<(String, String, String)> = {
        let c = db.lock();
        let mut st = c.prepare("SELECT id, status, vault_path FROM vaults WHERE status IN ('encrypting','restoring','removing')")?;
        let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        r
    };
    for (id, status, path) in rows {
        let dir = PathBuf::from(&path);
        let new_status = match status.as_str() {
            "encrypting" => {
                let sealed = VaultHeader::read(&dir).map(|h| h.sealed).unwrap_or(false) && dir.join(MANIFEST_FILE).exists();
                if sealed {
                    // The commit point was reached; only the DB update was lost.
                    let c = db.lock();
                    c.execute(
                        "UPDATE operations SET status='completed', processed_bytes=total_bytes, processed_files=total_files, updated_at=?2 WHERE vault_id=?1 AND operation_type='encrypt'",
                        params![id, now],
                    )?;
                    c.execute("DELETE FROM operation_journal WHERE operation_id IN (SELECT id FROM operations WHERE vault_id=?1 AND operation_type='encrypt')", [&id])?;
                    "encrypted".to_string()
                } else {
                    "incomplete".to_string()
                }
            }
            "restoring" => {
                let prev: Option<String> = db
                    .lock()
                    .query_row("SELECT params FROM operations WHERE vault_id=?1 AND operation_type='decrypt' ORDER BY created_at DESC LIMIT 1", [&id], |r| r.get(0))
                    .ok();
                prev.and_then(|p| serde_json::from_str::<crate::vault::engine::DecryptParams>(&p).ok()).map(|p| p.prev_status).unwrap_or_else(|| "locked".into())
            }
            _ => "encrypted".to_string(),
        };
        db.lock().execute("UPDATE vaults SET status=?2, updated_at=?3 WHERE id=?1", params![id, new_status, now])?;
        db.log("recovered_after_restart", Some(&id), "info", Some(&format!("{status} -> {new_status}")));
    }
    Ok(())
}
