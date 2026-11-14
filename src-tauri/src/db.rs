//! SQLite storage with versioned migrations (PRAGMA user_version).
//!
//! Nothing secret is stored in plaintext: the master key exists only wrapped
//! (by the Argon2id password key and by the recovery key); folder names and
//! original paths are AES-256-GCM encrypted with a key derived from the
//! master key. Journal rows contain relative paths only while an operation is
//! running and are purged once it completes.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::Result;

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

const MIGRATIONS: &[&str] = &[
    // v1
    r#"
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        master_key_metadata TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE vaults (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,              -- encrypted
        original_path TEXT NOT NULL,     -- encrypted
        vault_path TEXT NOT NULL,        -- vault directory (secure) or current location (quick)
        protection_mode TEXT NOT NULL,   -- 'quick' | 'secure'
        key_mode TEXT NOT NULL,          -- 'master' | 'password'
        status TEXT NOT NULL,
        size_bytes INTEGER NOT NULL DEFAULT 0,
        file_count INTEGER NOT NULL DEFAULT 0,
        skipped_count INTEGER NOT NULL DEFAULT 0,
        quick_state TEXT,                -- JSON (quick lock bookkeeping)
        locked_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE vault_key_wrappers (
        id INTEGER PRIMARY KEY,
        vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        wrapper_type TEXT NOT NULL,      -- 'master' | 'password' | 'recovery' | 'quick_password'
        kdf_salt TEXT,
        kdf_parameters TEXT,
        wrapped_vault_key TEXT NOT NULL, -- sealed (never a raw key)
        created_at INTEGER NOT NULL
    );
    CREATE TABLE operations (
        id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        operation_type TEXT NOT NULL,    -- 'encrypt' | 'decrypt' | 'verify' | 'cleanup'
        status TEXT NOT NULL,            -- 'running' | 'paused' | 'interrupted' | 'failed' | 'cancelled' | 'completed'
        total_bytes INTEGER NOT NULL DEFAULT 0,
        processed_bytes INTEGER NOT NULL DEFAULT 0,
        total_files INTEGER NOT NULL DEFAULT 0,
        processed_files INTEGER NOT NULL DEFAULT 0,
        failed_files INTEGER NOT NULL DEFAULT 0,
        last_processed_item INTEGER,
        params TEXT,
        error TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE operation_journal (
        id INTEGER PRIMARY KEY,
        operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
        item_id INTEGER NOT NULL,
        item_path_reference TEXT NOT NULL,
        kind TEXT NOT NULL,              -- 'f' | 'd'
        size INTEGER NOT NULL DEFAULT 0,
        mtime INTEGER,
        attrs INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL,            -- 'pending' | 'done' | 'error' | 'skipped'
        processed_bytes INTEGER NOT NULL DEFAULT 0,
        blob_id TEXT,
        sha256 TEXT,
        chunks INTEGER,
        error TEXT,
        updated_at INTEGER NOT NULL,
        UNIQUE(operation_id, item_id)
    );
    CREATE INDEX journal_status ON operation_journal(operation_id, status, item_id);
    CREATE INDEX journal_blob ON operation_journal(operation_id, blob_id);
    CREATE TABLE settings (
        id INTEGER PRIMARY KEY,
        setting_key TEXT NOT NULL UNIQUE,
        setting_value TEXT NOT NULL
    );
    CREATE TABLE activity_logs (
        id INTEGER PRIMARY KEY,
        action TEXT NOT NULL,
        vault_id TEXT,
        status TEXT NOT NULL,
        detail TEXT,
        created_at INTEGER NOT NULL
    );
    CREATE INDEX activity_time ON activity_logs(created_at DESC);
    "#,
];

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        let db = Db(Arc::new(Mutex::new(conn)));
        db.migrate()?;
        Ok(db)
    }

    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn migrate(&self) -> Result<()> {
        let mut c = self.lock();
        let ver: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(ver as usize) {
            let tx = c.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
            tx.commit()?;
        }
        Ok(())
    }

    // ---------------- settings ----------------
    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self.lock().query_row("SELECT setting_value FROM settings WHERE setting_key=?1", [key], |r| r.get(0)).optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.lock().execute(
            "INSERT INTO settings(setting_key, setting_value) VALUES(?1, ?2)
             ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn all_settings(&self) -> Result<Vec<(String, String)>> {
        let c = self.lock();
        let mut st = c.prepare("SELECT setting_key, setting_value FROM settings ORDER BY setting_key")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    // ---------------- activity ----------------
    pub fn log(&self, action: &str, vault_id: Option<&str>, status: &str, detail: Option<&str>) {
        // Activity logging must never break an operation.
        let _ = self.lock().execute(
            "INSERT INTO activity_logs(action, vault_id, status, detail, created_at) VALUES(?1,?2,?3,?4,?5)",
            params![action, vault_id, status, detail, now_ms()],
        );
    }
}
