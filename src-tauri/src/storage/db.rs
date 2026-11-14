//! SQLite storage with versioned migrations (PRAGMA user_version).
//!
//! Nothing secret is stored in plaintext: the master key exists only wrapped
//! (by the Argon2id password key and by the recovery key); folder names and
//! original paths are AES-256-GCM encrypted with a key derived from the
//! master key. Journal rows contain relative paths only while an operation is
//! running and are purged once it completes.

use parking_lot::{Mutex, MutexGuard};
use std::path::Path;
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::domain::error::Result;
use crate::security::crypto;

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
    // v2: incremental re-lock + where a vault was last restored to
    r#"
    -- The sealed manifest's file entries, copied in while a re-lock runs so
    -- unchanged files can reuse their encrypted objects. Purged on completion.
    CREATE TABLE relock_base (
        operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
        path TEXT NOT NULL,
        size INTEGER NOT NULL,
        mtime INTEGER,
        blob_id TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        chunks INTEGER NOT NULL,
        PRIMARY KEY(operation_id, path)
    ) WITHOUT ROWID;
    CREATE INDEX relock_base_blob ON relock_base(operation_id, blob_id);
    ALTER TABLE vaults ADD COLUMN restored_path TEXT; -- encrypted
    "#,
    // v3: hash-chained activity log (see `Db::log`)
    r#"
    ALTER TABLE activity_logs ADD COLUMN seq INTEGER;      -- position in the chain
    ALTER TABLE activity_logs ADD COLUMN prev_hash TEXT;   -- hash of the entry before
    ALTER TABLE activity_logs ADD COLUMN hash TEXT;        -- SHA-256 over prev_hash and this entry
    CREATE UNIQUE INDEX activity_seq ON activity_logs(seq);
    "#,
];

/// Chain head before the first entry.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const LOG_HEAD: &str = "log.head";
const LOG_CHECKPOINT: &str = "log.checkpoint";

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

    /// Writes a consistent copy of the whole database to `dest` (which must
    /// not exist yet). The copy is a plain SQLite file.
    pub fn snapshot_to(&self, dest: &Path) -> Result<()> {
        self.lock().execute("VACUUM INTO ?1", [dest.to_string_lossy()])?;
        Ok(())
    }

    /// Replaces the whole database with the SQLite file at `src` (online
    /// backup API, so the open connection stays valid), then brings it up to
    /// the current schema.
    pub fn replace_from(&self, src: &Path) -> Result<()> {
        let from = Connection::open_with_flags(src, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        {
            let mut c = self.lock();
            let b = rusqlite::backup::Backup::new(&from, &mut c)?;
            b.run_to_completion(256, std::time::Duration::ZERO, None)?;
        }
        self.migrate()
    }

    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.0.lock()
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

    pub fn delete_setting(&self, key: &str) -> Result<()> {
        self.lock().execute("DELETE FROM settings WHERE setting_key=?1", [key])?;
        Ok(())
    }

    pub fn all_settings(&self) -> Result<Vec<(String, String)>> {
        let c = self.lock();
        let mut st = c.prepare("SELECT setting_key, setting_value FROM settings ORDER BY setting_key")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    // ---------------- activity ----------------

    /// Appends an entry to the activity log.
    ///
    /// Entries form a hash chain: each stores the SHA-256 of the previous
    /// entry's hash and its own fields, and the chain's head is kept in the
    /// settings. While DirShield is signed in, the head is also sealed with a
    /// key derived from the master key (see [`Db::checkpoint_log`]), so
    /// deleting or editing entries is detected by [`Db::verify_log`] even by
    /// someone who can rewrite the database file.
    pub fn log(&self, action: &str, vault_id: Option<&str>, status: &str, detail: Option<&str>) {
        // Activity logging must never break an operation.
        let _ = self.append_log(action, vault_id, status, detail);
    }

    fn append_log(&self, action: &str, vault_id: Option<&str>, status: &str, detail: Option<&str>) -> Result<()> {
        let mut c = self.lock();
        let tx = c.transaction()?;
        let head: Option<String> = tx.query_row("SELECT setting_value FROM settings WHERE setting_key=?1", [LOG_HEAD], |r| r.get(0)).optional()?;
        let (seq, prev) = parse_head(head.as_deref());
        let seq = seq + 1;
        let now = now_ms();
        let hash = entry_hash(&prev, seq, action, vault_id, status, detail, now);
        tx.execute(
            "INSERT INTO activity_logs(action, vault_id, status, detail, created_at, seq, prev_hash, hash) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![action, vault_id, status, detail, now, seq, prev, hash],
        )?;
        tx.execute(
            "INSERT INTO settings(setting_key, setting_value) VALUES(?1, ?2) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value",
            params![LOG_HEAD, format!("{seq}:{hash}")],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Seals the current chain head with a key derived from the master key.
    /// Called periodically while signed in; cheap when nothing changed.
    pub fn checkpoint_log(&self, master: &[u8; 32]) -> Result<()> {
        let Some(head) = self.get_setting(LOG_HEAD)? else { return Ok(()) };
        if let Some(cp) = self.get_setting(LOG_CHECKPOINT)? {
            if cp.rsplit_once(':').map(|(h, _)| h) == Some(head.as_str()) {
                return Ok(());
            }
        }
        let mac = crypto::hmac_sha256(&*log_key(master), head.as_bytes());
        self.set_setting(LOG_CHECKPOINT, &format!("{head}:{}", hex::encode(mac)))
    }

    /// Empties the log, keeping the chain unbroken: the first new entry
    /// links to the last deleted one and records that the log was cleared.
    pub fn clear_log(&self, master: &[u8; 32]) -> Result<()> {
        self.lock().execute("DELETE FROM activity_logs", [])?;
        self.append_log("activity_cleared", None, "info", None)?;
        self.checkpoint_log(master)
    }

    /// Re-computes the chain and checks it against the sealed checkpoint.
    pub fn verify_log(&self, master: &[u8; 32]) -> Result<LogCheck> {
        type Row = (i64, String, Option<String>, String, Option<String>, i64, Option<String>, Option<String>);
        let rows: Vec<Row> = {
            let c = self.lock();
            let mut st = c.prepare("SELECT seq, action, vault_id, status, detail, created_at, prev_hash, hash FROM activity_logs WHERE seq IS NOT NULL ORDER BY seq")?;
            let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            r
        };
        let mut out = LogCheck { ok: true, entries: rows.len() as i64, ..Default::default() };
        out.unchained = self.lock().query_row("SELECT COUNT(*) FROM activity_logs WHERE seq IS NULL", [], |r| r.get(0))?;
        let mut problems: Vec<String> = Vec::new();
        let mut last: Option<(i64, String)> = None;
        for (seq, action, vid, status, detail, at, prev, hash) in &rows {
            let prev = prev.clone().unwrap_or_default();
            let hash = hash.clone().unwrap_or_default();
            if entry_hash(&prev, *seq, action, vid.as_deref(), status, detail.as_deref(), *at) != hash {
                problems.push(format!("Entry #{seq} (\"{action}\") was changed after it was written."));
            }
            match &last {
                Some((ls, lh)) => {
                    let gap = seq - ls - 1;
                    if gap > 0 {
                        problems.push(format!("{gap} entr{} missing between #{ls} and #{seq}.", if gap == 1 { "y is" } else { "ies are" }));
                    } else if prev != *lh {
                        problems.push(format!("Entry #{seq} does not follow entry #{ls}."));
                    }
                }
                // The oldest remaining entry is either the very first one or
                // the note left when the log was cleared.
                None if prev != GENESIS && action != "activity_cleared" => problems.push(format!("Entries before #{seq} were deleted without clearing the log.")),
                None => {}
            }
            last = Some((*seq, hash));
        }
        let head = parse_head(self.get_setting(LOG_HEAD)?.as_deref());
        match &last {
            Some((ls, lh)) if head.0 != *ls || head.1 != *lh => problems.push(format!("Entries after #{ls} were deleted.")),
            None if head.0 > 0 => problems.push("Every entry was deleted without clearing the log.".into()),
            _ => {}
        }
        match self.get_setting(LOG_CHECKPOINT)? {
            Some(cp) => {
                let parts: Vec<&str> = cp.split(':').collect();
                let mac_ok = parts.len() == 3 && hex::decode(parts[2]).map(|t| crypto::hmac_verify(&*log_key(master), format!("{}:{}", parts[0], parts[1]).as_bytes(), &t)).unwrap_or(false);
                if !mac_ok {
                    problems.push("The sealed checkpoint is not valid: the log or its checkpoint was replaced.".into());
                } else {
                    let cseq: i64 = parts[0].parse().unwrap_or(0);
                    out.sealed_through = cseq;
                    match rows.iter().find(|r| r.0 == cseq) {
                        Some(r) if r.7.as_deref() == Some(parts[1]) => {}
                        Some(_) => problems.push(format!("Entry #{cseq} does not match the sealed checkpoint.")),
                        // A real clear is sealed straight away, so a sealed
                        // entry older than every remaining one means the log
                        // was emptied behind DirShield's back.
                        None => problems.push(format!("Sealed entry #{cseq} is missing.")),
                    }
                    if head.0 < cseq {
                        problems.push("The log was rolled back to an older state.".into());
                    }
                }
            }
            None if head.0 > 0 => problems.push("The log has not been sealed yet. It is sealed automatically while you're signed in.".into()),
            None => {}
        }
        out.ok = problems.is_empty();
        problems.truncate(20);
        out.problems = problems;
        Ok(out)
    }
}

#[derive(Serialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LogCheck {
    pub ok: bool,
    pub entries: i64,
    /// Entries written before the log was chained (older DirShield versions).
    pub unchained: i64,
    /// Newest entry covered by the sealed checkpoint.
    pub sealed_through: i64,
    pub problems: Vec<String>,
}

fn parse_head(v: Option<&str>) -> (i64, String) {
    v.and_then(|h| h.split_once(':')).and_then(|(s, h)| Some((s.parse().ok()?, h.to_string()))).unwrap_or((0, GENESIS.to_string()))
}

fn log_key(master: &[u8; 32]) -> crypto::Key32 {
    crypto::hkdf32(master, b"", b"dirshield/v1/activity-log")
}

fn entry_hash(prev: &str, seq: i64, action: &str, vault_id: Option<&str>, status: &str, detail: Option<&str>, at: i64) -> String {
    let mut h = Sha256::new();
    // Length-prefixed fields (and a marker for None), so different entries
    // never hash the same input.
    let mut field = |b: Option<&[u8]>| match b {
        Some(b) => {
            h.update([1u8]);
            h.update((b.len() as u64).to_le_bytes());
            h.update(b);
        }
        None => h.update([0u8]),
    };
    field(Some(prev.as_bytes()));
    field(Some(&seq.to_le_bytes()));
    field(Some(action.as_bytes()));
    field(vault_id.map(str::as_bytes));
    field(Some(status.as_bytes()));
    field(detail.map(str::as_bytes));
    field(Some(&at.to_le_bytes()));
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, Db) {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("t.db")).unwrap();
        (d, db)
    }

    #[test]
    fn log_chain_detects_tampering() {
        let (_d, db) = db();
        let mk = crypto::random_key();
        for i in 0..5 {
            db.log("sign_in", None, "success", Some(&i.to_string()));
        }
        db.checkpoint_log(&mk).unwrap();
        assert!(db.verify_log(&mk).unwrap().ok);

        // editing an entry
        db.lock().execute("UPDATE activity_logs SET status='failed' WHERE seq=2", []).unwrap();
        assert!(!db.verify_log(&mk).unwrap().ok);
        db.lock().execute("UPDATE activity_logs SET status='success' WHERE seq=2", []).unwrap();
        assert!(db.verify_log(&mk).unwrap().ok);

        // deleting one in the middle
        db.lock().execute("DELETE FROM activity_logs WHERE seq=3", []).unwrap();
        assert!(!db.verify_log(&mk).unwrap().ok);
    }

    #[test]
    fn log_chain_detects_truncation_and_forgery() {
        let (_d, db) = db();
        let mk = crypto::random_key();
        for _ in 0..4 {
            db.log("a", None, "success", None);
        }
        db.checkpoint_log(&mk).unwrap();
        // delete the newest entries and rewind the head: the checkpoint catches it
        db.lock().execute("DELETE FROM activity_logs WHERE seq>=3", []).unwrap();
        let h2: String = db.lock().query_row("SELECT hash FROM activity_logs WHERE seq=2", [], |r| r.get(0)).unwrap();
        db.set_setting(LOG_HEAD, &format!("2:{h2}")).unwrap();
        assert!(!db.verify_log(&mk).unwrap().ok);
        // a checkpoint forged without the key is rejected
        db.set_setting(LOG_CHECKPOINT, &format!("2:{h2}:00")).unwrap();
        assert!(!db.verify_log(&mk).unwrap().ok);
        // and one sealed with another key too
        let other = crypto::random_key();
        db.lock().execute("DELETE FROM settings WHERE setting_key=?1", [LOG_CHECKPOINT]).unwrap();
        db.checkpoint_log(&other).unwrap();
        assert!(!db.verify_log(&mk).unwrap().ok);
    }

    #[test]
    fn clearing_keeps_the_chain_valid() {
        let (_d, db) = db();
        let mk = crypto::random_key();
        db.log("a", None, "success", None);
        db.checkpoint_log(&mk).unwrap();
        db.clear_log(&mk).unwrap();
        assert!(db.verify_log(&mk).unwrap().ok);
        db.log("b", None, "success", None);
        db.checkpoint_log(&mk).unwrap();
        let r = db.verify_log(&mk).unwrap();
        assert!(r.ok, "{:?}", r.problems);
        assert_eq!(r.entries, 2);
        // silently deleting everything is not the same as clearing
        db.lock().execute("DELETE FROM activity_logs", []).unwrap();
        assert!(!db.verify_log(&mk).unwrap().ok);
        // nor is faking a clear note without the key
        db.log("activity_cleared", None, "info", None);
        assert!(!db.verify_log(&mk).unwrap().ok);
    }

    #[test]
    fn snapshot_and_replace() {
        let (d, db) = db();
        db.set_setting("x", "1").unwrap();
        let snap = d.path().join("snap.db");
        db.snapshot_to(&snap).unwrap();
        db.set_setting("x", "2").unwrap();
        db.replace_from(&snap).unwrap();
        assert_eq!(db.get_setting("x").unwrap().as_deref(), Some("1"));
    }
}
