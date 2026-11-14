//! Encrypted backups of DirShield's database (`.dsbackup`).
//!
//! ```text
//! 0   8  magic "DSBACKUP"
//! 8   2  format version (u16 LE) = 1
//! 10  4  header length (u32 LE)
//! 14  .. UTF-8 JSON header (BackupHeader)
//! ..  .. AES-256-GCM: 12-byte nonce, then the SQLite file + tag
//! ```
//!
//! The header carries the master-key metadata exactly as the database holds
//! it (the master key wrapped by the master password and by the recovery
//! key; nothing in it is usable without one of those). The body key is
//! derived from the master key, and the whole header is authenticated as
//! associated data. A backup can therefore be restored with either the
//! master password that was current when it was made, or the recovery key,
//! even on a fresh install.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::domain::error::{Error, Result};
use crate::security::auth::{self, MasterKeyMetadata};
use crate::security::crypto::{self, Key32, Sealed};
use crate::storage::db::{now_ms, Db};

const MAGIC: &[u8; 8] = b"DSBACKUP";
const VERSION: u16 = 1;
pub const EXTENSION: &str = "dsbackup";

#[derive(Serialize, Deserialize)]
struct BackupHeader {
    v: u32,
    created_utc: i64,
    app_version: String,
    meta: MasterKeyMetadata,
    #[serde(with = "crypto::b64")]
    salt: Vec<u8>,
}

fn body_key(mk: &[u8; 32], salt: &[u8]) -> Key32 {
    crypto::hkdf32(mk, salt, b"dirshield/v1/backup")
}

fn aad(header_json: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(10 + header_json.len());
    a.extend_from_slice(MAGIC);
    a.extend_from_slice(&VERSION.to_le_bytes());
    a.extend_from_slice(header_json);
    a
}

/// Writes an encrypted copy of the database to `dest`. `scratch` is a
/// private folder for the short-lived plain snapshot.
pub fn create(db: &Db, mk: &[u8; 32], app_version: &str, dest: &Path, scratch: &Path) -> Result<()> {
    let meta = auth::load_metadata(db)?.ok_or(Error::NotInitialized)?;
    let snap = scratch.join(format!("backup-{}.tmp", crypto::random_id()));
    let plain = {
        let r = db.snapshot_to(&snap).and_then(|_| Ok(Zeroizing::new(fs::read(&snap)?)));
        let _ = fs::remove_file(&snap);
        r?
    };
    let salt = crypto::random_bytes::<16>().to_vec();
    let header = BackupHeader { v: 1, created_utc: now_ms(), app_version: app_version.into(), meta, salt };
    let hjson = serde_json::to_vec(&header)?;
    let sealed = crypto::seal(&body_key(mk, &header.salt), &plain, &aad(&hjson));

    let tmp = dest.with_extension(format!("{EXTENSION}.tmp"));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(MAGIC)?;
        f.write_all(&VERSION.to_le_bytes())?;
        f.write_all(&(hjson.len() as u32).to_le_bytes())?;
        f.write_all(&hjson)?;
        f.write_all(&sealed.nonce)?;
        f.write_all(&sealed.ct)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dest)?;
    Ok(())
}

pub struct Opened {
    pub mk: Key32,
    /// The plain SQLite file.
    pub sqlite: Zeroizing<Vec<u8>>,
    pub created_utc: i64,
    meta: MasterKeyMetadata,
}

/// How a backup is opened: the master password it was made with, or the recovery key.
pub enum Secret<'a> {
    Password(&'a str),
    Recovery(&'a str),
}

struct Parsed {
    header: BackupHeader,
    hjson: Vec<u8>,
    sealed: Sealed,
}

fn parse(raw: &[u8]) -> Result<Parsed> {
    if raw.len() < 14 || &raw[..8] != MAGIC {
        return Err(Error::Format("This isn't a DirShield backup.".into()));
    }
    if u16::from_le_bytes([raw[8], raw[9]]) != VERSION {
        return Err(Error::Format("This backup was made by a newer DirShield. Update DirShield first.".into()));
    }
    let hlen = u32::from_le_bytes(raw[10..14].try_into().unwrap()) as usize;
    if hlen > 1024 * 1024 || raw.len() < 14 + hlen + 12 + 16 {
        return Err(Error::Integrity("The backup file is damaged or incomplete.".into()));
    }
    let hjson = raw[14..14 + hlen].to_vec();
    let header: BackupHeader = serde_json::from_slice(&hjson)?;
    let body = &raw[14 + hlen..];
    Ok(Parsed { header, hjson, sealed: Sealed { nonce: body[..12].to_vec(), ct: body[12..].to_vec() } })
}

/// Unwraps the master key with `secret` (an [`Error::AuthFailed`] means a
/// wrong password or key, for the caller's rate limiter).
pub fn open(path: &Path, secret: Secret) -> Result<Opened> {
    let p = parse(&fs::read(path)?)?;
    let mk = match secret {
        Secret::Password(pw) => auth::unwrap_master(&p.header.meta, pw)?,
        Secret::Recovery(rk) => auth::unwrap_master_with_recovery(&p.header.meta, rk)?,
    };
    let sqlite = crypto::open(&body_key(&mk, &p.header.salt), &p.sealed, &aad(&p.hjson)).map_err(|_| Error::Integrity("The backup file has been modified or is damaged.".into()))?;
    Ok(Opened { mk, sqlite, created_utc: p.header.created_utc, meta: p.header.meta })
}

/// Replaces the live database with an opened backup.
pub fn restore(db: &Db, opened: &Opened, scratch: &Path) -> Result<()> {
    let tmp = scratch.join(format!("restore-{}.tmp", crypto::random_id()));
    let r = (|| {
        fs::write(&tmp, &*opened.sqlite)?;
        // The database inside must hold the same master key the header names.
        let inner: Option<String> = {
            let c = rusqlite::Connection::open_with_flags(&tmp, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            c.query_row("SELECT master_key_metadata FROM users WHERE id=1", [], |r| r.get(0)).ok()
        };
        let inner: MasterKeyMetadata = serde_json::from_str(&inner.ok_or_else(|| Error::Integrity("The backup holds no master key.".into()))?)?;
        if serde_json::to_string(&inner)? != serde_json::to_string(&opened.meta)? {
            return Err(Error::Integrity("The backup's contents don't match its header.".into()));
        }
        db.replace_from(&tmp)
    })();
    let _ = fs::remove_file(&tmp);
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::crypto::KdfParams;

    #[test]
    fn backup_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("a.db")).unwrap();
        let (mk, rec) = auth::setup(&db, "amber quartz tundra bicycle", KdfParams::new_test()).unwrap();
        db.set_setting("marker", "before").unwrap();
        let file = d.path().join("b.dsbackup");
        create(&db, &mk, "test", &file, d.path()).unwrap();
        db.set_setting("marker", "after").unwrap();

        assert!(matches!(open(&file, Secret::Password("wrong password here")), Err(Error::AuthFailed)));
        let o = open(&file, Secret::Recovery(&rec)).unwrap();
        assert_eq!(*o.mk, *mk);
        let o = open(&file, Secret::Password("amber quartz tundra bicycle")).unwrap();
        restore(&db, &o, d.path()).unwrap();
        assert_eq!(db.get_setting("marker").unwrap().as_deref(), Some("before"));

        // a fresh install can restore it too
        let db2 = Db::open(&d.path().join("c.db")).unwrap();
        restore(&db2, &o, d.path()).unwrap();
        assert_eq!(*auth::unwrap_master(&auth::load_metadata(&db2).unwrap().unwrap(), "amber quartz tundra bicycle").unwrap(), *mk);
    }

    #[test]
    fn tampered_backup_rejected() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("a.db")).unwrap();
        let (mk, _) = auth::setup(&db, "amber quartz tundra bicycle", KdfParams::new_test()).unwrap();
        let file = d.path().join("b.dsbackup");
        create(&db, &mk, "test", &file, d.path()).unwrap();
        let mut raw = fs::read(&file).unwrap();
        let n = raw.len();
        raw[n - 20] ^= 1;
        fs::write(&file, &raw).unwrap();
        assert!(matches!(open(&file, Secret::Password("amber quartz tundra bicycle")), Err(Error::Integrity(_))));
    }
}
