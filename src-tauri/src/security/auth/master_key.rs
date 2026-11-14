//! The master key and how it is wrapped: by the master password (Argon2id)
//! and by the recovery key (HKDF), plus the recovery key's X25519 escrow key.

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::password::validate_master_password;
use crate::domain::error::{Error, Result};
use crate::security::crypto::{self, b64, KdfParams, Key32, Sealed};
use crate::storage::db::{now_ms, Db};

const AAD_MK_PW: &[u8] = b"dirshield/v1/master-key/password";
const AAD_MK_REC: &[u8] = b"dirshield/v1/master-key/recovery";

#[derive(Serialize, Deserialize, Clone)]
pub struct MasterKeyMetadata {
    pub v: u32,
    pub kdf: KdfParams,
    pub mk_by_password: Sealed,
    pub mk_by_recovery: Sealed,
    #[serde(with = "b64")]
    pub recovery_salt: Vec<u8>,
    #[serde(with = "b64")]
    pub recovery_pub: Vec<u8>,
    pub recovery_id: String,
}

impl MasterKeyMetadata {
    pub fn recovery_pub(&self) -> Result<[u8; 32]> {
        self.recovery_pub.as_slice().try_into().map_err(|_| Error::Format("bad recovery public key".into()))
    }
}

pub fn load_metadata(db: &Db) -> Result<Option<MasterKeyMetadata>> {
    let raw: Option<String> = db.lock().query_row("SELECT master_key_metadata FROM users WHERE id=1", [], |r| r.get(0)).optional()?;
    match raw {
        Some(s) => Ok(Some(serde_json::from_str(&s)?)),
        None => Ok(None),
    }
}

fn store_metadata(db: &Db, m: &MasterKeyMetadata, insert: bool) -> Result<()> {
    let json = serde_json::to_string(m)?;
    let now = now_ms();
    if insert {
        db.lock().execute("INSERT INTO users(id, master_key_metadata, created_at, updated_at) VALUES(1, ?1, ?2, ?2)", params![json, now])?;
    } else {
        db.lock().execute("UPDATE users SET master_key_metadata=?1, updated_at=?2 WHERE id=1", params![json, now])?;
    }
    Ok(())
}

fn recovery_kek(recovery: &[u8; 32], salt: &[u8]) -> Key32 {
    crypto::hkdf32(recovery, salt, b"dirshield/v1/recovery-kek")
}

/// First-time setup. Returns (master key, formatted recovery key).
pub fn setup(db: &Db, password: &str, kdf: KdfParams) -> Result<(Key32, Zeroizing<String>)> {
    if load_metadata(db)?.is_some() {
        return Err(Error::AlreadyInitialized);
    }
    validate_master_password(password)?;
    let mk = crypto::random_key();
    let recovery = crypto::random_key();
    let recovery_salt = crypto::random_bytes::<16>().to_vec();
    let kek = crypto::derive_password_key(password, &kdf)?;
    let meta = MasterKeyMetadata {
        v: 1,
        mk_by_password: crypto::seal(&kek, mk.as_ref(), AAD_MK_PW),
        mk_by_recovery: crypto::seal(&recovery_kek(&recovery, &recovery_salt), mk.as_ref(), AAD_MK_REC),
        recovery_pub: crypto::recovery_public(&recovery, &recovery_salt).to_vec(),
        recovery_id: crypto::random_id(),
        recovery_salt,
        kdf,
    };
    store_metadata(db, &meta, true)?;
    db.log("setup", None, "success", None);
    Ok((mk, Zeroizing::new(crypto::encode_recovery_key(&recovery))))
}

pub fn unwrap_master(meta: &MasterKeyMetadata, password: &str) -> Result<Key32> {
    unwrap_master_parts(&meta.kdf, &meta.mk_by_password, password)
}

/// Master key from a password-wrapped copy (the database's, or the portable
/// copy kept in a vault header).
pub fn unwrap_master_parts(kdf: &KdfParams, sealed: &Sealed, password: &str) -> Result<Key32> {
    let kek = crypto::derive_password_key(password, kdf)?;
    crypto::open_key(&kek, sealed, AAD_MK_PW)
}

pub fn unwrap_master_with_recovery(meta: &MasterKeyMetadata, recovery_text: &str) -> Result<Key32> {
    let rk = crypto::decode_recovery_key(recovery_text)?;
    crypto::open_key(&recovery_kek(&rk, &meta.recovery_salt), &meta.mk_by_recovery, AAD_MK_REC)
}

pub fn recovery_secret(meta: &MasterKeyMetadata, recovery_text: &str) -> Result<x25519_dalek::StaticSecret> {
    let rk = crypto::decode_recovery_key(recovery_text)?;
    Ok(crypto::recovery_x25519_secret(&rk, &meta.recovery_salt))
}

/// Re-wraps the master key under a new password. Vaults are untouched.
pub fn rewrap_master(db: &Db, mk: &[u8; 32], new_password: &str, kdf: KdfParams) -> Result<()> {
    validate_master_password(new_password)?;
    let mut meta = load_metadata(db)?.ok_or(Error::NotInitialized)?;
    let kek = crypto::derive_password_key(new_password, &kdf)?;
    meta.mk_by_password = crypto::seal(&kek, mk, AAD_MK_PW);
    meta.kdf = kdf;
    store_metadata(db, &meta, false)
}

/// Replaces the recovery key: the master key is wrapped for a new random
/// recovery key, and a new escrow public key is published. Vault headers keep
/// their old escrow until they are re-escrowed (see `commands::sync_headers`).
/// Returns the updated metadata.
pub fn rotate_recovery(db: &Db, mk: &[u8; 32], recovery: &[u8; 32]) -> Result<MasterKeyMetadata> {
    let mut meta = load_metadata(db)?.ok_or(Error::NotInitialized)?;
    let salt = crypto::random_bytes::<16>().to_vec();
    meta.mk_by_recovery = crypto::seal(&recovery_kek(recovery, &salt), mk, AAD_MK_REC);
    meta.recovery_pub = crypto::recovery_public(recovery, &salt).to_vec();
    meta.recovery_id = crypto::random_id();
    meta.recovery_salt = salt;
    store_metadata(db, &meta, false)?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::super::password::{password_strength, MIN_MASTER_SCORE};
    use super::*;

    fn db() -> (tempfile::TempDir, Db) {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("t.db")).unwrap();
        (d, db)
    }

    #[test]
    fn setup_login_change_recover() {
        let (_d, db) = db();
        let (mk, rec) = setup(&db, "amber quartz tundra bicycle", KdfParams::new_test()).unwrap();
        assert!(matches!(setup(&db, "lunar copper meadow fiddle", KdfParams::new_test()), Err(Error::AlreadyInitialized)));
        let meta = load_metadata(&db).unwrap().unwrap();
        assert_eq!(*unwrap_master(&meta, "amber quartz tundra bicycle").unwrap(), *mk);
        assert!(matches!(unwrap_master(&meta, "wrong-password"), Err(Error::AuthFailed)));
        // change password: same MK, old password no longer works
        rewrap_master(&db, &mk, "velvet harbor crimson oyster", KdfParams::new_test()).unwrap();
        let meta = load_metadata(&db).unwrap().unwrap();
        assert!(unwrap_master(&meta, "amber quartz tundra bicycle").is_err());
        assert_eq!(*unwrap_master(&meta, "velvet harbor crimson oyster").unwrap(), *mk);
        // recovery key still yields the same MK
        assert_eq!(*unwrap_master_with_recovery(&meta, &rec).unwrap(), *mk);
        // a new recovery key replaces the old one
        let new_rk = crypto::random_bytes::<32>();
        let rotated = rotate_recovery(&db, &mk, &new_rk).unwrap();
        assert_ne!(rotated.recovery_id, meta.recovery_id);
        let new_text = crypto::encode_recovery_key(&new_rk);
        assert_eq!(*unwrap_master_with_recovery(&rotated, &new_text).unwrap(), *mk);
        assert!(unwrap_master_with_recovery(&rotated, &rec).is_err());
        assert_eq!(*unwrap_master(&rotated, "velvet harbor crimson oyster").unwrap(), *mk);
        // a different (valid-looking) recovery key fails
        let other = crypto::encode_recovery_key(&crypto::random_bytes::<32>());
        assert!(unwrap_master_with_recovery(&meta, &other).is_err());
        // nothing secret in the DB in plaintext
        let raw: String = db.lock().query_row("SELECT master_key_metadata FROM users", [], |r| r.get(0)).unwrap();
        assert!(!raw.contains("velvet harbor crimson oyster"));
        assert!(!raw.contains(&hex::encode(*mk)));
    }

    #[test]
    fn short_passwords_rejected() {
        let (_d, db) = db();
        assert!(setup(&db, "short", KdfParams::new_test()).is_err());
    }

    #[test]
    fn weak_master_passwords_rejected() {
        let (_d, db) = db();
        for weak in ["password123", "qwertyuiop", "dirshield2026", "aaaaaaaaaaaa", "P@ssw0rd!"] {
            assert!(matches!(setup(&db, weak, KdfParams::new_test()), Err(Error::Invalid(_))), "{weak} accepted");
        }
        assert!(password_strength("amber quartz tundra bicycle").score >= MIN_MASTER_SCORE);
        assert_eq!(password_strength("").score, 0);
    }
}
