//! Checking credentials against the master key metadata, a Secure Lock vault
//! header, or a Quick Lock folder password. Every check is rate limited.

use std::path::Path;

use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::auth::{self, RateLimiter};
use crate::crypto::{self, KdfParams, Key32};
use crate::db::{now_ms, Db};
use crate::error::{invalid, Error, Result};
use crate::model::{CredentialKind, KeyMode, ProtectionMode};
use crate::vault::header::VaultHeader;
use crate::vaults::{aad, VaultRow};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    pub kind: CredentialKind,
    pub secret: String,
}

impl Credential {
    pub fn folder(secret: &str) -> Self {
        Self { kind: CredentialKind::Folder, secret: secret.to_string() }
    }
}

/// Checks the master password and returns the master key.
pub fn verify_master(db: &Db, password: &str) -> Result<Key32> {
    let meta = auth::load_metadata(db)?.ok_or(Error::NotInitialized)?;
    RateLimiter::guarded(db, || auth::unwrap_master(&meta, password))
}

/// Unwraps a Secure Lock vault key with the given credential and verifies the header MAC.
pub fn secure_vault_key(db: &Db, row: &VaultRow, cred: &Credential) -> Result<Key32> {
    if row.mode != ProtectionMode::Secure {
        return invalid("not a Secure Lock vault");
    }
    let secret = Zeroizing::new(cred.secret.clone());
    let header = VaultHeader::read(Path::new(&row.vault_path))?;
    let meta = auth::load_metadata(db)?.ok_or(Error::NotInitialized)?;
    let vk = RateLimiter::guarded(db, || match cred.kind {
        CredentialKind::Master => header.unwrap_with_master(&auth::unwrap_master(&meta, &secret)?),
        CredentialKind::Folder => header.unwrap_with_password(&secret),
        CredentialKind::Recovery => header.unwrap_with_recovery(&crypto::decode_recovery_key(&secret)?),
    })?;
    header.verify_mac(&vk)?;
    Ok(vk)
}

const QUICK_VERIFIER: &[u8] = b"dirshield-quick-lock-verifier";

/// Authenticates access to a Quick-Locked folder.
///
/// The master password is accepted only for folders in master mode; a folder
/// with its own password needs that password or the recovery key.
pub fn quick_verify(db: &Db, row: &VaultRow, cred: &Credential) -> Result<()> {
    let secret = Zeroizing::new(cred.secret.clone());
    let meta = auth::load_metadata(db)?.ok_or(Error::NotInitialized)?;
    RateLimiter::guarded(db, || match (cred.kind, row.key_mode) {
        (CredentialKind::Master, KeyMode::Master) => auth::unwrap_master(&meta, &secret).map(|_| ()),
        (CredentialKind::Master, KeyMode::Password) => Err(Error::AuthFailed),
        (CredentialKind::Folder, _) => {
            let w: String = db
                .lock()
                .query_row("SELECT wrapped_vault_key FROM vault_key_wrappers WHERE vault_id=?1 AND wrapper_type='quick_password'", [&row.id], |r| r.get(0))
                .optional()?
                .ok_or(Error::AuthFailed)?;
            let (kdf, sealed): (KdfParams, crypto::Sealed) = serde_json::from_str(&w)?;
            let k = crypto::derive_password_key(&secret, &kdf)?;
            crypto::open(&k, &sealed, &aad(&row.id, "quick")).map(|_| ())
        }
        (CredentialKind::Recovery, _) => auth::unwrap_master_with_recovery(&meta, &secret).map(|_| ()),
    })
}

/// Stores (replacing any previous one) the verifier for a Quick Lock folder password.
pub fn store_quick_verifier(db: &Db, id: &str, password: &str) -> Result<()> {
    store_quick_verifier_with(db, id, password, KdfParams::new_default())
}

pub fn store_quick_verifier_with(db: &Db, id: &str, password: &str, kdf: KdfParams) -> Result<()> {
    let k = crypto::derive_password_key(password, &kdf)?;
    let sealed = crypto::seal(&k, QUICK_VERIFIER, &aad(id, "quick"));
    let c = db.lock();
    c.execute("DELETE FROM vault_key_wrappers WHERE vault_id=?1 AND wrapper_type='quick_password'", [id])?;
    c.execute(
        "INSERT INTO vault_key_wrappers(vault_id, wrapper_type, kdf_salt, kdf_parameters, wrapped_vault_key, created_at) VALUES(?1,'quick_password',?2,?3,?4,?5)",
        params![id, hex::encode(&kdf.salt), serde_json::to_string(&kdf)?, serde_json::to_string(&(kdf.clone(), sealed))?, now_ms()],
    )?;
    Ok(())
}

pub fn clear_quick_verifier(db: &Db, id: &str) -> Result<()> {
    db.lock().execute("DELETE FROM vault_key_wrappers WHERE vault_id=?1 AND wrapper_type='quick_password'", [id])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::VaultStatus;

    const MASTER: &str = "amber quartz tundra bicycle";

    fn setup() -> (tempfile::TempDir, Db, String) {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("t.db")).unwrap();
        let (_mk, rec) = auth::setup(&db, MASTER, KdfParams::new_test()).unwrap();
        (d, db, rec.to_string())
    }

    fn quick_row(db: &Db, id: &str, key_mode: KeyMode) -> VaultRow {
        db.lock()
            .execute(
                "INSERT INTO vaults(id, name, original_path, vault_path, protection_mode, key_mode, status, size_bytes, file_count, created_at, updated_at)
                 VALUES(?1,'n','p','/x',?2,?3,?4,0,0,0,0)",
                params![id, ProtectionMode::Quick, key_mode, VaultStatus::QuickLocked],
            )
            .unwrap();
        crate::vaults::load(db, id).unwrap()
    }

    fn cred(kind: CredentialKind, s: &str) -> Credential {
        Credential { kind, secret: s.into() }
    }

    #[test]
    fn quick_master_mode() {
        let (_d, db, rec) = setup();
        let r = quick_row(&db, "a", KeyMode::Master);
        quick_verify(&db, &r, &cred(CredentialKind::Master, MASTER)).unwrap();
        quick_verify(&db, &r, &cred(CredentialKind::Recovery, &rec)).unwrap();
        assert!(matches!(quick_verify(&db, &r, &cred(CredentialKind::Master, "nope nope nope")), Err(Error::AuthFailed)));
        // no folder password was ever set
        assert!(matches!(quick_verify(&db, &r, &Credential::folder("anything")), Err(Error::AuthFailed)));
    }

    #[test]
    fn quick_password_mode_refuses_master() {
        let (_d, db, rec) = setup();
        let r = quick_row(&db, "b", KeyMode::Password);
        store_quick_verifier_with(&db, "b", "folder secret 1", KdfParams::new_test()).unwrap();
        quick_verify(&db, &r, &Credential::folder("folder secret 1")).unwrap();
        quick_verify(&db, &r, &cred(CredentialKind::Recovery, &rec)).unwrap();
        assert!(matches!(quick_verify(&db, &r, &cred(CredentialKind::Master, MASTER)), Err(Error::AuthFailed)));
        assert!(matches!(quick_verify(&db, &r, &Credential::folder("wrong")), Err(Error::AuthFailed)));
        // the verifier is bound to its vault id
        let other = quick_row(&db, "c", KeyMode::Password);
        db.lock().execute("UPDATE vault_key_wrappers SET vault_id='c' WHERE vault_id='b'", []).unwrap();
        assert!(matches!(quick_verify(&db, &other, &Credential::folder("folder secret 1")), Err(Error::AuthFailed)));
        clear_quick_verifier(&db, "c").unwrap();
    }

    #[test]
    fn secure_key_rejects_quick_rows() {
        let (_d, db, _) = setup();
        let r = quick_row(&db, "q", KeyMode::Master);
        assert!(matches!(secure_vault_key(&db, &r, &cred(CredentialKind::Master, MASTER)), Err(Error::Invalid(_))));
    }

    #[test]
    fn verify_master_counts_failures() {
        let (_d, db, _) = setup();
        verify_master(&db, MASTER).unwrap();
        for _ in 0..5 {
            assert!(matches!(verify_master(&db, "wrong wrong wrong"), Err(Error::AuthFailed)));
        }
        assert!(matches!(verify_master(&db, MASTER), Err(Error::RateLimited(_))));
    }
}
