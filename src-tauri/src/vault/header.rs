//! `vault.dsv` – the vault header.
//!
//! ```text
//! 0   8  magic "DIRSHLD\0"
//! 8   2  format version (u16 LE) = 1
//! 10  4  body length (u32 LE)
//! 14  .. UTF-8 JSON body (VaultHeader)
//! ```
//!
//! The body holds no plaintext names or paths. It carries the algorithm
//! identifiers, chunk size, the vault id, every key wrapper (with its KDF
//! parameters and salt), the sealed flag, and an HMAC-SHA256 over the
//! canonical body computed with a key derived from the vault key. A tampered
//! header therefore fails verification right after the vault key is unwrapped.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::domain::error::{Error, Result};
use crate::security::crypto::{self, hkdf32, EscrowBox, KdfParams, Key32, Sealed};

pub const HEADER_MAGIC: &[u8; 8] = b"DIRSHLD\0";
pub const FORMAT_VERSION: u16 = 1;
pub const ALGORITHM: &str = "AES-256-GCM/STREAM-HKDF-SHA256";
pub const HEADER_FILE: &str = "vault.dsv";
pub const MANIFEST_FILE: &str = "manifest.dsb";
pub const OBJECTS_DIR: &str = "objects";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyWrapper {
    /// Vault key wrapped by the user's master key (master password mode).
    Master { sealed: Sealed },
    /// Vault key wrapped by an Argon2id key derived from a folder password.
    Password { kdf: KdfParams, sealed: Sealed },
    /// Vault key sealed to the recovery key's X25519 public key.
    /// The salt is stored here (it is not secret) so the vault can be recovered
    /// with only the recovery key, even if the DirShield database is lost.
    RecoveryEscrow {
        recovery_id: String,
        #[serde(with = "crypto::b64")]
        salt: Vec<u8>,
        #[serde(rename = "box")]
        escrow: EscrowBox,
    },
    /// Copy of the master key as wrapped by the master password (the same
    /// blob DirShield keeps in its database). Present only when "Open vaults
    /// on another PC with the master password" is on, so a vault can be
    /// imported with the master password alone. Refreshed whenever the
    /// master password changes.
    MasterPassword { kdf: KdfParams, sealed: Sealed },
}

impl KeyWrapper {
    pub fn kind(&self) -> &'static str {
        match self {
            KeyWrapper::Master { .. } => "master",
            KeyWrapper::Password { .. } => "password",
            KeyWrapper::RecoveryEscrow { .. } => "recovery",
            KeyWrapper::MasterPassword { .. } => "master_password",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultHeader {
    pub format_version: u16,
    pub algorithm: String,
    pub vault_id: String,
    pub chunk_size: u32,
    pub created_utc: i64,
    pub wrappers: Vec<KeyWrapper>,
    /// True only once every file is encrypted, verified, and the manifest is in place.
    pub sealed: bool,
    #[serde(default)]
    pub mac: String,
}

pub fn wrapper_aad(vault_id: &str, kind: &str) -> Vec<u8> {
    format!("dirshield/v1/vault-key/{kind}/{vault_id}").into_bytes()
}

impl VaultHeader {
    pub fn vault_id_bytes(&self) -> Result<[u8; 16]> {
        let v = hex::decode(&self.vault_id).map_err(|_| Error::Format("bad vault id".into()))?;
        v.try_into().map_err(|_| Error::Format("bad vault id".into()))
    }

    fn mac_key(vk: &[u8; 32]) -> Key32 {
        hkdf32(vk, b"", b"dirshield/v1/header-mac")
    }

    fn canonical(&self) -> Result<Vec<u8>> {
        let mut c = self.clone();
        c.mac = String::new();
        Ok(serde_json::to_vec(&c)?)
    }

    pub fn compute_mac(&mut self, vk: &[u8; 32]) -> Result<()> {
        let tag = crypto::hmac_sha256(&*Self::mac_key(vk), &self.canonical()?);
        self.mac = hex::encode(tag);
        Ok(())
    }

    pub fn verify_mac(&self, vk: &[u8; 32]) -> Result<()> {
        let tag = hex::decode(&self.mac).map_err(|_| Error::Integrity("vault header MAC missing".into()))?;
        if !crypto::hmac_verify(&*Self::mac_key(vk), &self.canonical()?, &tag) {
            return Err(Error::Integrity("vault header has been modified".into()));
        }
        Ok(())
    }

    pub fn read(vault_dir: &Path) -> Result<Self> {
        let raw = fs::read(vault_dir.join(HEADER_FILE)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound("vault header (vault.dsv)".into()),
            _ => Error::Io(e),
        })?;
        if raw.len() < 14 || &raw[0..8] != HEADER_MAGIC {
            return Err(Error::Format("not a DirShield vault".into()));
        }
        let ver = u16::from_le_bytes([raw[8], raw[9]]);
        if ver != FORMAT_VERSION {
            return Err(Error::Format(format!("vault format version {ver} is not supported")));
        }
        let len = u32::from_le_bytes(raw[10..14].try_into().unwrap()) as usize;
        if raw.len() != 14 + len || len > 1024 * 1024 {
            return Err(Error::Integrity("vault header length mismatch".into()));
        }
        let h: VaultHeader = serde_json::from_slice(&raw[14..])?;
        if h.format_version != FORMAT_VERSION || h.algorithm != ALGORITHM {
            return Err(Error::Format("unsupported vault algorithm".into()));
        }
        h.vault_id_bytes()?;
        Ok(h)
    }

    /// Atomic replace: write temp file, flush to disk, rename over the old header.
    pub fn write_atomic(&self, vault_dir: &Path) -> Result<()> {
        let body = serde_json::to_vec(self)?;
        let mut raw = Vec::with_capacity(14 + body.len());
        raw.extend_from_slice(HEADER_MAGIC);
        raw.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        raw.extend_from_slice(&(body.len() as u32).to_le_bytes());
        raw.extend_from_slice(&body);
        let tmp = vault_dir.join(format!("{HEADER_FILE}.tmp"));
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&raw)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, vault_dir.join(HEADER_FILE))?;
        Ok(())
    }

    pub fn unwrap_with_master(&self, master: &[u8; 32]) -> Result<Key32> {
        for w in &self.wrappers {
            if let KeyWrapper::Master { sealed } = w {
                return crypto::open_key(master, sealed, &wrapper_aad(&self.vault_id, "master"));
            }
        }
        Err(Error::AuthFailed)
    }

    pub fn unwrap_with_password(&self, password: &str) -> Result<Key32> {
        for w in &self.wrappers {
            if let KeyWrapper::Password { kdf, sealed } = w {
                let kek = crypto::derive_password_key(password, kdf)?;
                return crypto::open_key(&kek, sealed, &wrapper_aad(&self.vault_id, "password"));
            }
        }
        Err(Error::AuthFailed)
    }

    pub fn unwrap_with_recovery(&self, recovery_key: &[u8; 32]) -> Result<Key32> {
        for w in &self.wrappers {
            if let KeyWrapper::RecoveryEscrow { escrow, salt, .. } = w {
                let secret = crypto::recovery_x25519_secret(recovery_key, salt);
                if let Ok(k) = crypto::escrow_open_key(&secret, escrow, &wrapper_aad(&self.vault_id, "recovery")) {
                    return Ok(k);
                }
            }
        }
        Err(Error::AuthFailed)
    }

    /// Master key from the portable copy in this header (see
    /// [`KeyWrapper::MasterPassword`]), then the vault key from it.
    pub fn unwrap_with_master_password(&self, password: &str) -> Result<Key32> {
        for w in &self.wrappers {
            if let KeyWrapper::MasterPassword { kdf, sealed } = w {
                let mk = crate::security::auth::unwrap_master_parts(kdf, sealed, password)?;
                return self.unwrap_with_master(&mk);
            }
        }
        Err(Error::AuthFailed)
    }

    /// The recovery key id this vault's escrow was made for, if any.
    pub fn recovery_id(&self) -> Option<&str> {
        self.wrappers.iter().find_map(|w| match w {
            KeyWrapper::RecoveryEscrow { recovery_id, .. } => Some(recovery_id.as_str()),
            _ => None,
        })
    }

    pub fn key_mode(&self) -> &'static str {
        if self.wrappers.iter().any(|w| matches!(w, KeyWrapper::Password { .. })) {
            "password"
        } else {
            "master"
        }
    }
}

pub fn master_wrapper(vault_id: &str, master: &[u8; 32], vk: &[u8; 32]) -> KeyWrapper {
    KeyWrapper::Master { sealed: crypto::seal(master, vk, &wrapper_aad(vault_id, "master")) }
}

pub fn password_wrapper(vault_id: &str, password: &str, vk: &[u8; 32]) -> Result<KeyWrapper> {
    let kdf = KdfParams::new_default();
    password_wrapper_with(vault_id, password, vk, kdf)
}

pub fn password_wrapper_with(vault_id: &str, password: &str, vk: &[u8; 32], kdf: KdfParams) -> Result<KeyWrapper> {
    let kek = crypto::derive_password_key(password, &kdf)?;
    Ok(KeyWrapper::Password { sealed: crypto::seal(&kek, vk, &wrapper_aad(vault_id, "password")), kdf })
}

pub fn recovery_wrapper(vault_id: &str, recovery_pub: &[u8; 32], recovery_id: &str, recovery_salt: &[u8], vk: &[u8; 32]) -> Result<KeyWrapper> {
    Ok(KeyWrapper::RecoveryEscrow { recovery_id: recovery_id.to_string(), salt: recovery_salt.to_vec(), escrow: crypto::escrow_seal(recovery_pub, vk, &wrapper_aad(vault_id, "recovery"))? })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::auth;
    use crate::storage::db::Db;

    fn header(wrappers: Vec<KeyWrapper>, vk: &[u8; 32], id: &str) -> VaultHeader {
        let mut h = VaultHeader { format_version: FORMAT_VERSION, algorithm: ALGORITHM.into(), vault_id: id.into(), chunk_size: 4096, created_utc: 0, wrappers, sealed: true, mac: String::new() };
        h.compute_mac(vk).unwrap();
        h
    }

    #[test]
    fn portable_master_password_copy() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("t.db")).unwrap();
        let (mk, _) = auth::setup(&db, "amber quartz tundra bicycle", KdfParams::new_test()).unwrap();
        let meta = auth::load_metadata(&db).unwrap().unwrap();
        let id = crypto::random_id();
        let vk = crypto::random_key();
        let h = header(vec![master_wrapper(&id, &mk, &vk), KeyWrapper::MasterPassword { kdf: meta.kdf.clone(), sealed: meta.mk_by_password.clone() }], &vk, &id);
        // survives a round trip through the file format
        h.write_atomic(d.path()).unwrap();
        let h = VaultHeader::read(d.path()).unwrap();
        h.verify_mac(&vk).unwrap();
        assert_eq!(*h.unwrap_with_master_password("amber quartz tundra bicycle").unwrap(), *vk);
        assert!(matches!(h.unwrap_with_master_password("wrong password!"), Err(Error::AuthFailed)));
        // without the copy, the password alone is not enough
        let plain = header(vec![master_wrapper(&id, &mk, &vk)], &vk, &id);
        assert!(plain.unwrap_with_master_password("amber quartz tundra bicycle").is_err());
    }

    #[test]
    fn any_recovery_escrow_opens() {
        let id = crypto::random_id();
        let vk = crypto::random_key();
        let (a, b) = (crypto::random_bytes::<32>(), crypto::random_bytes::<32>());
        let salt = crypto::random_bytes::<16>();
        let w = |k: &[u8; 32]| recovery_wrapper(&id, &crypto::recovery_public(k, &salt), "r", &salt, &vk).unwrap();
        let h = header(vec![w(&a), w(&b)], &vk, &id);
        assert_eq!(*h.unwrap_with_recovery(&a).unwrap(), *vk);
        assert_eq!(*h.unwrap_with_recovery(&b).unwrap(), *vk);
        assert!(h.unwrap_with_recovery(&crypto::random_bytes::<32>()).is_err());
        assert_eq!(h.recovery_id(), Some("r"));
    }
}
