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

use crate::crypto::{self, hkdf32, EscrowBox, Key32, KdfParams, Sealed};
use crate::error::{Error, Result};

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
}

impl KeyWrapper {
    pub fn kind(&self) -> &'static str {
        match self {
            KeyWrapper::Master { .. } => "master",
            KeyWrapper::Password { .. } => "password",
            KeyWrapper::RecoveryEscrow { .. } => "recovery",
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
                return crypto::escrow_open_key(&secret, escrow, &wrapper_aad(&self.vault_id, "recovery"));
            }
        }
        Err(Error::AuthFailed)
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
    Ok(KeyWrapper::RecoveryEscrow {
        recovery_id: recovery_id.to_string(),
        salt: recovery_salt.to_vec(),
        escrow: crypto::escrow_seal(recovery_pub, vk, &wrapper_aad(vault_id, "recovery"))?,
    })
}
