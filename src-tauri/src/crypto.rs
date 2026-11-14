//! Cryptographic building blocks. Everything here composes audited RustCrypto /
//! dalek primitives; no primitive is implemented by hand.
//!
//! * AES-256-GCM       – key wrapping and (see `vault::stream`) chunked content encryption
//! * Argon2id          – password -> key-encryption-key derivation
//! * HKDF-SHA256       – sub-key derivation from high-entropy keys
//! * HMAC-SHA256       – vault header integrity
//! * X25519 + HKDF     – recovery escrow ("sealed box") so a vault key can be
//!   wrapped for the recovery key without the recovery key being present
//! * OsRng             – all randomness (BCryptGenRandom on Windows)

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub type Key32 = Zeroizing<[u8; 32]>;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn random_key() -> Key32 {
    Zeroizing::new(random_bytes::<32>())
}

pub fn random_id() -> String {
    hex::encode(random_bytes::<16>())
}

/// Base64 (de)serialization helper for byte vectors.
pub mod b64 {
    use super::*;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KdfParams {
    pub alg: String,
    /// Memory cost in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// 64 MiB, 3 passes, 4 lanes: ~0.3-0.8 s on a modern desktop CPU.
    pub fn new_default() -> Self {
        Self { alg: "argon2id".into(), m_cost: 64 * 1024, t_cost: 3, p_cost: 4, salt: random_bytes::<16>().to_vec() }
    }

    /// Cheap parameters, only for unit tests.
    #[cfg(test)]
    pub fn new_test() -> Self {
        Self { alg: "argon2id".into(), m_cost: 1024, t_cost: 1, p_cost: 1, salt: random_bytes::<16>().to_vec() }
    }

    fn validate(&self) -> Result<()> {
        // Parameters come from files on disk; reject anything absurd so a
        // tampered header cannot make us allocate gigabytes or spin forever.
        if self.alg != "argon2id" {
            return Err(Error::Format(format!("unsupported KDF {}", self.alg)));
        }
        if self.salt.len() < 16 || self.m_cost < 8 || self.m_cost > 2 * 1024 * 1024 || self.t_cost == 0 || self.t_cost > 32 || self.p_cost == 0 || self.p_cost > 16 {
            return Err(Error::Format("KDF parameters out of range".into()));
        }
        Ok(())
    }
}

pub fn derive_password_key(password: &str, p: &KdfParams) -> Result<Key32> {
    p.validate()?;
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(32)).map_err(|e| Error::Format(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password.as_bytes(), &p.salt, out.as_mut()).map_err(|e| Error::Format(e.to_string()))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// HKDF / HMAC
// ---------------------------------------------------------------------------

pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, out.as_mut()).expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

pub fn hmac_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.verify_slice(tag).is_ok() // constant time
}

// ---------------------------------------------------------------------------
// AES-256-GCM key wrapping (small payloads, random 96-bit nonces)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Sealed {
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ct: Vec<u8>,
}

pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Sealed {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = random_bytes::<12>();
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad }).expect("AES-GCM encryption of a small buffer cannot fail");
    Sealed { nonce: nonce.to_vec(), ct }
}

pub fn open(key: &[u8; 32], s: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if s.nonce.len() != 12 {
        return Err(Error::Format("bad nonce length".into()));
    }
    let cipher = Aes256Gcm::new(key.into());
    cipher.decrypt(Nonce::from_slice(&s.nonce), Payload { msg: &s.ct, aad }).map(Zeroizing::new).map_err(|_| Error::AuthFailed)
}

pub fn open_key(key: &[u8; 32], s: &Sealed, aad: &[u8]) -> Result<Key32> {
    let pt = open(key, s, aad)?;
    if pt.len() != 32 {
        return Err(Error::Format("wrapped key has wrong length".into()));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&pt);
    Ok(k)
}

// ---------------------------------------------------------------------------
// Recovery key: 256 random bits, shown to the user as Crockford base32.
// ---------------------------------------------------------------------------

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn encode_recovery_key(bytes: &[u8; 32]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &b in bytes.iter() {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    // 52 symbols -> 13 groups of 4
    out.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

pub fn decode_recovery_key(text: &str) -> Result<Key32> {
    let mut buffer: u32 = 0;
    let mut bits = 0;
    let mut out = Zeroizing::new(Vec::with_capacity(33));
    let mut symbols = 0;
    for ch in text.chars() {
        let c = ch.to_ascii_uppercase();
        let v = match c {
            '-' | ' ' | '\t' | '\r' | '\n' => continue,
            'O' => 0,
            'I' | 'L' => 1,
            _ => match CROCKFORD.iter().position(|&x| x as char == c) {
                Some(p) => p as u32,
                None => return Err(Error::Invalid("The recovery key contains invalid characters.".into())),
            },
        };
        symbols += 1;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if symbols != 52 || out.len() != 32 {
        return Err(Error::Invalid("A recovery key has 52 characters (13 groups of 4).".into()));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&out);
    Ok(k)
}

// ---------------------------------------------------------------------------
// Recovery escrow (X25519 ECDH -> HKDF -> AES-256-GCM)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EscrowBox {
    #[serde(with = "b64")]
    pub eph_pub: Vec<u8>,
    pub sealed: Sealed,
}

pub fn recovery_x25519_secret(recovery: &[u8; 32], salt: &[u8]) -> x25519_dalek::StaticSecret {
    let k = hkdf32(recovery, salt, b"dirshield/v1/recovery-x25519");
    x25519_dalek::StaticSecret::from(*k)
}

pub fn recovery_public(recovery: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&recovery_x25519_secret(recovery, salt)).to_bytes()
}

fn escrow_kek(shared: &[u8; 32], eph_pub: &[u8; 32], recipient: &[u8; 32]) -> Key32 {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pub);
    salt[32..].copy_from_slice(recipient);
    hkdf32(shared, &salt, b"dirshield/v1/escrow")
}

pub fn escrow_seal(recipient_pub: &[u8; 32], secret: &[u8], aad: &[u8]) -> Result<EscrowBox> {
    let eph = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&x25519_dalek::PublicKey::from(*recipient_pub));
    if !shared.was_contributory() {
        return Err(Error::Format("invalid recovery public key".into()));
    }
    let kek = escrow_kek(shared.as_bytes(), &eph_pub, recipient_pub);
    Ok(EscrowBox { eph_pub: eph_pub.to_vec(), sealed: seal(&kek, secret, aad) })
}

pub fn escrow_open_key(secret: &x25519_dalek::StaticSecret, b: &EscrowBox, aad: &[u8]) -> Result<Key32> {
    let eph: [u8; 32] = b.eph_pub.as_slice().try_into().map_err(|_| Error::Format("bad escrow key".into()))?;
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(eph));
    if !shared.was_contributory() {
        return Err(Error::AuthFailed);
    }
    let me = x25519_dalek::PublicKey::from(secret).to_bytes();
    let kek = escrow_kek(shared.as_bytes(), &eph, &me);
    open_key(&kek, &b.sealed, aad)
}

/// Metadata key used to encrypt sensitive columns (folder names / paths) in SQLite.
pub fn metadata_key(master: &[u8; 32]) -> Key32 {
    hkdf32(master, b"", b"dirshield/v1/db-metadata")
}

pub fn encrypt_text(key: &[u8; 32], text: &str, aad: &[u8]) -> String {
    serde_json::to_string(&seal(key, text.as_bytes(), aad)).expect("serializable")
}

pub fn decrypt_text(key: &[u8; 32], stored: &str, aad: &[u8]) -> Result<String> {
    let s: Sealed = serde_json::from_str(stored)?;
    let pt = open(key, &s, aad).map_err(|_| Error::Integrity("encrypted metadata could not be authenticated".into()))?;
    String::from_utf8(pt.to_vec()).map_err(|_| Error::Integrity("metadata is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_key_roundtrip() {
        let k = random_bytes::<32>();
        let s = encode_recovery_key(&k);
        assert_eq!(s.len(), 52 + 12);
        assert_eq!(*decode_recovery_key(&s).unwrap(), k);
        assert_eq!(*decode_recovery_key(&s.to_lowercase().replace('-', " ")).unwrap(), k);
        assert!(decode_recovery_key("ABCD").is_err());
    }

    #[test]
    fn seal_open_and_tamper() {
        let k = random_key();
        let mut s = seal(&k, b"secret", b"aad");
        assert_eq!(&**open(&k, &s, b"aad").unwrap(), b"secret");
        assert!(matches!(open(&k, &s, b"other"), Err(Error::AuthFailed)));
        s.ct[0] ^= 1;
        assert!(matches!(open(&k, &s, b"aad"), Err(Error::AuthFailed)));
    }

    #[test]
    fn argon2_wrong_password() {
        let p = KdfParams::new_test();
        let a = derive_password_key("correct horse", &p).unwrap();
        let b = derive_password_key("correct horse", &p).unwrap();
        let c = derive_password_key("wrong horse", &p).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn argon2_rejects_absurd_params() {
        let mut p = KdfParams::new_test();
        p.m_cost = u32::MAX;
        assert!(derive_password_key("x", &p).is_err());
    }

    #[test]
    fn escrow_roundtrip() {
        let rk = random_bytes::<32>();
        let salt = random_bytes::<16>();
        let pubk = recovery_public(&rk, &salt);
        let vk = random_key();
        let b = escrow_seal(&pubk, vk.as_ref(), b"vault").unwrap();
        let sec = recovery_x25519_secret(&rk, &salt);
        assert_eq!(*escrow_open_key(&sec, &b, b"vault").unwrap(), *vk);
        let wrong = recovery_x25519_secret(&random_bytes::<32>(), &salt);
        assert!(escrow_open_key(&wrong, &b, b"vault").is_err());
    }
}
