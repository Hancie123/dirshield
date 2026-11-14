//! Master password, recovery key, session and rate limiting.
//!
//! Key hierarchy
//! ```text
//! master password --Argon2id(salt)--> KEK_pw  --AES-GCM--> master key (MK, random 256-bit)
//! recovery key (256-bit) --HKDF-->     KEK_rec --AES-GCM--> MK
//! recovery key --HKDF--> X25519 secret; its public key is stored so every
//!                         vault key can be escrowed without the recovery key.
//! MK --AES-GCM--> vault key (master-mode vaults)
//! MK --HKDF--> metadata key (encrypts names/paths in SQLite)
//! ```
//! Changing the master password only re-wraps MK; no vault is re-encrypted.

use parking_lot::Mutex;
use std::time::{Duration, Instant};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, b64, KdfParams, Key32, Sealed};
use crate::db::{now_ms, Db};
use crate::error::{Error, Result};

const AAD_MK_PW: &[u8] = b"dirshield/v1/master-key/password";
const AAD_MK_REC: &[u8] = b"dirshield/v1/master-key/recovery";
pub const MIN_PASSWORD_LEN: usize = 8;

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

pub fn validate_new_password(pw: &str) -> Result<()> {
    if pw.chars().count() < MIN_PASSWORD_LEN {
        return Err(Error::Invalid(format!("Passwords must be at least {MIN_PASSWORD_LEN} characters.")));
    }
    if pw.len() > 1024 {
        return Err(Error::Invalid("Password is too long.".into()));
    }
    Ok(())
}

/// Minimum zxcvbn score (0–4) for the master password. 3 = "safely
/// unguessable": strong protection against an offline attack on Argon2id.
pub const MIN_MASTER_SCORE: u8 = 3;

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PasswordStrength {
    /// 0 (too guessable) ... 4 (very unguessable)
    pub score: u8,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

/// zxcvbn estimate of how guessable `pw` is (dictionary words, names,
/// keyboard patterns, dates, repeats, l33t substitutions...).
pub fn password_strength(pw: &str) -> PasswordStrength {
    if pw.is_empty() || pw.len() > 1024 {
        return PasswordStrength { score: 0, warning: None, suggestions: vec![] };
    }
    // zxcvbn's matching gets very slow on long inputs; like the reference
    // implementation, only the first 100 characters are analysed. Anything
    // longer that passes those is a long passphrase anyway.
    let pw: &str = match pw.char_indices().nth(100) {
        Some((i, _)) => &pw[..i],
        None => pw,
    };
    let e = zxcvbn::zxcvbn(pw, &["dirshield", "dir shield", "folder", "lock"]);
    let (warning, suggestions) = match e.feedback() {
        Some(f) => (f.warning().map(|w| w.to_string()), f.suggestions().iter().map(|s| s.to_string()).collect()),
        None => (None, vec![]),
    };
    PasswordStrength { score: e.score().into(), warning, suggestions }
}

/// Rules for a new master password: the length rules plus a zxcvbn check.
/// The master password is the only thing between an offline attacker holding
/// the database and every vault key, so "eight characters" is not enough.
pub fn validate_master_password(pw: &str) -> Result<()> {
    validate_new_password(pw)?;
    let s = password_strength(pw);
    if s.score < MIN_MASTER_SCORE {
        let why = s.warning.map(|w| format!(" {w}")).unwrap_or_default();
        return Err(Error::Invalid(format!("This master password is too easy to guess.{why} Try a longer passphrase of several unrelated words.")));
    }
    Ok(())
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
    let kek = crypto::derive_password_key(password, &meta.kdf)?;
    crypto::open_key(&kek, &meta.mk_by_password, AAD_MK_PW)
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

// ---------------------------------------------------------------------------
// Rate limiting (persisted so restarting the app does not reset it)
// ---------------------------------------------------------------------------

const FREE_ATTEMPTS: i64 = 5;

pub struct RateLimiter;

impl RateLimiter {
    pub fn check(db: &Db) -> Result<()> {
        let until: i64 = db.get_setting("auth.lock_until")?.and_then(|v| v.parse().ok()).unwrap_or(0);
        let now = now_ms();
        if until > now {
            return Err(Error::RateLimited(((until - now) as u64).div_ceil(1000)));
        }
        Ok(())
    }

    pub fn remaining_ms(db: &Db) -> i64 {
        let until: i64 = db.get_setting("auth.lock_until").ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(0);
        (until - now_ms()).max(0)
    }

    pub fn failure(db: &Db) -> Result<()> {
        let n: i64 = db.get_setting("auth.failures")?.and_then(|v| v.parse().ok()).unwrap_or(0) + 1;
        db.set_setting("auth.failures", &n.to_string())?;
        if n >= FREE_ATTEMPTS {
            // 30 s, 60 s, 120 s ... capped at 15 minutes
            let secs = (30i64 << (n - FREE_ATTEMPTS).min(5)).min(900);
            db.set_setting("auth.lock_until", &(now_ms() + secs * 1000).to_string())?;
        }
        db.log("authentication", None, "failed", None);
        Ok(())
    }

    pub fn success(db: &Db) -> Result<()> {
        db.set_setting("auth.failures", "0")?;
        db.set_setting("auth.lock_until", "0")?;
        Ok(())
    }

    /// Runs `f` (which performs a password check) under the rate limiter.
    ///
    /// The check, the verification and the bookkeeping run under one global
    /// gate, so parallel attempts are serialised: each sees the failures
    /// recorded by the ones before it and cannot slip past the limit while
    /// another attempt is still inside Argon2. `f` must not call `guarded`
    /// itself (the gate is not re-entrant).
    pub fn guarded<T>(db: &Db, f: impl FnOnce() -> Result<T>) -> Result<T> {
        static GATE: Mutex<()> = Mutex::new(());
        let _gate = GATE.lock();
        Self::check(db)?;
        match f() {
            Ok(v) => {
                Self::success(db)?;
                Ok(v)
            }
            Err(Error::AuthFailed) => {
                Self::failure(db)?;
                Err(Error::AuthFailed)
            }
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Session: holds the master key in memory while unlocked.
// ---------------------------------------------------------------------------

pub struct Session {
    inner: Mutex<SessionInner>,
}

struct SessionInner {
    master: Option<Key32>,
    last_activity: Instant,
    timeout: Duration,
}

impl Default for Session {
    fn default() -> Self {
        Self { inner: Mutex::new(SessionInner { master: None, last_activity: Instant::now(), timeout: Duration::from_secs(600) }) }
    }
}

impl Session {
    pub fn unlock(&self, mk: Key32) {
        let mut s = self.inner.lock();
        s.master = Some(mk);
        s.last_activity = Instant::now();
    }

    pub fn lock(&self) {
        self.inner.lock().master = None; // Zeroizing wipes the key on drop
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.lock().master.is_some()
    }

    pub fn touch(&self) {
        self.inner.lock().last_activity = Instant::now();
    }

    pub fn set_timeout(&self, d: Duration) {
        self.inner.lock().timeout = d;
    }

    /// Copy of the master key for the duration of one command.
    ///
    /// Does NOT count as user activity: background refreshes (polling,
    /// event-driven reloads) call this constantly and must not keep an
    /// unattended session alive. Use [`Session::master_active`] for commands
    /// the user explicitly started.
    pub fn master(&self) -> Result<Key32> {
        let s = self.inner.lock();
        s.master.as_ref().map(|k| Zeroizing::new(**k)).ok_or(Error::SessionLocked)
    }

    /// Like [`Session::master`], but also resets the idle timer. For
    /// user-initiated actions only.
    pub fn master_active(&self) -> Result<Key32> {
        let mut s = self.inner.lock();
        let k = s.master.as_ref().map(|k| Zeroizing::new(**k)).ok_or(Error::SessionLocked)?;
        s.last_activity = Instant::now();
        Ok(k)
    }

    /// Returns true if the session was auto-locked by this call.
    pub fn expire_if_idle(&self) -> bool {
        let mut s = self.inner.lock();
        if s.master.is_some() && !s.timeout.is_zero() && s.last_activity.elapsed() > s.timeout {
            s.master = None;
            return true;
        }
        false
    }
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
    fn strength_is_fast_on_long_input() {
        let long = "a1b2c3d4e5".repeat(100);
        let t = std::time::Instant::now();
        password_strength(&long);
        assert!(t.elapsed() < Duration::from_secs(2), "took {:?}", t.elapsed());
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

    #[test]
    fn rate_limit_kicks_in() {
        let (_d, db) = db();
        for _ in 0..FREE_ATTEMPTS {
            let _ = RateLimiter::guarded::<()>(&db, || Err(Error::AuthFailed));
        }
        assert!(matches!(RateLimiter::check(&db), Err(Error::RateLimited(_))));
        assert!(matches!(RateLimiter::guarded(&db, || Ok(())), Err(Error::RateLimited(_))));
    }

    #[test]
    fn session_auto_lock() {
        let s = Session::default();
        s.unlock(crypto::random_key());
        s.set_timeout(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(s.expire_if_idle());
        assert!(matches!(s.master(), Err(Error::SessionLocked)));
    }

    #[test]
    fn background_reads_do_not_reset_idle_timer() {
        let s = Session::default();
        s.unlock(crypto::random_key());
        s.set_timeout(Duration::from_millis(20));
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(5));
            s.master().unwrap();
        }
        assert!(s.expire_if_idle());
    }

    #[test]
    fn user_actions_reset_idle_timer() {
        let s = Session::default();
        s.unlock(crypto::random_key());
        s.set_timeout(Duration::from_millis(50));
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(15));
            s.master_active().unwrap();
        }
        assert!(!s.expire_if_idle());
    }

    #[test]
    fn parallel_attempts_cannot_bypass_rate_limit() {
        let (_d, db) = db();
        let passed = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|sc| {
            for _ in 0..(FREE_ATTEMPTS * 4) {
                sc.spawn(|| {
                    let _ = RateLimiter::guarded::<()>(&db, || {
                        passed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(20)); // stand-in for Argon2
                        Err(Error::AuthFailed)
                    });
                });
            }
        });
        assert_eq!(passed.load(std::sync::atomic::Ordering::SeqCst), FREE_ATTEMPTS as usize);
    }
}
