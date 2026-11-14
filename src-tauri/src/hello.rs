//! Windows Hello unlock (fingerprint, face or PIN).
//!
//! ```text
//! Windows Hello key credential (RSA-2048 key pair held by the TPM, or by
//! software where there is none; usable only after a Hello check)
//!   signs  "dirshield/v1/hello-challenge" || challenge (32 random bytes)
//!   --RSASSA-PKCS1-v1_5 (deterministic)--> signature
//! HKDF-SHA256(signature, salt = challenge)  --> KEK_hello
//! KEK_hello --AES-GCM--> master key, then DPAPI (current Windows user) on top
//! ```
//! The signature can only be produced on this PC, by this Windows account,
//! after Windows Hello verifies the user, so the stored record is useless on
//! its own (copied database, other account, other machine). The master
//! password and recovery key keep working exactly as before; turning Hello
//! off deletes both the record and the key credential.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, b64, Key32, Sealed};
use crate::db::Db;
use crate::error::{Error, Result};

const SETTING: &str = "windowsHello";
const AAD: &[u8] = b"dirshield/v1/master-key/hello";
const CHALLENGE_LABEL: &[u8] = b"dirshield/v1/hello-challenge";
const DPAPI_ENTROPY: &[u8] = b"dirshield/v1/hello-dpapi";

#[derive(Serialize, Deserialize)]
struct Record {
    v: u32,
    /// Name of the Windows Hello key credential.
    credential: String,
    #[serde(with = "b64")]
    challenge: Vec<u8>,
    /// DPAPI-protected JSON of the sealed master key.
    #[serde(with = "b64")]
    protected: Vec<u8>,
}

fn load(db: &Db) -> Result<Option<Record>> {
    Ok(match db.get_setting(SETTING)? {
        Some(s) if !s.is_empty() => Some(serde_json::from_str(&s)?),
        _ => None,
    })
}

fn message(challenge: &[u8]) -> Vec<u8> {
    [CHALLENGE_LABEL, challenge].concat()
}

fn kek(signature: &[u8], challenge: &[u8]) -> Key32 {
    crypto::hkdf32(signature, challenge, b"dirshield/v1/hello-kek")
}

/// Windows Hello is set up on this PC (a PIN at least) and usable.
pub fn available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(platform::supported)
}

pub fn is_enabled(db: &Db) -> bool {
    load(db).ok().flatten().is_some()
}

/// Turns Hello unlock on for master key `mk` (shows the Hello prompt).
pub fn enable(db: &Db, mk: &[u8; 32]) -> Result<()> {
    if !available() {
        return Err(not_set_up());
    }
    let name = format!("DirShield-{}", &crypto::random_id()[..16]);
    platform::create(&name)?;
    let challenge = crypto::random_bytes::<32>().to_vec();
    let sig = match platform::sign(&name, &message(&challenge)) {
        Ok(s) => s,
        Err(e) => {
            platform::delete(&name);
            return Err(e);
        }
    };
    let sealed = crypto::seal(&kek(&sig, &challenge), mk, AAD);
    let protected = platform::protect(&serde_json::to_vec(&sealed)?, DPAPI_ENTROPY)?;
    let old = load(db).ok().flatten();
    db.set_setting(SETTING, &serde_json::to_string(&Record { v: 1, credential: name, challenge, protected })?)?;
    if let Some(old) = old {
        platform::delete(&old.credential);
    }
    Ok(())
}

/// Shows the Hello prompt and returns the master key.
pub fn unlock(db: &Db) -> Result<Key32> {
    let rec = load(db)?.ok_or_else(|| Error::Invalid("Windows Hello isn't turned on for DirShield. Use your master password.".into()))?;
    let sig = platform::sign(&rec.credential, &message(&rec.challenge))?;
    let raw = Zeroizing::new(platform::unprotect(&rec.protected, DPAPI_ENTROPY)?);
    let sealed: Sealed = serde_json::from_slice(&raw).map_err(|_| Error::Integrity("Windows Hello record is damaged".into()))?;
    crypto::open_key(&kek(&sig, &rec.challenge), &sealed, AAD)
        .map_err(|_| Error::Invalid("Windows Hello couldn't unlock DirShield (its key changed). Use your master password, then turn Windows Hello off and on again in Settings.".into()))
}

pub fn disable(db: &Db) -> Result<()> {
    if let Some(rec) = load(db).ok().flatten() {
        platform::delete(&rec.credential);
    }
    db.set_setting(SETTING, "")
}

fn not_set_up() -> Error {
    Error::Invalid("Windows Hello isn't set up on this PC. Add a PIN, fingerprint or face in Windows Settings > Accounts > Sign-in options.".into())
}

#[cfg(windows)]
mod platform {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use windows::core::{Array, HSTRING, PCWSTR};
    use windows::Security::Credentials::{KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus};
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB};
    use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
    use zeroize::Zeroizing;

    use crate::error::{Error, Result};

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    fn win(e: windows::core::Error) -> Error {
        Error::Win(format!("Windows Hello: {}", e.message()))
    }

    fn check(s: KeyCredentialStatus) -> Result<()> {
        if s == KeyCredentialStatus::Success {
            Ok(())
        } else if s == KeyCredentialStatus::UserCanceled || s == KeyCredentialStatus::UserPrefersPassword {
            Err(Error::Cancelled)
        } else if s == KeyCredentialStatus::NotFound {
            Err(Error::Invalid("DirShield's Windows Hello key is gone. Use your master password, then turn Windows Hello on again in Settings.".into()))
        } else if s == KeyCredentialStatus::SecurityDeviceLocked {
            Err(Error::Invalid("Windows Hello is locked after too many attempts. Use your master password.".into()))
        } else {
            Err(Error::Win(format!("Windows Hello failed (status {}).", s.0)))
        }
    }

    pub fn supported() -> bool {
        KeyCredentialManager::IsSupportedAsync().and_then(|op| op.get()).unwrap_or(false)
    }

    /// Unpackaged desktop apps get the Hello dialog without an owner window,
    /// and Windows sometimes opens it behind the app. Keep bringing it to the
    /// front while the request is pending.
    struct Foreground(Arc<AtomicBool>);

    impl Foreground {
        fn start() -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let s = stop.clone();
            std::thread::spawn(move || {
                let class = HSTRING::from("Credential Dialog Xaml Host");
                let started = Instant::now();
                while !s.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(20) {
                    if let Ok(h) = unsafe { FindWindowW(PCWSTR(class.as_ptr()), PCWSTR::null()) } {
                        if !h.is_invalid() {
                            let _ = unsafe { SetForegroundWindow(h) };
                            return;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
            Foreground(stop)
        }
    }

    impl Drop for Foreground {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    pub fn create(name: &str) -> Result<()> {
        let _fg = Foreground::start();
        let r = KeyCredentialManager::RequestCreateAsync(&HSTRING::from(name), KeyCredentialCreationOption::ReplaceExisting).and_then(|op| op.get()).map_err(win)?;
        check(r.Status().map_err(win)?)
    }

    pub fn sign(name: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let r = KeyCredentialManager::OpenAsync(&HSTRING::from(name)).and_then(|op| op.get()).map_err(win)?;
        check(r.Status().map_err(win)?)?;
        let cred = r.Credential().map_err(win)?;
        let buf = CryptographicBuffer::CreateFromByteArray(data).map_err(win)?;
        let _fg = Foreground::start();
        let res = cred.RequestSignAsync(&buf).and_then(|op| op.get()).map_err(win)?;
        check(res.Status().map_err(win)?)?;
        let out = res.Result().map_err(win)?;
        let mut arr = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&out, &mut arr).map_err(win)?;
        Ok(Zeroizing::new(arr.to_vec()))
    }

    pub fn delete(name: &str) {
        let _ = KeyCredentialManager::DeleteAsync(&HSTRING::from(name)).and_then(|op| op.get());
    }

    fn blob(b: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: b.len() as u32, pbData: b.as_ptr() as *mut u8 }
    }

    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        unsafe { LocalFree(Some(HLOCAL(out.pbData as _))) };
        v
    }

    pub fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let (input, ent) = (blob(data), blob(entropy));
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe { CryptProtectData(&input, PCWSTR::null(), Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out) }.map_err(|e| Error::Win(format!("CryptProtectData: {e}")))?;
        Ok(take(out))
    }

    pub fn unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let (input, ent) = (blob(data), blob(entropy));
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe { CryptUnprotectData(&input, None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out) }
            .map_err(|_| Error::Invalid("The Windows Hello record belongs to another Windows account or PC. Use your master password.".into()))?;
        Ok(take(out))
    }
}

#[cfg(not(windows))]
mod platform {
    use crate::error::{Error, Result};
    use zeroize::Zeroizing;

    fn unsupported() -> Error {
        Error::Invalid("Windows Hello is only available on Windows.".into())
    }
    pub fn supported() -> bool {
        false
    }
    pub fn create(_: &str) -> Result<()> {
        Err(unsupported())
    }
    pub fn sign(_: &str, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(unsupported())
    }
    pub fn delete(_: &str) {}
    pub fn protect(_: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        Err(unsupported())
    }
    pub fn unprotect(_: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        Err(unsupported())
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn dpapi_roundtrip_and_entropy_binding() {
        let p = super::platform::protect(b"secret", b"e1").unwrap();
        assert_eq!(super::platform::unprotect(&p, b"e1").unwrap(), b"secret");
        assert!(super::platform::unprotect(&p, b"e2").is_err());
    }
}
