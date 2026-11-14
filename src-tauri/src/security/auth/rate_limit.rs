//! Rate limiting of password checks, persisted in the database so that
//! restarting DirShield does not reset it.

use parking_lot::Mutex;

use crate::domain::error::{Error, Result};
use crate::storage::db::{now_ms, Db};

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn db() -> (tempfile::TempDir, Db) {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("t.db")).unwrap();
        (d, db)
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
