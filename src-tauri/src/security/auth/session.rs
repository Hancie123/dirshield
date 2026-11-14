//! The signed-in session: holds the master key in memory while unlocked
//! and expires it after a period of inactivity.

use parking_lot::Mutex;
use std::time::{Duration, Instant};

use crate::domain::error::{Error, Result};
use crate::security::crypto::Key32;
use zeroize::Zeroizing;

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

    /// A zero duration disables auto-lock (the "Never" option in Settings).
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
    use crate::security::crypto;

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
}
