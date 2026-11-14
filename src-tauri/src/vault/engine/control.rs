//! Pause/cancel control and progress counters shared with the UI thread.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::domain::error::{Error, Result};

#[derive(Default)]
pub struct Control {
    pub pause: AtomicBool,
    pub cancel: AtomicBool,
    pub(super) abort: AtomicBool,
    pub processed_bytes: AtomicU64,
    pub processed_files: AtomicU64,
    pub failed_files: AtomicU64,
    pub total_bytes: AtomicU64,
    pub total_files: AtomicU64,
    pub current: Mutex<String>,
    pub phase: Mutex<String>,
}

impl Control {
    pub fn stopped(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || self.abort.load(Ordering::Relaxed)
    }

    /// Called between chunks: blocks while paused, errors when cancelled.
    pub fn checkpoint(&self) -> Result<()> {
        loop {
            if self.stopped() {
                return Err(Error::Cancelled);
            }
            if !self.pause.load(Ordering::Relaxed) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn set_phase(&self, p: &str) {
        *self.phase.lock() = p.to_string();
    }

    pub(super) fn set_current(&self, c: &str) {
        *self.current.lock() = c.to_string();
    }
}

/// Tracks progress contributed by one item so it can be rolled back on failure.
pub(super) struct ItemProgress<'a> {
    ctrl: &'a Control,
    added: u64,
}

impl<'a> ItemProgress<'a> {
    pub(super) fn new(ctrl: &'a Control) -> Self {
        Self { ctrl, added: 0 }
    }
    pub(super) fn add(&mut self, n: u64) {
        self.added += n;
        self.ctrl.processed_bytes.fetch_add(n, Ordering::Relaxed);
    }
    pub(super) fn settle(&mut self, total: u64) {
        if total > self.added {
            self.add(total - self.added);
        } else if total < self.added {
            self.ctrl.processed_bytes.fetch_sub(self.added - total, Ordering::Relaxed);
            self.added = total;
        }
    }
    pub(super) fn rollback(&mut self) {
        self.ctrl.processed_bytes.fetch_sub(self.added, Ordering::Relaxed);
        self.added = 0;
    }
}
