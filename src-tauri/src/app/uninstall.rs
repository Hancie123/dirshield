//! `--confirm-uninstall`: started by the uninstaller. Only the password
//! window is shown; the exit code tells the uninstaller whether to go on
//! (0 = master password confirmed, 1 = cancelled).

use std::sync::atomic::AtomicBool;

pub const CONFIRM_UNINSTALL_ARG: &str = "--confirm-uninstall";

/// DirShield was started by the uninstaller.
pub static UNINSTALL_MODE: AtomicBool = AtomicBool::new(false);

/// The master password was confirmed in the uninstall prompt.
pub static UNINSTALL_CONFIRMED: AtomicBool = AtomicBool::new(false);
