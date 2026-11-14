//! Application shell: shared state, windows, tray icon, background
//! operations and the uninstall handshake.

pub mod ops;
pub mod state;
pub mod tray;
pub mod uninstall;
pub mod windows;

pub use state::{reconcile, AppState, BrowseSession, Dirs, WorkSession};
