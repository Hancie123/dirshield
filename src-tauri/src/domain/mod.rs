//! Types shared by every layer: the error type, the typed values that cross
//! the IPC boundary and are stored in SQLite, and pure policy checks.

pub mod error;
pub mod model;
pub mod policy;
