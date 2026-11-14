//! Unified error type. Serialized to the frontend as `{ code, message }` so the
//! UI can branch on `code` without parsing text. Messages never contain secrets.

use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Incorrect password or key.")]
    AuthFailed,
    #[error("Too many failed attempts. Try again in {0} seconds.")]
    RateLimited(u64),
    #[error("DirShield is locked. Sign in with your master password.")]
    SessionLocked,
    #[error("DirShield has not been set up yet.")]
    NotInitialized,
    #[error("DirShield is already set up.")]
    AlreadyInitialized,
    #[error("Data integrity check failed: {0}")]
    Integrity(String),
    #[error("Unsupported vault format: {0}")]
    Format(String),
    #[error("{0}")]
    Invalid(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Not enough free disk space: {need} bytes required, {free} bytes available.")]
    InsufficientSpace { need: u64, free: u64 },
    #[error("Operation cancelled.")]
    Cancelled,
    #[error("Windows API error: {0}")]
    Win(String),
    #[error("File system error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::AuthFailed => "auth_failed",
            Error::RateLimited(_) => "rate_limited",
            Error::SessionLocked => "session_locked",
            Error::NotInitialized => "not_initialized",
            Error::AlreadyInitialized => "already_initialized",
            Error::Integrity(_) => "integrity",
            Error::Format(_) => "format",
            Error::Invalid(_) => "invalid",
            Error::NotFound(_) => "not_found",
            Error::Conflict(_) => "conflict",
            Error::InsufficientSpace { .. } => "insufficient_space",
            Error::Cancelled => "cancelled",
            Error::Win(_) => "windows",
            Error::Io(_) => "io",
            Error::Db(_) => "db",
            Error::Json(_) => "json",
        }
    }
}

impl Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Error", 2)?;
        st.serialize_field("code", self.code())?;
        st.serialize_field("message", &self.to_string())?;
        st.end()
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn invalid<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(msg.into()))
}
