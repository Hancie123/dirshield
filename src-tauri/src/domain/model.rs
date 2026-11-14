//! Typed values that cross the IPC boundary and are stored in SQLite.
//!
//! Every enum serialises (serde) and is stored (rusqlite) as the same
//! lowercase string the app has always used, so existing databases and the
//! frontend's string unions keep working. An unknown string is rejected when
//! it is read instead of silently falling into an `else` branch.

use std::fmt;

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use serde::{Deserialize, Serialize};

macro_rules! str_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $var:ident = $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum $name {
            $($(#[$vm])* #[serde(rename = $s)] $var),+
        }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$var),+];

            pub fn as_str(self) -> &'static str {
                match self { $($name::$var => $s),+ }
            }

            pub fn parse(s: &str) -> Option<Self> {
                match s { $($s => Some($name::$var),)+ _ => None }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ToSql for $name {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                Ok(ToSqlOutput::from(self.as_str()))
            }
        }

        impl FromSql for $name {
            fn column_result(v: ValueRef<'_>) -> FromSqlResult<Self> {
                let s = v.as_str()?;
                Self::parse(s).ok_or_else(|| FromSqlError::Other(format!("unknown {} {s:?}", stringify!($name)).into()))
            }
        }
    };
}

str_enum! {
    /// Which secret the user is presenting.
    CredentialKind {
        Master = "master",
        Folder = "folder",
        Recovery = "recovery",
        /// Windows Hello (no secret; master-key folders only)
        Hello = "hello",
    }
}

str_enum! {
    /// `vaults.protection_mode`
    ProtectionMode {
        /// ACL + hide, no encryption
        Quick = "quick",
        /// AES-256-GCM vault
        Secure = "secure",
    }
}

str_enum! {
    /// `vaults.key_mode`: what unlocks the folder besides the recovery key.
    KeyMode {
        Master = "master",
        /// a separate folder password
        Password = "password",
    }
}

str_enum! {
    /// `vaults.status`
    VaultStatus {
        QuickLocked = "quick_locked",
        QuickVisible = "quick_visible",
        Encrypting = "encrypting",
        Incomplete = "incomplete",
        /// encrypted, originals still present
        Encrypted = "encrypted",
        Removing = "removing",
        /// encrypted, originals removed
        Locked = "locked",
        Restoring = "restoring",
        Restored = "restored",
        /// re-lock in progress (only changed files are re-encrypted)
        Relocking = "relocking",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_roundtrip_through_serde_and_sql() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        for s in VaultStatus::ALL {
            let json = serde_json::to_string(s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.as_str()));
            assert_eq!(serde_json::from_str::<VaultStatus>(&json).unwrap(), *s);
            let back: VaultStatus = c.query_row("SELECT ?1", [s], |r| r.get(0)).unwrap();
            assert_eq!(back, *s);
        }
        for k in KeyMode::ALL.iter().map(|k| k.as_str()).chain(ProtectionMode::ALL.iter().map(|m| m.as_str())) {
            assert!(KeyMode::parse(k).is_some() || ProtectionMode::parse(k).is_some());
        }
    }

    #[test]
    fn unknown_values_are_rejected() {
        assert!(serde_json::from_str::<CredentialKind>("\"admin\"").is_err());
        let c = rusqlite::Connection::open_in_memory().unwrap();
        assert!(c.query_row("SELECT 'bogus'", [], |r| r.get::<_, VaultStatus>(0)).is_err());
    }
}
