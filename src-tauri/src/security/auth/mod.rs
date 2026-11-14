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

mod master_key;
mod password;
mod rate_limit;
mod session;

pub use master_key::*;
pub use password::*;
pub use rate_limit::RateLimiter;
pub use session::Session;
