//! Secure Lock vault format and engine. See docs/VAULT_FORMAT.md.
//!
//! On-disk layout of a vault directory (named by its random vault id):
//! ```text
//! <vault id>/
//!   vault.dsv            header: algorithms, KDF params, salts, key wrappers, sealed flag, HMAC
//!   manifest.dsb         encrypted manifest (names, structure, sizes, times, attrs, checksums)
//!   objects/<xx>/<id>.dsb  one encrypted blob per file, named by a random id
//! ```
//! No original file or folder name appears anywhere in the vault directory.

pub mod engine;
pub mod header;
pub mod manifest;
pub mod scan;
pub mod stream;
