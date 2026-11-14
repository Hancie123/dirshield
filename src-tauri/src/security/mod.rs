//! Everything that protects keys: cryptographic primitives, the master
//! password and recovery key, the signed-in session, rate limiting and
//! Windows Hello.

pub mod auth;
pub mod crypto;
pub mod hello;
