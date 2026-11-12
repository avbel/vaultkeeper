//! Bitwarden-compatible client-side crypto: master key derivation, key stretching,
//! `EncString` (types 0, 2 and 4), the RSA private key used for organization keys, the binary
//! attachment format in [`enc_buffer`] and the keys of Sends in [`send`].
//!
//! Every type holding key material zeroizes it on drop.

pub mod enc_buffer;
mod enc_string;
mod error;
mod kdf;
mod keys;
mod primitives;
pub mod send;

pub use enc_string::EncString;
pub use error::{Error, Result};
pub use kdf::Kdf;
pub use keys::{MasterKey, PrivateKey, SymmetricKey};
pub use send::SendKey;
