//! Bitwarden-compatible client-side crypto: master key derivation, key stretching,
//! `EncString` (types 0, 2 and 4) and the RSA private key used for organization keys.
//!
//! Every type holding key material zeroizes it on drop.

mod enc_string;
mod error;
mod kdf;
mod keys;

pub use enc_string::EncString;
pub use error::{Error, Result};
pub use kdf::Kdf;
pub use keys::{MasterKey, PrivateKey, SymmetricKey};
