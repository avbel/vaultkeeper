//! TOTP code generation and password/passphrase generators.

mod error;
pub mod generator;
pub mod totp;

pub use error::{Error, Result};
