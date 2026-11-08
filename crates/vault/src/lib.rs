//! Vault session: login, lock/unlock, encrypted on-disk cache, decrypt-on-demand views and CRUD.
//!
//! The UI talks only to [`VaultService`]. Unlocking decrypts just what the list and search need
//! (names, subtitles, URIs, folder names); secrets are decrypted per request and returned as
//! `Zeroizing` values the caller drops right after use.

mod error;
pub mod model;
mod service;

pub use bwl_api::TwoFactorProvider;
pub use bwl_gen::totp::TotpCode;
pub use error::{Error, Result};
pub use service::VaultService;
