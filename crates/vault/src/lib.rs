//! Vault session: login, lock/unlock, encrypted on-disk cache, decrypt-on-demand views and CRUD.
//!
//! The UI talks only to [`VaultService`]. Unlocking decrypts just what the list and search need
//! (names, subtitles, URIs, folder names); secrets are decrypted per request and returned as
//! `Zeroizing` values the caller drops right after use.
//!
//! [`Vault`] is the real implementation. It is platform-agnostic: tokens go through the injected
//! [`SecretStore`], files under [`VaultConfig::data_dir`], and the host reports sleep, wake and
//! network changes through [`Vault::on_sleep`], [`Vault::on_wake`] and
//! [`Vault::on_network_change`].

mod config;
mod encrypt;
mod error;
mod index;
mod keys;
pub mod model;
mod passthrough;
mod reveal;
mod secrets;
mod service;
mod store;
#[cfg(test)]
mod testutil;
mod util;
mod vault;

pub use config::{Timings, VaultConfig};
pub use error::{
    CONFLICT_MESSAGE, Error, KDF_DOWNGRADE_MESSAGE, LogoutErrors, OFFLINE_MESSAGE, Result,
};
pub use secrets::{MemorySecretStore, SecretStore, SecretStoreError};
pub use service::VaultService;
pub use vault::{BackgroundStatus, Vault};
pub use vk_api::{DeviceInfo, TwoFactorProvider};
pub use vk_gen::totp::TotpCode;
