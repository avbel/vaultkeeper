//! HTTP client and wire models for the Bitwarden-compatible API served by Vaultwarden.
//!
//! Vaultwarden mixes PascalCase (`Key`, `Kdf`), snake_case (`access_token`) and camelCase keys
//! across endpoints and versions. Responses are therefore parsed into `serde_json::Value`, keys are
//! normalized (first letter lowercased, recursively) and only then deserialized into the camelCase
//! models below. Encrypted fields stay as `EncString` text; decryption is `bwl-vault`'s job.

mod client;
mod error;
pub mod models;

pub use client::{Client, DeviceInfo, LoginOutcome, TwoFactorProvider, TwoFactorToken};
pub use error::{Error, Result};
