//! HTTP client and wire models for the Bitwarden-compatible API served by Vaultwarden.
//!
//! Vaultwarden mixes PascalCase (`Key`, `Kdf`), snake_case (`access_token`) and camelCase keys
//! across endpoints and versions. Responses are therefore parsed into `serde_json::Value`, keys are
//! normalized (first letter lowercased, recursively) and only then deserialized into the camelCase
//! models below. Encrypted fields stay as `EncString` text; decryption is `bwl-vault`'s job.
//!
//! [`notifications`] adds the websocket live-sync channel.

mod client;
mod error;
mod http;
mod login;
pub mod models;
mod normalize;
pub mod notifications;
mod probe;
mod server_url;
mod token;

pub use client::{Client, DeviceInfo, LoginOutcome, TwoFactorProvider, TwoFactorToken};
pub use error::{Error, Result};
pub use http::HttpTimeouts;
pub use probe::Prober;
pub use server_url::{is_local_host, validate_server_url};
