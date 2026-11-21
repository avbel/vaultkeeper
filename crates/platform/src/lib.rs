//! OS integration. macOS is implemented first; other targets compile with `Unsupported` errors.

pub mod autostart;
pub mod biometric;
pub mod clipboard;
pub mod code_signature;
#[cfg(windows)]
pub mod dpapi;
mod error;
pub mod fs;
pub mod hardening;
pub mod install_kind;
pub mod keychain;
pub mod network;
pub mod paths;
pub mod power;
pub mod security;
pub mod single_instance;

pub use error::{Error, Result};
