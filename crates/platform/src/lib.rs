//! OS integration. macOS is implemented first; other targets compile with `Unsupported` errors.

pub mod autostart;
pub mod biometric;
pub mod clipboard;
mod error;
pub mod fs;
pub mod hardening;
pub mod keychain;
pub mod network;
pub mod paths;
pub mod power;
pub mod single_instance;

pub use error::{Error, Result};
