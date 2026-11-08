//! OS integration. macOS is implemented first; other targets compile with `Unsupported` errors.

pub mod autostart;
pub mod biometric;
pub mod clipboard;
mod error;
pub mod hardening;
pub mod keychain;
pub mod paths;
pub mod single_instance;

pub use error::{Error, Result};
