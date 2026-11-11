//! Isolated browser socket and its JSON protocol.

pub mod protocol;
mod server;

pub use server::{BrowserConnection, BrowserServeOptions, BrowserServerHandle, serve_browser};

pub const BROWSER_MAX_FRAME: usize = 64 * 1024;
