//! Website icons, fetched and cached by the daemon so they outlive the on-demand UI process.

use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiteIcon {
    /// The encoded image.
    Found(Vec<u8>),
    /// The server has no icon for the host; asking again will not change that.
    Missing,
    /// Locked, offline, or the server failed for now; worth asking again later.
    Unavailable,
}

pub type IconFuture = Pin<Box<dyn Future<Output = SiteIcon> + Send>>;

pub trait SiteIconHost: Send + Sync + 'static {
    /// The icon of `host` from the active account's server.
    fn icon(&self, host: String) -> IconFuture;
}
