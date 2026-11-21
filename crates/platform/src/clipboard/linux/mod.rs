//! Chain C8 on Linux: the clipboard link that works on this compositor, strongest first.
//!
//! 1. `ext-data-control-v1` through wl-clipboard-rs (KDE, Sway, Hyprland): offers the secret hint,
//!    so clipboard history skips the entry.
//! 2. The RemoteDesktop + Clipboard portal (GNOME), supplied by the app as a [`PortalClipboard`]
//!    because the portal client lives there.
//! 3. arboard: a plain set that history managers may record ("Reduced").
//!
//! Selection and fallback are plain functions over injected probes and backends, so they are
//! unit-tested on every host; only the three real links are Linux-only.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod chain;
#[cfg(target_os = "linux")]
mod data_control;
mod fallback;
#[cfg(target_os = "linux")]
mod plain;

#[cfg(target_os = "linux")]
use crate::Result;
use crate::security::Probe;

#[cfg(target_os = "linux")]
pub use chain::{Capabilities, LinkKind};
#[cfg(target_os = "linux")]
pub use fallback::LinuxClipboard;

use super::ClipboardBackend;

/// The GNOME link, implemented by the app. Its `availability` is answered from the probe it ran
/// when it was created; it may ask the user for permission on the first `set_secret`.
pub trait PortalClipboard: ClipboardBackend {
    fn availability(&self) -> Probe;
}

/// Probes the real links and builds the clipboard from those that work.
#[cfg(target_os = "linux")]
pub fn open(portal: Option<Box<dyn PortalClipboard>>) -> Result<LinuxClipboard> {
    let plain = plain::open();
    let capabilities = Capabilities {
        data_control: data_control::probe(),
        portal: portal.as_ref().map_or_else(
            || Probe::Unavailable("the app did not provide the portal clipboard".into()),
            |portal| portal.availability(),
        ),
        plain: plain
            .as_ref()
            .map_or_else(|why| Probe::Unavailable(why.clone()), |_| Probe::Available),
    };
    let portal =
        portal.map(|portal| Box::new(PortalAsBackend(portal)) as Box<dyn ClipboardBackend>);
    let parts = fallback::Parts {
        data_control: Some(Box::new(data_control::DataControl)),
        portal,
        plain: plain
            .ok()
            .map(|plain| Box::new(plain) as Box<dyn ClipboardBackend>),
    };
    LinuxClipboard::assemble(&capabilities, parts)
}

#[cfg(target_os = "linux")]
struct PortalAsBackend(Box<dyn PortalClipboard>);

#[cfg(target_os = "linux")]
impl ClipboardBackend for PortalAsBackend {
    fn set_secret(&mut self, text: &str) -> Result<()> {
        self.0.set_secret(text)
    }

    fn text(&mut self) -> Result<Option<zeroize::Zeroizing<String>>> {
        self.0.text()
    }

    fn clear(&mut self) -> Result<()> {
        self.0.clear()
    }
}
