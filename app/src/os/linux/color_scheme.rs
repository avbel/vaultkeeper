//! Reads the desktop colour scheme from the Settings portal and follows its changes.
//!
//! Wayland gives winit no initial theme, so a window opened while the desktop is already dark
//! would draw light content under a dark title bar.

use std::time::Duration;

use ashpd::desktop::settings::{ColorScheme, Settings};
use futures_util::StreamExt as _;
use tokio::{runtime::Handle, sync::watch};

use super::portal;
use crate::system_scheme::{self, SystemScheme};

/// A missing or slow portal must never delay the first frame.
const INITIAL_READ_LIMIT: Duration = Duration::from_secs(1);

const fn scheme_of(scheme: ColorScheme) -> SystemScheme {
    match scheme {
        ColorScheme::PreferDark => SystemScheme::Dark,
        ColorScheme::PreferLight => SystemScheme::Light,
        ColorScheme::NoPreference => SystemScheme::Unknown,
    }
}

async fn read_initial() -> SystemScheme {
    portal::ensure_registered().await;
    let Ok(settings) = Settings::new().await else {
        return SystemScheme::Unknown;
    };
    settings
        .color_scheme()
        .await
        .map_or(SystemScheme::Unknown, scheme_of)
}

async fn follow(changes: watch::Sender<SystemScheme>) {
    let Ok(settings) = Settings::new().await else {
        return;
    };
    let Ok(stream) = settings.receive_color_scheme_changed().await else {
        return;
    };
    let mut stream = std::pin::pin!(stream);
    while let Some(scheme) = stream.next().await {
        let scheme = scheme_of(scheme);
        system_scheme::store(scheme);
        if changes.send(scheme).is_err() {
            break;
        }
    }
}

/// Stores the portal's current scheme (waiting at most [`INITIAL_READ_LIMIT`]) and returns a
/// receiver that fires on every later change. Must not be called from inside an async context.
#[must_use]
pub fn start(runtime: &Handle) -> watch::Receiver<SystemScheme> {
    let initial = runtime
        .block_on(tokio::time::timeout(INITIAL_READ_LIMIT, read_initial()))
        .unwrap_or_else(|_| {
            tracing::warn!("the colour scheme portal did not answer in time");
            SystemScheme::Unknown
        });
    system_scheme::store(initial);
    let (sender, receiver) = watch::channel(initial);
    runtime.spawn(follow(sender));
    receiver
}

/// The one-shot read for processes without a runtime (the refusal window).
#[must_use]
pub fn read_once() -> SystemScheme {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let scheme = match runtime {
        Ok(runtime) => runtime
            .block_on(tokio::time::timeout(INITIAL_READ_LIMIT, read_initial()))
            .unwrap_or(SystemScheme::Unknown),
        Err(error) => {
            tracing::warn!(%error, "cannot read the colour scheme");
            SystemScheme::Unknown
        }
    };
    system_scheme::store(scheme);
    scheme
}
