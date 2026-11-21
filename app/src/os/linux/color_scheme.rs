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
    // The timer is created inside `block_on`: a `timeout` built on this thread, outside the
    // runtime, panics with "no reactor running".
    let initial = runtime
        .block_on(async { tokio::time::timeout(INITIAL_READ_LIMIT, read_initial()).await })
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
        // Same reason as in `start`: the timer must be created inside the runtime.
        Ok(runtime) => runtime
            .block_on(async { tokio::time::timeout(INITIAL_READ_LIMIT, read_initial()).await })
            .unwrap_or(SystemScheme::Unknown),
        Err(error) => {
            tracing::warn!(%error, "cannot read the colour scheme");
            SystemScheme::Unknown
        }
    };
    system_scheme::store(scheme);
    scheme
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `run_ui` calls `start` from the main thread, outside the runtime; building the timeout there
    /// panicked with "no reactor running".
    #[test]
    fn start_works_from_a_thread_outside_the_runtime() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let receiver = start(runtime.handle());
        assert_eq!(*receiver.borrow(), system_scheme::current());
    }

    /// The refusal window calls it with no runtime at all; it panicked the same way.
    #[test]
    fn read_once_works_without_a_runtime() {
        assert_eq!(read_once(), system_scheme::current());
    }
}
