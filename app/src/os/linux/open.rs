//! Opening links on Linux: the OpenURI portal only. An `xdg-open` fallback cannot exist once
//! Landlock forbids exec, so without a portal the caller shows the address to open by hand.

use std::{
    future::Future,
    sync::{OnceLock, mpsc},
    time::Duration,
};

use ashpd::{Uri, desktop::open_uri::OpenFileRequest};
use tokio::runtime::{Builder, Runtime};

use super::portal;
use crate::hooks::{HookError, HookResult};

/// The portal answers a method call within milliseconds; waiting longer means it is stuck, and the
/// UI thread must not wait on it.
const HAND_OVER_WAIT: Duration = Duration::from_secs(5);

/// How long a process waits for its registration before it drops dumpable. A reply that arrives
/// after that is refused anyway, so a timeout means portal calls fail until the next start.
#[derive(Debug, Clone, Copy)]
pub enum RegistrationWait {
    /// D-Bus's own reply timeout: at login the daemon's call may be what activates the portal.
    Daemon,
    /// The daemon has already activated the portal, and it drops a UI that sends no Hello within
    /// its 5 s handshake timeout, which runs from the spawn.
    Ui,
}

impl RegistrationWait {
    const fn limit(self) -> Duration {
        match self {
            Self::Daemon => Duration::from_secs(25),
            Self::Ui => Duration::from_secs(2),
        }
    }
}

/// Never dropped: ashpd caches its session connection on the runtime that first used it, and the
/// portal restart watcher lives on it too.
fn runtime() -> Option<&'static Runtime> {
    static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("vaultkeeper-portal")
                .enable_all()
                .build()
                .inspect_err(|error| tracing::warn!(%error, "cannot start the portal runtime"))
                .ok()
        })
        .as_ref()
}

/// Runs `work` on the portal runtime and waits for it at most [`HAND_OVER_WAIT`].
fn run_bounded<T: Send + 'static>(work: impl Future<Output = T> + Send + 'static) -> Option<T> {
    run_waiting(work, HAND_OVER_WAIT)
}

fn run_waiting<T: Send + 'static>(
    work: impl Future<Output = T> + Send + 'static,
    wait: Duration,
) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    runtime()?.spawn(async move {
        let _ = tx.send(work.await);
    });
    rx.recv_timeout(wait).ok()
}

/// Registers while this process is still dumpable; daemon and UI call it before
/// `harden_after_handshake`. The portal identifies a caller by opening `/proc/<pid>/root`, which a
/// non-dumpable process denies, and caches the result per connection, so only a registration made
/// now lets later portal calls on ashpd's shared connection through ([`portal`] has the details).
pub fn register_before_hardening(wait: RegistrationWait) {
    if run_waiting(portal::ensure_registered(), wait.limit()).is_none() {
        tracing::warn!(
            "portal registration did not finish before hardening; portal calls will be refused"
        );
    }
}

/// Binds this process to its app id at the portal; file dialogs call it before the first picker.
pub fn register_with_portal() {
    if run_bounded(portal::ensure_registered()).is_none() {
        tracing::warn!("portal registration did not finish in time");
    }
}

fn no_portal_message(url: &url::Url) -> String {
    format!("no portal: open {url} yourself")
}

/// `url` was already limited to http/https by the caller.
pub fn open(url: &url::Url) -> HookResult<()> {
    let uri = Uri::parse(url.as_str())
        .map_err(|error| HookError::Failed(format!("Not a link the portal accepts: {error}")))?;
    let outcome = run_bounded(async move {
        portal::ensure_registered().await;
        OpenFileRequest::default().send_uri(&uri).await.map(drop)
    });
    match outcome {
        Some(Ok(())) => Ok(()),
        Some(Err(error)) => {
            tracing::warn!(%error, "the OpenURI portal refused the link");
            Err(HookError::Failed(no_portal_message(url)))
        }
        None => {
            tracing::warn!("the OpenURI portal did not answer in time");
            Err(HookError::Failed(no_portal_message(url)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fallback_text_carries_the_address() {
        let url = url::Url::parse("https://example.com/login?a=1").expect("url");
        assert_eq!(
            no_portal_message(&url),
            "no portal: open https://example.com/login?a=1 yourself"
        );
    }
}
