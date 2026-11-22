//! SSH agent client connection listener abstraction

#[cfg(unix)]
pub(crate) mod unix;

#[cfg(windows)]
pub(crate) mod windows;

#[cfg(windows)]
pub use windows::PipeNameTaken;

use std::time::Duration;

use anyhow::Result;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::Sender,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use super::connection::Connection;

/// Implementors handle platform-specific socket/pipe creation and connection acceptance.
#[async_trait::async_trait]
pub(crate) trait Listener: Send + Sync {
    /// The stream type returned by `accept()`
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// Accept a new connection
    async fn accept(&mut self) -> Result<Connection<Self::Stream>>;
}

/// Creates the listeners for the Unix platform.
#[cfg(unix)]
pub(crate) fn create_listeners() -> Result<Vec<impl Listener>> {
    Ok(vec![unix::UnixListener::new()?])
}

/// vk patch: creates the Unix listener on an explicit socket path.
#[cfg(unix)]
pub(crate) fn create_listeners_at(socket_path: std::path::PathBuf) -> Result<Vec<impl Listener>> {
    Ok(vec![unix::UnixListener::bind(socket_path)?])
}

/// Creates the listeners for the Windows platform.
#[cfg(windows)]
pub(crate) fn create_listeners() -> Result<Vec<impl Listener>> {
    Ok(vec![windows::WindowsListener::new()?])
}

/// vk patch: creates the Windows listener on an explicit pipe name.
#[cfg(windows)]
pub(crate) fn create_listeners_on(name: &str) -> Result<Vec<impl Listener>> {
    Ok(vec![windows::WindowsListener::with_name(name)?])
}

/// vk patch: pause after the first failed accept; it doubles per consecutive failure.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(10);

/// vk patch: ceiling for the pause between failed accepts (e.g. `EMFILE` until a handler closes).
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// vk patch: an accept failure after which the listener can never accept again, so its task
/// exits (and the server reports not running) instead of retrying forever.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct ListenerExhausted(pub(crate) &'static str);

/// Spawns an independent tokio task for each listener in `listeners`.
///
/// Each task loops calling `listener.accept()` and forwards accepted connections to `tx`.
/// Tasks exit when the cancellation token is triggered, the channel receiver is dropped, or the
/// listener reports [`ListenerExhausted`].
pub(crate) fn spawn_listener_tasks<L>(
    listeners: Vec<L>,
    tx: &Sender<Connection<L::Stream>>,
    cancel_token: &CancellationToken,
) where
    L: Listener + 'static,
{
    for listener in listeners {
        tokio::spawn(run_listener(listener, tx.clone(), cancel_token.clone()));
    }
}

async fn run_listener<L: Listener>(
    mut listener: L,
    tx: Sender<Connection<L::Stream>>,
    token: CancellationToken,
) {
    let mut backoff = ACCEPT_BACKOFF_MIN;
    loop {
        tokio::select! {
            () = token.cancelled() => {
                debug!("Listener task received cancellation signal");
                break;
            }
            result = listener.accept() => match result {
                Ok(conn) => {
                    backoff = ACCEPT_BACKOFF_MIN;
                    // Receiver dropped; main loop has exited
                    if tx.send(conn).await.is_err() {
                        break;
                    }
                }
                Err(error) if error.downcast_ref::<ListenerExhausted>().is_some() => {
                    error!(%error, "Listener can no longer accept, stopping it");
                    break;
                }
                Err(error) => {
                    error!(%error, ?backoff, "Listener accept failed, retrying");
                    tokio::select! {
                        () = token.cancelled() => break,
                        () = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                }
            }
        }
    }
}
