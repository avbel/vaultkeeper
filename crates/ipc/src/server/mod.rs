//! Daemon side: owns the socket and serves one UI process at a time.
//!
//! Task tree: the accept loop owns a `JoinSet` of connections; each connection owns its reader
//! (which owns a `JoinSet` of in-flight calls), its writer and two forwarders through abort-on-drop
//! guards. Dropping [`ServerHandle`] aborts the accept loop, and every task below it is dropped
//! with its owner. Only service calls already running on the blocking pool (`spawn_blocking`)
//! finish on their own.

mod connection;
mod dispatch;

use std::{
    fs::{self, DirBuilder, Permissions},
    io,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use bwl_vault::VaultService;
use tokio::{
    net::UnixListener,
    sync::{Mutex, Semaphore, mpsc, oneshot, watch},
    task::{JoinError, JoinHandle, JoinSet},
};

use crate::{
    IpcError, PeerVerifier, SameExecutable,
    peer::own_uid,
    protocol::{SshDecision, SshPrompt, UiCommand, UiNotice},
};

const DIR_MODE: u32 = 0o700;
const SOCKET_MODE: u32 = 0o600;
const DEFAULT_MAX_CALLS: usize = 8;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a graceful shutdown waits for connections to deliver `Shutdown`.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
/// Pause after a failed `accept` (e.g. out of file descriptors) so the loop does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What the daemon pushes to the UI process. Events wait in the channel while no UI is
/// connected and are delivered, at most once, to the next one.
#[derive(Debug)]
pub enum DaemonEvent {
    Command(UiCommand),
    /// Dropping `reply`, or the UI disconnecting, counts as deny.
    SshApproval {
        prompt: SshPrompt,
        reply: oneshot::Sender<SshDecision>,
    },
    /// Tells the connected UI process to exit.
    Shutdown,
}

pub struct ServeOptions {
    /// Asked after the uid check passed.
    pub verifier: Arc<dyn PeerVerifier>,
    /// Service calls of one connection that run at the same time.
    pub max_concurrent_calls: usize,
    /// How long a new connection may take to send `Hello`.
    pub handshake_timeout: Duration,
    /// Where [`UiNotice`]s from the UI process go; dropped when `None` or when the channel is full.
    pub notices: Option<mpsc::Sender<UiNotice>>,
}

impl ServeOptions {
    /// Only this executable may connect; 8 concurrent calls; 5 s to say `Hello`.
    pub fn new() -> io::Result<Self> {
        Ok(Self::with_verifier(SameExecutable::current()?))
    }

    pub fn with_verifier(verifier: impl PeerVerifier) -> Self {
        Self {
            verifier: Arc::new(verifier),
            max_concurrent_calls: DEFAULT_MAX_CALLS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            notices: None,
        }
    }

    #[must_use]
    pub fn with_notices(self, notices: mpsc::Sender<UiNotice>) -> Self {
        Self {
            notices: Some(notices),
            ..self
        }
    }
}

/// Stops the server when dropped: the accept loop, the connection and its calls are aborted and
/// the socket file is removed.
#[must_use = "dropping the handle stops the IPC server"]
pub struct ServerHandle {
    path: PathBuf,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    slot: Arc<Semaphore>,
}

impl ServerHandle {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A UI process finished the handshake and is still connected.
    #[must_use]
    pub fn is_ui_connected(&self) -> bool {
        self.slot.available_permits() == 0
    }

    /// Sends `Shutdown` to the connected UI, waits up to a second for it to go out, then stops.
    pub async fn shutdown(mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            log_join("IPC accept loop", task.await);
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Err(error) = fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, path = %self.path.display(), "cannot remove the IPC socket");
        }
    }
}

struct Shared<S> {
    service: Arc<S>,
    events: Arc<Mutex<mpsc::Receiver<DaemonEvent>>>,
    verifier: Arc<dyn PeerVerifier>,
    uid: u32,
    max_concurrent_calls: usize,
    handshake_timeout: Duration,
    notices: Option<mpsc::Sender<UiNotice>>,
    /// One permit: the connected UI process.
    slot: Arc<Semaphore>,
}

/// [`serve_with`] using [`ServeOptions::new`].
pub async fn serve<S: VaultService>(
    path: impl Into<PathBuf>,
    service: Arc<S>,
    events: mpsc::Receiver<DaemonEvent>,
) -> Result<ServerHandle, IpcError> {
    serve_with(path, service, events, ServeOptions::new()?).await
}

/// Binds `path` (mode 0600, parent directory forced to 0700) and starts serving. A socket left
/// behind by a dead daemon is replaced; a live one is an `AddrInUse` error.
pub async fn serve_with<S: VaultService>(
    path: impl Into<PathBuf>,
    service: Arc<S>,
    events: mpsc::Receiver<DaemonEvent>,
    options: ServeOptions,
) -> Result<ServerHandle, IpcError> {
    let path = path.into();
    prepare_directory(&path)?;
    remove_stale_socket(&path)?;
    let listener = bind(&path)?;
    let (stop, stop_rx) = watch::channel(false);
    let slot = Arc::new(Semaphore::new(1));
    let shared = Arc::new(Shared {
        service,
        events: Arc::new(Mutex::new(events)),
        verifier: options.verifier,
        uid: own_uid(),
        max_concurrent_calls: options.max_concurrent_calls.max(1),
        handshake_timeout: options.handshake_timeout,
        notices: options.notices,
        slot: Arc::clone(&slot),
    });
    let task = tokio::spawn(accept_loop(listener, shared, stop_rx));
    Ok(ServerHandle {
        path,
        stop,
        task: Some(task),
        slot,
    })
}

fn prepare_directory(path: &Path) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket path has no parent"))?;
    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir)?;
    let metadata = fs::metadata(dir)?;
    if metadata.uid() != own_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the socket directory belongs to another user",
        ));
    }
    if metadata.permissions().mode() & 0o777 != DIR_MODE {
        fs::set_permissions(dir, Permissions::from_mode(DIR_MODE))?;
    }
    Ok(())
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the socket path exists and is not a socket",
        ));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "another daemon is listening on the socket",
        )),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(path),
        Err(error) => Err(error),
    }
}

/// The 0700 directory keeps others out between `bind` and the `chmod`, so the process umask is
/// left alone.
fn bind(path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    if let Err(error) = fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE)) {
        drop(listener);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(listener)
}

async fn accept_loop<S: VaultService>(
    listener: UnixListener,
    shared: Arc<Shared<S>>,
    mut stop: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    let connection_stop = stop.clone();
    loop {
        tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            Some(joined) = connections.join_next() => log_join("IPC connection", joined),
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    connections.spawn(connection::handle(
                        stream,
                        Arc::clone(&shared),
                        connection_stop.clone(),
                    ));
                }
                Err(error) => {
                    tracing::warn!(%error, "IPC accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
        }
    }
    drop(listener);
    let drain = async {
        while let Some(joined) = connections.join_next().await {
            log_join("IPC connection", joined);
        }
    };
    if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
        tracing::debug!("IPC connections did not close in time; aborting them");
    }
}

/// Resolves once a stop is requested or the handle is gone; the watch guard does not escape.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stop| *stop).await;
}

fn log_join(what: &str, joined: Result<(), JoinError>) {
    if let Err(error) = joined
        && error.is_panic()
    {
        tracing::error!(%error, "{what} task panicked");
    }
}

/// Aborts the task when dropped, so a connection's helpers never outlive it.
struct TaskGuard<T>(JoinHandle<T>);

impl<T> Drop for TaskGuard<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
