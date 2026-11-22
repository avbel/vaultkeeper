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
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::{
    fs::{DirBuilder, Permissions},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
};

use tokio::{
    sync::{Mutex, Semaphore, mpsc, oneshot, watch},
    task::{JoinError, JoinHandle, JoinSet},
};
use vk_vault::VaultService;

#[cfg(unix)]
use crate::peer::own_uid;
use crate::{
    ClipboardHost, GeneratedHost, IpcError, PeerCredentials, PeerVerifier, SameExecutable,
    SecurityHost, SiteIconHost, TouchIdBackend,
    protocol::{BrowserPrompt, BrowserReply, SshDecision, SshPrompt, UiCommand, UiNotice},
    transport::{Endpoint, Listener, Stream},
};

#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const SOCKET_MODE: u32 = 0o600;
const DEFAULT_MAX_CALLS: usize = 8;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a graceful shutdown waits for connections to deliver `Shutdown`.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
/// Pause after a failed `accept` (e.g. out of file descriptors) so the loop does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// Connections waiting for the accept loop; one UI runs at a time, so a second means a bug.
const INHERITED_QUEUE: usize = 2;

/// What the daemon pushes to the UI process. Events wait in the channel while no UI is
/// connected and are delivered, at most once, to the next one. `seq` is the daemon's number for
/// the event, passed through to the UI (see [`crate::protocol::Event::Command`]).
#[derive(Debug)]
pub enum DaemonEvent {
    Command {
        seq: u64,
        command: UiCommand,
    },
    /// Dropping `reply`, or the UI disconnecting, counts as deny. Once `reply` is closed the UI
    /// gets [`crate::protocol::Event::Skipped`] instead of the prompt.
    SshApproval {
        seq: u64,
        prompt: SshPrompt,
        reply: oneshot::Sender<SshDecision>,
    },
    /// Tells the connected UI process to exit.
    Shutdown,
    BrowserPrompt {
        seq: u64,
        prompt: BrowserPrompt,
        reply: oneshot::Sender<BrowserReply>,
    },
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
    /// Serves `EnrollTouchId` / `UnlockWithTouchId`; without it they answer
    /// [`crate::TouchIdFailure::Unavailable`].
    pub touch_id: Option<Arc<dyn TouchIdBackend>>,
    /// Serves `CopyToClipboard` / `ClearClipboard`; without it a copy fails.
    pub clipboard: Option<Arc<dyn ClipboardHost>>,
    /// Serves `SiteIcon`; without it every host has no icon.
    pub site_icons: Option<Arc<dyn SiteIconHost>>,
    /// Serves the generated-password calls; without it the list is empty.
    pub generated: Option<Arc<dyn GeneratedHost>>,
    /// Serves `SecurityStatus`; without it the report has no chains.
    pub security: Option<Arc<dyn SecurityHost>>,
}

/// The daemon-side services a call may need besides the vault.
#[derive(Clone)]
pub(crate) struct Backends {
    pub(crate) touch_id: Option<Arc<dyn TouchIdBackend>>,
    pub(crate) clipboard: Option<Arc<dyn ClipboardHost>>,
    pub(crate) site_icons: Option<Arc<dyn SiteIconHost>>,
    pub(crate) generated: Option<Arc<dyn GeneratedHost>>,
    pub(crate) security: Option<Arc<dyn SecurityHost>>,
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
            touch_id: None,
            clipboard: None,
            site_icons: None,
            generated: None,
            security: None,
        }
    }

    #[must_use]
    pub fn with_touch_id(self, backend: Arc<dyn TouchIdBackend>) -> Self {
        Self {
            touch_id: Some(backend),
            ..self
        }
    }

    #[must_use]
    pub fn with_clipboard(self, clipboard: Arc<dyn ClipboardHost>) -> Self {
        Self {
            clipboard: Some(clipboard),
            ..self
        }
    }

    #[must_use]
    pub fn with_security(self, security: Arc<dyn SecurityHost>) -> Self {
        Self {
            security: Some(security),
            ..self
        }
    }

    #[must_use]
    pub fn with_site_icons(self, site_icons: Arc<dyn SiteIconHost>) -> Self {
        Self {
            site_icons: Some(site_icons),
            ..self
        }
    }

    #[must_use]
    pub fn with_generated(self, generated: Arc<dyn GeneratedHost>) -> Self {
        Self {
            generated: Some(generated),
            ..self
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
    /// `None` when connections are handed in with [`UiSink::offer`] instead of accepted.
    endpoint: Option<Endpoint>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    slot: Arc<Semaphore>,
}

impl ServerHandle {
    /// The socket path on Unix.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.endpoint
            .as_ref()
            .and_then(Endpoint::as_path)
            .expect("only a server bound to a socket path has one")
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
        if let Some(path) = self.endpoint.as_ref().and_then(Endpoint::as_path)
            && let Err(error) = fs::remove_file(path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, path = %path.display(), "cannot remove the IPC socket");
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
    backends: Backends,
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
    let endpoint = Endpoint::path(path.into());
    #[cfg(unix)]
    {
        let path = endpoint
            .as_path()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "a path is required"))?;
        prepare_directory(path)?;
        remove_stale_socket(path)?;
    }
    let listener = bind_endpoint(&endpoint)?;
    Ok(start(
        Incoming::Listener(listener),
        Some(endpoint),
        service,
        events,
        options,
    ))
}

/// Hands in connections instead of accepting them: the Windows and Linux daemons create the UI's
/// channel themselves (a pipe, a socket pair) and give its server end to [`UiSink::offer`], so
/// there is no name to listen on and no peer to check (`docs/solutions/windows-support.md` §5.2,
/// linux-plan.md 2d).
pub fn serve_inherited<S: VaultService>(
    service: Arc<S>,
    events: mpsc::Receiver<DaemonEvent>,
    options: ServeOptions,
) -> (ServerHandle, UiSink) {
    let (sink, streams) = mpsc::channel(INHERITED_QUEUE);
    let handle = start(Incoming::Injected(streams), None, service, events, options);
    (handle, UiSink(sink))
}

/// Where the code that spawns the UI process delivers its end of the channel.
#[derive(Clone)]
pub struct UiSink(mpsc::Sender<Stream>);

impl UiSink {
    /// A sink whose streams arrive on the returned receiver, for callers that run their own
    /// accept loop (and tests that only spawn processes).
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<Stream>) {
        let (sink, streams) = mpsc::channel(capacity);
        (Self(sink), streams)
    }

    /// Serves `stream` as a UI connection. Its owner vouches for the peer, so the verifier is
    /// not asked.
    pub fn offer(&self, stream: Stream) -> Result<(), IpcError> {
        self.0.try_send(stream).map_err(|_| IpcError::Disconnected)
    }
}

/// Where the accept loop gets its connections from.
enum Incoming {
    Listener(Listener),
    Injected(mpsc::Receiver<Stream>),
}

impl Incoming {
    /// A connection and, when it came from a listener, the credentials of its peer.
    async fn next(&mut self) -> io::Result<(Stream, Option<PeerCredentials>)> {
        match self {
            Self::Listener(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok((stream, Some(peer)))
            }
            Self::Injected(streams) => match streams.recv().await {
                Some(stream) => Ok((stream, None)),
                None => std::future::pending().await,
            },
        }
    }
}

fn start<S: VaultService>(
    incoming: Incoming,
    endpoint: Option<Endpoint>,
    service: Arc<S>,
    events: mpsc::Receiver<DaemonEvent>,
    options: ServeOptions,
) -> ServerHandle {
    let (stop, stop_rx) = watch::channel(false);
    let slot = Arc::new(Semaphore::new(1));
    let shared = Arc::new(Shared {
        service,
        events: Arc::new(Mutex::new(events)),
        verifier: options.verifier,
        #[cfg(unix)]
        uid: own_uid(),
        #[cfg(not(unix))]
        uid: 0,
        max_concurrent_calls: options.max_concurrent_calls.max(1),
        handshake_timeout: options.handshake_timeout,
        notices: options.notices,
        backends: Backends {
            touch_id: options.touch_id,
            clipboard: options.clipboard,
            site_icons: options.site_icons,
            generated: options.generated,
            security: options.security,
        },
        slot: Arc::clone(&slot),
    });
    let task = tokio::spawn(accept_loop(incoming, shared, stop_rx));
    ServerHandle {
        endpoint,
        stop,
        task: Some(task),
        slot,
    }
}

#[cfg(unix)]
pub(crate) fn prepare_directory(path: &Path) -> io::Result<()> {
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

#[cfg(unix)]
pub(crate) fn remove_stale_socket(path: &Path) -> io::Result<()> {
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

/// Prepares whatever the transport needs before a bind: on Unix the private directory and the
/// removal of a socket left behind by a dead daemon.
#[cfg_attr(
    not(unix),
    allow(clippy::unnecessary_wraps, reason = "Unix can fail here")
)]
pub(crate) fn prepare_endpoint(endpoint: &Endpoint) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(path) = endpoint.as_path() {
        prepare_directory(path)?;
        remove_stale_socket(path)?;
    }
    #[cfg(not(unix))]
    let _ = endpoint;
    Ok(())
}

/// Binds the UI's transport endpoint; on Unix that is a socket with mode 0600.
pub(crate) fn bind_endpoint(endpoint: &Endpoint) -> io::Result<Listener> {
    let listener = Listener::bind(endpoint)?;
    #[cfg(unix)]
    if let Some(path) = endpoint.as_path()
        && let Err(error) = fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE))
    {
        drop(listener);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(listener)
}

async fn accept_loop<S: VaultService>(
    mut incoming: Incoming,
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
            accepted = incoming.next() => match accepted {
                Ok((stream, peer)) => {
                    connections.spawn(connection::handle(
                        stream,
                        peer,
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
    drop(incoming);
    let drain = async {
        while let Some(joined) = connections.join_next().await {
            log_join("IPC connection", joined);
        }
    };
    if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
        tracing::debug!("IPC connections did not close in time; aborting them");
    }
}

/// Resolves once a stop is requested; the watch guard does not escape. A dropped handle is not
/// a stop request: its drop aborts the tasks, and a connection that outran the abort must not
/// send `Shutdown` into a socket that is being torn down.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    if stop.wait_for(|stop| *stop).await.is_err() {
        std::future::pending::<()>().await;
    }
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
