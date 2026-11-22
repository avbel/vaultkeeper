//! Named pipes behind the transport seam.
//!
//! The final pipe DACL withholds `FILE_CREATE_PIPE_INSTANCE` from every principal, our own user
//! included, so no same-user process can add an instance and steal the next client
//! (`docs/solutions/windows-support.md` §5.3). The listener therefore creates the whole pool from
//! a setup DACL that still allows it, applies the final DACL to every instance, and recycles an
//! instance after its client disconnects.

use std::{
    io,
    os::windows::io::{AsRawHandle as _, IntoRawHandle as _, OwnedHandle, RawHandle},
    path::PathBuf,
    pin::{Pin, pin},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::{
    io::{
        AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf, ReadHalf as TokioReadHalf,
        WriteHalf as TokioWriteHalf,
    },
    net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions},
    runtime::{Handle, RuntimeFlavor},
    sync::{Mutex as AsyncMutex, mpsc},
    task::JoinSet,
    time::Sleep,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY},
    System::Pipes::{
        GetNamedPipeClientProcessId, GetNamedPipeClientSessionId, GetNamedPipeServerProcessId,
        GetNamedPipeServerSessionId, WaitNamedPipeW,
    },
};

use super::Endpoint;
use crate::peer::PeerCredentials;

/// Instances created at bind: enough for the CLI and browser clients to overlap. The DACL denies
/// creating more later, so this number is the ceiling for concurrent clients.
const POOL_SIZE: usize = 4;
/// A client that connects and never sends its hello must not hold a pool instance forever.
const SILENCE_TIMEOUT: Duration = Duration::from_secs(30);
/// Pause before re-arming an instance whose connect failed.
const RETRY_DELAY: Duration = Duration::from_millis(50);
/// How long a client waits through a busy pipe (all pooled instances taken) before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a finished connection waits for its client to close before the instance is recycled.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounds each step of clearing an instance's stale I/O state; they normally finish in microseconds
/// because every operation on a disconnected pipe fails at once.
const RESET_TIMEOUT: Duration = Duration::from_secs(1);
/// Resets tried (with a doubling pause) before an instance is given up as lost.
const RESET_ATTEMPTS: u32 = 4;
/// How long `bind` waits for a previous listener's aborted instances to close before it reports the
/// name as taken.
const REBIND_WINDOW: Duration = Duration::from_millis(500);
const REBIND_PAUSE: Duration = Duration::from_millis(20);

/// A named-pipe listener backed by a fixed pool of instances.
pub struct Listener {
    pool: Arc<Pool>,
    /// An async mutex so concurrent `accept` calls queue instead of needing `&mut self`.
    connected: AsyncMutex<mpsc::UnboundedReceiver<Ready>>,
}

impl Listener {
    pub fn bind(endpoint: &Endpoint) -> io::Result<Self> {
        let Some(name) = endpoint.as_pipe() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a named pipe listener cannot bind a socket path",
            ));
        };
        let sid = vk_win::current_user_sid()?;
        let servers = create_instances_when_free(name, &sid)?;
        tracing::debug!(pipe = name, "created the IPC pipe pool with its final DACL");
        let (pool, connected) = Pool::new(name, Handle::try_current().map_err(io::Error::other)?);
        for server in servers {
            pool.arm(server);
        }
        Ok(Self {
            pool,
            connected: AsyncMutex::new(connected),
        })
    }

    /// Accepts a connection from any free instance, with the pid of the process behind it.
    pub async fn accept(&self) -> io::Result<(Stream, PeerCredentials)> {
        let mut connected = self.connected.lock().await;
        if self.pool.live.load(Ordering::Acquire) == 0 {
            return Err(pool_exhausted());
        }
        // `recv` is cancel safe: an instance that connected while nobody was accepting stays queued.
        let Some(Some(server)) = connected.recv().await else {
            return Err(pool_exhausted());
        };
        drop(connected);
        // Wrapped before anything can fail, so an error below recycles the instance on drop.
        let stream = Stream {
            inner: Some(Inner::Server(server)),
            recycle: Some(Arc::clone(&self.pool)),
            silence: Some(Box::pin(tokio::time::sleep(SILENCE_TIMEOUT))),
        };
        let peer = stream.peer_credentials()?;
        Ok((stream, peer))
    }

    /// Stops the pool and waits until every idle instance handle is closed, so the same name can
    /// be bound again right away. Instances held by live connections close when those end.
    pub async fn shutdown(mut self) {
        let mut tasks = self.close();
        while tasks.join_next().await.is_some() {}
    }

    fn close(&mut self) -> JoinSet<()> {
        let tasks = self.pool.shutdown();
        let connected = self.connected.get_mut();
        connected.close();
        while connected.try_recv().is_ok() {}
        tasks
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        drop(self.close());
    }
}

fn pool_exhausted() -> io::Error {
    io::Error::other("every pipe instance was lost; the pipe cannot serve clients any more")
}

/// A just-dropped listener's aborted tasks release their handles on the runtime a moment later,
/// during which the name still looks taken; only a name that stays taken is a squatter.
fn create_instances_when_free(name: &str, sid: &str) -> io::Result<Vec<NamedPipeServer>> {
    let deadline = Instant::now() + REBIND_WINDOW;
    loop {
        match create_instances(name, sid) {
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied && Instant::now() < deadline =>
            {
                pause_before_rebind();
            }
            result => return result,
        }
    }
}

/// `bind` is synchronous but runs inside the runtime; on a multi-thread runtime the worker's
/// other tasks move elsewhere while it sleeps.
fn pause_before_rebind() {
    let pause = || std::thread::sleep(REBIND_PAUSE);
    match Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(pause),
        _ => pause(),
    }
}

/// Creates the pool, then locks every instance down to the final DACL. The first instance sets
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`, which is what turns a squatted name into an error instead of
/// silently attaching to another program's pipe.
///
/// Every instance is created from the setup DACL with WRITE_DAC: the final one withholds
/// FILE_CREATE_PIPE_INSTANCE from us too, so it can only be applied once the pool is complete.
fn create_instances(name: &str, sid: &str) -> io::Result<Vec<NamedPipeServer>> {
    let setup = vk_win::SecurityDescriptor::from_sddl(&vk_win::sddl::pipe_setup(sid)?)?;
    let mut attributes = setup.as_attributes(false);
    let mut servers = Vec::with_capacity(POOL_SIZE);
    for index in 0..POOL_SIZE {
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(index == 0)
            .reject_remote_clients(true)
            .write_dac(true);
        // SAFETY: `attributes` is a live, initialised SECURITY_ATTRIBUTES whose descriptor is
        // `setup`; both outlive every call in the loop.
        let created = unsafe {
            options.create_with_security_attributes_raw(name, (&raw mut attributes).cast())
        };
        match created {
            Ok(server) => servers.push(server),
            Err(error) if index == 0 && is_access_denied(&error) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("another program is serving the Vaultkeeper pipe {name}"),
                ));
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("cannot build the IPC pipe pool for {name}: {error}"),
                ));
            }
        }
    }
    let fin = vk_win::SecurityDescriptor::from_sddl(&vk_win::sddl::pipe(sid)?)?;
    for server in &servers {
        // The descriptor may be shared between instances; applying it to each is harmless then.
        fin.apply_dacl(server)?;
    }
    Ok(servers)
}

fn is_access_denied(error: &io::Error) -> bool {
    error.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok()
}

/// Re-arms instances: each idle one waits for a client in its own task, because Windows hands a
/// connecting client to any listening instance, not to one we picked.
struct Pool {
    /// Only used to name the pipe in log lines about a lost instance.
    name: String,
    handle: Handle,
    /// `None` is the wake-up sent when the last instance is lost, so a pending `accept` can fail.
    ready: mpsc::UnboundedSender<Ready>,
    /// Instances not lost yet, idle or in use. The DACL forbids creating replacements.
    live: AtomicUsize,
    /// Every task that owns an instance (waiting or recycling), so shutdown reaches all of them.
    /// `None` once the listener is gone, so late recycles drop their instance instead of arming it.
    tasks: Mutex<Option<JoinSet<()>>>,
}

/// A connected instance, or the signal that the pool is empty.
type Ready = Option<NamedPipeServer>;

impl Pool {
    fn new(name: &str, handle: Handle) -> (Arc<Self>, mpsc::UnboundedReceiver<Ready>) {
        let (ready, connected) = mpsc::unbounded_channel();
        let pool = Arc::new(Self {
            name: name.to_owned(),
            handle,
            ready,
            live: AtomicUsize::new(POOL_SIZE),
            tasks: Mutex::new(Some(JoinSet::new())),
        });
        (pool, connected)
    }

    fn arm(self: &Arc<Self>, server: NamedPipeServer) {
        self.spawn(|pool| wait_for_client(server, pool));
    }

    /// Drains a finished connection's instance and re-arms it, as a tracked task.
    fn recycle(self: &Arc<Self>, server: NamedPipeServer) {
        self.spawn(|pool| recycle_instance(server, pool));
    }

    fn spawn<F: Future<Output = ()> + Send + 'static>(
        self: &Arc<Self>,
        task: impl FnOnce(Arc<Self>) -> F,
    ) {
        let mut guard = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(tasks) = guard.as_mut() else {
            return;
        };
        while tasks.try_join_next().is_some() {}
        tasks.spawn_on(task(Arc::clone(self)), &self.handle);
    }

    /// Aborts every owning task, which drops their instances and releases the pipe; the caller can
    /// await the returned set to know the handles are closed.
    fn shutdown(&self) -> JoinSet<()> {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .unwrap_or_default();
        tasks.abort_all();
        tasks
    }

    /// Gives up an instance that cannot be reset. The pool does not refill, so the last loss makes
    /// `accept` fail instead of waiting for a client nobody can serve.
    fn lose(&self, error: &io::Error) {
        let remaining = self.live.fetch_sub(1, Ordering::AcqRel).saturating_sub(1);
        tracing::error!(pipe = %self.name, %error, remaining, "lost a named pipe instance");
        if remaining == 0 {
            let _ = self.ready.send(None);
        }
    }
}

/// A failed connect (a client that vanished early) must not shrink the fixed pool, so the instance
/// is reset and armed again after a pause that keeps a persistent error from spinning.
async fn wait_for_client(mut server: NamedPipeServer, pool: Arc<Pool>) {
    loop {
        match server.connect().await {
            Ok(()) => {
                let _ = pool.ready.send(Some(server));
                return;
            }
            Err(error) => {
                tracing::debug!(pipe = %pool.name, %error, "a named pipe connect failed; re-arming the instance");
                tokio::time::sleep(RETRY_DELAY).await;
                if let Err(error) = reset_with_retry(&mut server).await {
                    pool.lose(&error);
                    return;
                }
            }
        }
    }
}

/// A reset can fail transiently (a client mid-teardown); losing the instance is permanent, so
/// retry with a growing pause first.
async fn reset_with_retry(server: &mut NamedPipeServer) -> io::Result<()> {
    let mut pause = RETRY_DELAY;
    let mut attempt = 1;
    loop {
        match reset_instance(server).await {
            Err(error) if attempt < RESET_ATTEMPTS => {
                tracing::debug!(%error, attempt, "resetting a named pipe instance failed; retrying");
                tokio::time::sleep(pause).await;
                pause *= 2;
                attempt += 1;
            }
            result => return result,
        }
    }
}

/// Detaches the instance from its previous client and clears the I/O state that tokio's pipe keeps
/// across `disconnect`, then issues the `ConnectNamedPipe` for the next client.
///
/// mio drives a `NamedPipeServer` with one overlapped read slot that it refills on its own: when
/// the client closes, or `DisconnectNamedPipe` cancels an in-flight read, the slot ends up holding
/// that error, `disconnect` leaves it there, and after the next connect mio skips scheduling a read
/// because the slot is not empty. The first read of the next client would then receive the previous
/// client's `ERROR_BROKEN_PIPE` (an early EOF) or `ERROR_PIPE_NOT_CONNECTED`. The write slot keeps
/// a failed or cancelled write's error the same way. The slot only empties when a read is refused
/// with `ERROR_PIPE_LISTENING`, so the stale error is consumed after `ConnectNamedPipe` was issued
/// but, because mio hands out the slot before refilling it, before any data of the new client can
/// land in it.
///
/// Rewrapping a `DuplicateHandle` of the instance in a fresh `NamedPipeServer` would avoid relying
/// on mio's slots, but cannot work: the completion-port association lives on the kernel file
/// object, which the duplicate shares, so registering it again fails with `ERROR_INVALID_PARAMETER`
/// (a file object joins one port until it is destroyed). The slot behaviour relied on here has been
/// unchanged since mio took the pipe code over from `mio-named-pipes`.
async fn reset_instance(server: &mut NamedPipeServer) -> io::Result<()> {
    server.disconnect()?;
    flush_stale_write(server).await;
    if !settle_reads(server).await {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "a disconnected pipe instance kept a read in flight",
        ));
    }
    issue_connect(server).await?;
    if !flush_stale_read(server).await {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "a re-armed pipe instance did not surface its stale read error",
        ));
    }
    Ok(())
}

/// With the pipe disconnected an empty write reaches no client: it either returns the stale error
/// or is refused by the pipe without touching the slot, so the slot is clean either way.
async fn flush_stale_write(server: &NamedPipeServer) {
    let flush = async {
        loop {
            if server.writable().await.is_err() {
                return;
            }
            if !matches!(server.try_write(&[]), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            {
                return;
            }
        }
    };
    let _ = tokio::time::timeout(RESET_TIMEOUT, flush).await;
}

/// Reads until the slot holds an error. Every read on a disconnected pipe is refused with
/// `ERROR_PIPE_NOT_CONNECTED`, and `DisconnectNamedPipe` completes an in-flight read with the same
/// error, so this ends with exactly one stale error in the slot; data still buffered from the old
/// client is discarded on the way. Returns `false` if the pipe never settled.
async fn settle_reads(server: &mut NamedPipeServer) -> bool {
    let mut sink = [0_u8; 64];
    let settled = async { while server.read(&mut sink).await.is_ok() {} };
    tokio::time::timeout(RESET_TIMEOUT, settled).await.is_ok()
}

/// Polls `connect` once so `ConnectNamedPipe` is in flight, without waiting for a client. mio keeps
/// the pending connect across the dropped future, and a later `connect` resumes waiting on it.
async fn issue_connect(server: &NamedPipeServer) -> io::Result<()> {
    let mut connect = pin!(server.connect());
    match std::future::poll_fn(|context| Poll::Ready(connect.as_mut().poll(context))).await {
        Poll::Ready(Err(error)) => Err(error),
        Poll::Ready(Ok(())) | Poll::Pending => Ok(()),
    }
}

/// Consumes the one stale error left by `settle_reads`, which lets mio schedule a fresh read for
/// the next client. Returns `false` if nothing surfaced in time.
async fn flush_stale_read(server: &mut NamedPipeServer) -> bool {
    let mut sink = [0_u8; 64];
    tokio::time::timeout(RESET_TIMEOUT, server.read(&mut sink))
        .await
        .is_ok()
}

/// Either end of a named pipe: an accepted server instance, or a client we connected.
enum Inner {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

/// A connected named pipe.
pub struct Stream {
    /// `None` only while `Drop` moves the instance back to the pool.
    inner: Option<Inner>,
    /// Present on an accepted connection: the instance belongs to this pool.
    recycle: Option<Arc<Pool>>,
    /// Sender silence budget, cleared by the first byte the client sends.
    silence: Option<Pin<Box<Sleep>>>,
}

impl Stream {
    #[must_use]
    pub fn into_split(self) -> (ReadHalf, WriteHalf) {
        tokio::io::split(self)
    }

    /// A client pipe: no pool to recycle and no idle-timeout budget.
    pub(super) fn client(client: NamedPipeClient) -> Self {
        Self {
            inner: Some(Inner::Client(client)),
            recycle: None,
            silence: None,
        }
    }

    /// A server instance that is not part of a pool, with no silence budget: its client is the
    /// UI process the daemon just spawned.
    pub(super) fn server(server: NamedPipeServer) -> Self {
        Self {
            inner: Some(Inner::Server(server)),
            recycle: None,
            silence: None,
        }
    }

    /// The credentials of the process on the other end: the server for a client pipe, the client
    /// for an accepted instance.
    pub fn peer_credentials(&self) -> io::Result<PeerCredentials> {
        match self.inner.as_ref() {
            Some(Inner::Server(server)) => credentials(server.as_raw_handle(), false),
            Some(Inner::Client(client)) => credentials(client.as_raw_handle(), true),
            None => Err(io::Error::other(
                "the pipe is taken only while the stream drops",
            )),
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let Some(pool) = self.recycle.take() else {
            return;
        };
        let Some(inner) = self.inner.take() else {
            return;
        };
        let Inner::Server(server) = inner else {
            return;
        };
        pool.recycle(server);
    }
}

/// Disconnect frees the instance for the next client; the handle itself must be reused, since the
/// DACL denies creating a replacement.
///
/// DisconnectNamedPipe discards whatever the client has not read yet, so a reply written just
/// before the drop would be lost. FlushFileBuffers would wait for the client to read it, but it
/// blocks a thread and cannot be cancelled. Waiting for the client to close its end instead means
/// it has read everything it wanted, costs no thread, and the timeout bounds a client that never
/// closes.
async fn recycle_instance(mut server: NamedPipeServer, pool: Arc<Pool>) {
    wait_for_client_close(&mut server).await;
    if let Err(error) = reset_with_retry(&mut server).await {
        pool.lose(&error);
        return;
    }
    pool.arm(server);
}

/// Reads and discards until the client closes its end (EOF or a broken pipe) or the budget runs out.
async fn wait_for_client_close(server: &mut NamedPipeServer) {
    let mut sink = [0_u8; 256];
    let closed = async {
        loop {
            match server.read(&mut sink).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    };
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, closed).await;
}

/// The read end of a [`Stream`], owned so it can move to its own task.
pub type ReadHalf = TokioReadHalf<Stream>;
/// The write end of a [`Stream`], owned so it can move to its own task.
pub type WriteHalf = TokioWriteHalf<Stream>;

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(deadline) = this.silence.as_mut()
            && deadline.as_mut().poll(context).is_ready()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the IPC client sent nothing for 30 s",
            )));
        }
        let filled = buffer.filled().len();
        let polled = match this
            .inner
            .as_mut()
            .expect("the pipe is taken only while the stream drops")
        {
            Inner::Server(server) => Pin::new(server).poll_read(context, buffer),
            Inner::Client(client) => Pin::new(client).poll_read(context, buffer),
        };
        // Only the first byte is on a timer: a CLI waiting for the user to approve a prompt may
        // legitimately stay quiet for a long time after its hello.
        if matches!(polled, Poll::Ready(Ok(()))) && buffer.filled().len() > filled {
            this.silence = None;
        }
        polled
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match this
            .inner
            .as_mut()
            .expect("the pipe is taken only while the stream drops")
        {
            Inner::Server(server) => Pin::new(server).poll_write(context, buffer),
            Inner::Client(client) => Pin::new(client).poll_write(context, buffer),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this
            .inner
            .as_mut()
            .expect("the pipe is taken only while the stream drops")
        {
            Inner::Server(server) => Pin::new(server).poll_flush(context),
            Inner::Client(client) => Pin::new(client).poll_flush(context),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this
            .inner
            .as_mut()
            .expect("the pipe is taken only while the stream drops")
        {
            Inner::Server(server) => Pin::new(server).poll_shutdown(context),
            Inner::Client(client) => Pin::new(client).poll_shutdown(context),
        }
    }
}

/// Connects to a pipe name and verifies the server is this same executable in this same session.
pub async fn connect(endpoint: &Endpoint) -> io::Result<Stream> {
    let Some(name) = endpoint.as_pipe() else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a named pipe client cannot connect to a socket path",
        ));
    };
    let name = name.to_owned();
    // `WaitNamedPipeW` blocks for up to CONNECT_TIMEOUT; off the runtime, so an enclosing
    // tokio timeout can still fire.
    let handle = tokio::task::spawn_blocking(move || open(&name))
        .await
        .map_err(io::Error::other)??;
    // SAFETY: the handle is a fresh overlapped pipe client handle that we own; tokio takes over
    // closing it.
    let client = unsafe { NamedPipeClient::from_raw_handle(handle.into_raw_handle()) }?;
    verify_server(&client)?;
    Ok(Stream::client(client))
}

/// Opens a client handle, waiting through the brief window where every pooled instance is taken.
/// Not tokio's `ClientOptions`: its GENERIC_WRITE includes FILE_CREATE_PIPE_INSTANCE, which the
/// final DACL withholds.
fn open(name: &str) -> io::Result<OwnedHandle> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match vk_win::open_pipe_client(name, true) {
            Ok(handle) => return Ok(handle),
            Err(error) if is_pipe_busy(&error) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(error);
                }
                let wait_ms = u32::try_from(remaining.as_millis().max(1))
                    .expect("the remaining wait fits a u32");
                // SAFETY: `wide` is NUL-terminated and lives for the whole call.
                if unsafe { WaitNamedPipeW(wide.as_ptr(), wait_ms) } == 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// Refuses a server that is not this exact executable in this session. The pipe name is
/// SID-scoped, so a mismatch means a same-user process squatted the name or the daemon is stale.
fn verify_server(client: &NamedPipeClient) -> io::Result<()> {
    let mut server_pid = 0_u32;
    // SAFETY: the client handle is live and connected; `server_pid` is ours.
    if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &raw mut server_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let own = vk_win::ImageIdentity::of_current_exe()?;
    let server = vk_win::ImageIdentity::of_pid(server_pid)?;
    let same_session = vk_win::process_session_id(server_pid)? == vk_win::current_session_id()?;
    if server == own && same_session {
        return Ok(());
    }
    // The image path only picks the message: a stale build of our own binary is worth a restart
    // hint, anything else is refused outright.
    let same_path = match (
        vk_win::image_path_of_pid(server_pid),
        std::env::current_exe(),
    ) {
        (Ok(server_path), Ok(own_path)) => server_path == own_path,
        _ => false,
    };
    Err(if same_path {
        io::Error::other("Vaultkeeper was updated; restart it")
    } else {
        io::Error::other("another program is serving Vaultkeeper's pipe")
    })
}

/// Reads the peer's pid and session off a connected pipe handle. `peer_is_server` names which side
/// the handle we hold is on, so the peer is the other one.
pub(super) fn credentials(handle: RawHandle, peer_is_server: bool) -> io::Result<PeerCredentials> {
    let mut pid = 0_u32;
    let mut session = 0_u32;
    // SAFETY: the handle is live and connected; both out pointers are ours.
    let (pid_ok, session_ok) = if peer_is_server {
        (
            unsafe { GetNamedPipeServerProcessId(handle, &raw mut pid) },
            unsafe { GetNamedPipeServerSessionId(handle, &raw mut session) },
        )
    } else {
        (
            unsafe { GetNamedPipeClientProcessId(handle, &raw mut pid) },
            unsafe { GetNamedPipeClientSessionId(handle, &raw mut session) },
        )
    };
    if pid_ok == 0 || session_ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        uid: 0,
        pid: i32::try_from(pid)
            .map_err(|_| io::Error::other("the IPC peer pid does not fit an i32"))?,
        executable: PathBuf::new(),
        audit_token: None,
        session_id: session,
    })
}

pub(super) fn is_pipe_busy(error: &io::Error) -> bool {
    error.raw_os_error() == i32::try_from(ERROR_PIPE_BUSY).ok()
}
