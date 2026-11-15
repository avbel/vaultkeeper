//! Named pipes behind the transport seam.
//!
//! The final pipe DACL withholds `FILE_CREATE_PIPE_INSTANCE` from every principal, our own user
//! included, so no same-user process can add an instance and steal the next client
//! (`docs/solutions/windows-support.md` §5.3). The listener therefore builds the whole pool while
//! creating the first instance and recycles an instance after its client disconnects.

use std::{
    io,
    os::windows::io::{AsRawHandle as _, RawHandle},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf as TokioReadHalf, WriteHalf as TokioWriteHalf},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
    sync::Notify,
    time::Sleep,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY},
    Security::{DACL_SECURITY_INFORMATION, SetKernelObjectSecurity},
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
/// How long a client waits through a busy pipe (all pooled instances taken) before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// A named-pipe listener backed by a fixed pool of instances.
pub struct Listener {
    pool: Arc<Pool>,
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
        let strict = vk_win::sddl::pipe(&sid)?;
        let servers = match create_instances(name, &strict, false) {
            Ok(servers) => {
                tracing::debug!(pipe = name, "created the IPC pipe pool with its final DACL");
                servers
            }
            Err(error) if is_access_denied(&error) => {
                // The final DACL denies FILE_CREATE_PIPE_INSTANCE to us too, so the remaining
                // instances can only be made from a DACL that grants it; lock each one down after.
                let builder = vk_win::sddl::pipe_pool_builder(&sid)?;
                let servers = create_instances(name, &builder, true).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("cannot build the IPC pipe pool for {name}: {error}"),
                    )
                })?;
                tighten(&servers, &strict)?;
                tracing::debug!(
                    pipe = name,
                    "created the IPC pipe pool, then locked it down"
                );
                servers
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            pool: Arc::new(Pool::new(name, servers)),
        })
    }

    /// Accepts a connection from any free instance, with the pid of the process behind it.
    pub async fn accept(&self) -> io::Result<(Stream, PeerCredentials)> {
        let mut slot = self.pool.acquire().await;
        slot.connect().await?;
        let peer = slot.peer()?;
        Ok((slot.into_stream(), peer))
    }
}

/// Creates the pool. The first instance sets `FILE_FLAG_FIRST_PIPE_INSTANCE`, which is what turns a
/// squatted name into an error instead of silently attaching to another program's pipe.
fn create_instances(name: &str, sddl: &str, write_dac: bool) -> io::Result<Vec<NamedPipeServer>> {
    let descriptor = vk_win::SecurityDescriptor::from_sddl(sddl)?;
    let mut attributes = descriptor.as_attributes(false);
    let mut servers = Vec::with_capacity(POOL_SIZE);
    for index in 0..POOL_SIZE {
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(index == 0)
            .reject_remote_clients(true)
            .write_dac(write_dac);
        // SAFETY: `attributes` is a live, initialised SECURITY_ATTRIBUTES whose descriptor is
        // `descriptor`; both outlive every call in the loop.
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
            Err(error) => return Err(error),
        }
    }
    Ok(servers)
}

/// Replaces the DACL of every pooled instance with the strict one. Each instance keeps its own
/// descriptor, so tightening one says nothing about the others.
fn tighten(servers: &[NamedPipeServer], strict_sddl: &str) -> io::Result<()> {
    let descriptor = vk_win::SecurityDescriptor::from_sddl(strict_sddl)?;
    for server in servers {
        // SAFETY: the instance handle is live, was opened with WRITE_DAC (see the `write_dac`
        // argument above), and `descriptor` outlives the call.
        let applied = unsafe {
            SetKernelObjectSecurity(
                server.as_raw_handle(),
                DACL_SECURITY_INFORMATION,
                descriptor.as_ptr(),
            )
        };
        if applied == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn is_access_denied(error: &io::Error) -> bool {
    error.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok()
}

/// The instances not currently serving a client, plus a wake-up for acceptors waiting on one.
struct Pool {
    /// Only used to name the pipe in log lines about a lost instance.
    name: String,
    slots: Mutex<Vec<NamedPipeServer>>,
    free: Notify,
}

impl Pool {
    fn new(name: &str, servers: Vec<NamedPipeServer>) -> Self {
        Self {
            name: name.to_owned(),
            slots: Mutex::new(servers),
            free: Notify::new(),
        }
    }

    async fn acquire(self: &Arc<Self>) -> Slot {
        loop {
            let available = self
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop();
            if let Some(server) = available {
                return Slot {
                    server: Some(server),
                    connected: false,
                    pool: Arc::clone(self),
                };
            }
            self.free.notified().await;
        }
    }

    fn release(&self, server: NamedPipeServer) {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(server);
        self.free.notify_one();
    }
}

/// An instance taken from the pool while it waits for a client. Returning it on drop covers a
/// cancelled accept: `connect` is cancel safe, so an unfinished wait can be resumed later.
struct Slot {
    server: Option<NamedPipeServer>,
    connected: bool,
    pool: Arc<Pool>,
}

impl Slot {
    async fn connect(&mut self) -> io::Result<()> {
        if let Some(server) = &self.server {
            server.connect().await?;
            self.connected = true;
        }
        Ok(())
    }

    fn peer(&self) -> io::Result<PeerCredentials> {
        let Some(server) = &self.server else {
            return Err(io::Error::other("the pipe instance was taken"));
        };
        credentials(server.as_raw_handle(), false)
    }

    fn into_stream(mut self) -> Stream {
        Stream {
            inner: self.server.take().map(Inner::Server),
            recycle: Some(Arc::clone(&self.pool)),
            silence: Some(Box::pin(tokio::time::sleep(SILENCE_TIMEOUT))),
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let Some(server) = self.server.take() else {
            return;
        };
        if self.connected && server.disconnect().is_err() {
            tracing::warn!(pipe = %self.pool.name, "cannot recycle a named pipe instance");
            return;
        }
        self.pool.release(server);
    }
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
        // Disconnect frees this instance for the next client; the handle itself must be reused,
        // since the DACL denies creating a replacement.
        if server.disconnect().is_err() {
            tracing::warn!(pipe = %pool.name, "cannot recycle a named pipe instance");
            return;
        }
        pool.release(server);
    }
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
    let client = open(name)?;
    verify_server(&client)?;
    Ok(Stream::client(client))
}

/// Opens a client handle, waiting through the brief window where every pooled instance is taken.
fn open(name: &str) -> io::Result<NamedPipeClient> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match ClientOptions::new().open(name) {
            Ok(client) => return Ok(client),
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

fn is_pipe_busy(error: &io::Error) -> bool {
    error.raw_os_error() == i32::try_from(ERROR_PIPE_BUSY).ok()
}
