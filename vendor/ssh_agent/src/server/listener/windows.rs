//! Windows named pipe listener for the SSH agent server
//!
//! vk patch: the pipe ends up with an explicit DACL that withholds
//! `FILE_CREATE_PIPE_INSTANCE` from everyone, so no same-user process can add an instance and
//! steal the next client. The listener therefore builds a fixed pool of instances up front (from
//! a setup DACL that still allows it), applies the final DACL to each and recycles them after
//! their client disconnects (same approach as `vk-ipc`'s transport).

use std::{
    future::Future as _,
    io,
    os::windows::io::AsRawHandle,
    pin::{pin, Pin},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, PoisonError,
    },
    task::{Context, Poll},
};

use anyhow::{anyhow, Result};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    runtime::{Handle, RuntimeFlavor},
    sync::mpsc,
    task::JoinSet,
};
use tracing::{info, warn};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle, LocalFree, ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, HANDLE, HLOCAL,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            },
            GetTokenInformation, SetKernelObjectSecurity, TokenUser, DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            Pipes::GetNamedPipeClientProcessId,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    },
};

use super::{Listener, ListenerExhausted};
use crate::server::{connection::Connection, peer_info::PeerInfo};

/// The fixed named pipe path that OpenSSH clients expect on Windows
const PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

/// The DACL denies creating more instances later, so this is the ceiling for concurrent clients.
const POOL_SIZE: usize = 4;

/// Pause before re-arming an instance whose connect failed.
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// How long a finished connection waits for its client to close before the instance is recycled.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Resets tried (with a doubling pause) before an instance is given up as lost.
const RESET_ATTEMPTS: u32 = 4;

/// How long a bind waits for a previous listener's aborted instances to close before it reports
/// the name as taken.
const REBIND_WINDOW: std::time::Duration = std::time::Duration::from_millis(500);

/// Pause between bind attempts inside `REBIND_WINDOW`.
const REBIND_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// Bounds each step of clearing an instance's stale I/O state; they normally finish in microseconds
/// because every operation on a disconnected pipe fails at once.
const RESET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

const SDDL_REVISION_1: u32 = 1;

/// Another program already owns the pipe name; the Windows OpenSSH agent service is the usual one.
/// Callers recover it with `downcast_ref` to tell it from other bind failures.
#[derive(Debug, thiserror::Error)]
#[error("another program already owns the named pipe {name}")]
pub struct PipeNameTaken {
    pub name: String,
}

/// Windows named pipe listener for the SSH agent server
pub(crate) struct WindowsListener {
    pool: Arc<Pool>,
    connected: mpsc::UnboundedReceiver<Ready>,
}

impl WindowsListener {
    /// Creates a new [`WindowsListener`], binding to the OpenSSH named pipe path.
    ///
    /// The whole pool is created synchronously so the pipe name is registered in the OS before
    /// this function returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the named pipe cannot be created, or if another program owns the name.
    pub(crate) fn new() -> Result<Self> {
        Self::with_name(PIPE_NAME)
    }

    /// Binds to the given pipe path instead of the OpenSSH one. Tests use this to avoid colliding
    /// with the runner's own OpenSSH agent service, which owns `PIPE_NAME`.
    pub(crate) fn with_name(name: &str) -> Result<Self> {
        let sid = current_user_sid().map_err(|e| anyhow!("Unable to read the user SID: {e}"))?;
        // The final DACL withholds FILE_CREATE_PIPE_INSTANCE from us too and strips the owner's
        // implicit WRITE_DAC, so the pool is created from a setup DACL that grants both (0x14019f)
        // and the final one is applied to every instance afterwards.
        let setup = format!("D:P(A;;0x14019f;;;{sid})");
        let strict = format!("D:P(A;;0x12019b;;;{sid})(A;;RC;;;OW)");
        let servers = create_instances_when_free(name, &setup)?;
        tighten(name, &servers, &strict)?;

        info!(pipe_name = name, "Named pipe listener ready");

        let handle = Handle::try_current()
            .map_err(|e| anyhow!("The pipe listener needs a Tokio runtime: {e}"))?;
        let (pool, connected) = Pool::new(handle);
        for server in servers {
            pool.arm(server);
        }

        Ok(Self { pool, connected })
    }
}

impl Drop for WindowsListener {
    fn drop(&mut self) {
        drop(self.pool.shutdown());
        self.connected.close();
        while self.connected.try_recv().is_ok() {}
    }
}

/// A just-dropped listener's aborted tasks release their handles on the runtime a moment later,
/// during which the name still looks taken; only a name that stays taken is a squatter.
fn create_instances_when_free(name: &str, sddl: &str) -> Result<Vec<NamedPipeServer>> {
    let deadline = std::time::Instant::now() + REBIND_WINDOW;
    loop {
        match create_instances(name, sddl) {
            Err(error)
                if std::time::Instant::now() < deadline
                    && error.downcast_ref::<PipeNameTaken>().is_some() =>
            {
                pause_before_rebind();
            }
            result => return result,
        }
    }
}

/// vk patch: the bind is synchronous and runs on a runtime thread; on a multi-thread runtime the
/// worker hands its other tasks off while it waits. A current-thread runtime cannot do that
/// (`block_in_place` panics there), so it sleeps as before.
fn pause_before_rebind() {
    let pause = || std::thread::sleep(REBIND_POLL);
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(pause);
        }
        _ => pause(),
    }
}

#[async_trait::async_trait]
impl Listener for WindowsListener {
    type Stream = PooledPipe;

    async fn accept(&mut self) -> Result<Connection<Self::Stream>> {
        if self.pool.live.load(Ordering::Acquire) == 0 {
            return Err(pool_exhausted());
        }
        // `recv` is cancel safe: an instance that connected while nobody was accepting stays queued.
        let Some(Some(server)) = self.connected.recv().await else {
            return Err(pool_exhausted());
        };
        let peer_info = get_peer_info(&server);
        Ok(Connection {
            stream: PooledPipe {
                server: Some(server),
                pool: Arc::clone(&self.pool),
            },
            peer_info,
        })
    }
}

/// Creates the pool. The first instance sets `FILE_FLAG_FIRST_PIPE_INSTANCE`, which turns a name
/// owned by another program into an error instead of silently attaching to its pipe.
fn create_instances(name: &str, sddl: &str) -> Result<Vec<NamedPipeServer>> {
    let descriptor = SecurityDescriptor::from_sddl(sddl)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: descriptor.0 .0,
        bInheritHandle: false.into(),
    };
    let mut servers = Vec::with_capacity(POOL_SIZE);
    for index in 0..POOL_SIZE {
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(index == 0)
            .reject_remote_clients(true)
            .write_dac(true);
        // SAFETY: `attributes` is a live, initialised SECURITY_ATTRIBUTES whose descriptor is
        // owned by `descriptor`; both outlive every call in the loop.
        let created = unsafe {
            options.create_with_security_attributes_raw(name, (&raw mut attributes).cast())
        };
        match created {
            Ok(server) => servers.push(server),
            Err(e) if index == 0 && is_name_taken_io(&e) => {
                return Err(PipeNameTaken {
                    name: name.to_owned(),
                }
                .into());
            }
            Err(e) => return Err(anyhow!("Unable to create named pipe {name}: {e}")),
        }
    }
    Ok(servers)
}

/// Replaces the DACL of every pooled instance; harmless when the descriptor is shared.
fn tighten(name: &str, servers: &[NamedPipeServer], strict_sddl: &str) -> Result<()> {
    let descriptor = SecurityDescriptor::from_sddl(strict_sddl)?;
    for server in servers {
        // SAFETY: the instance handle is live, was opened with WRITE_DAC, and `descriptor`
        // outlives the call.
        unsafe {
            SetKernelObjectSecurity(
                HANDLE(server.as_raw_handle().cast()),
                DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        }
        .map_err(|e| anyhow!("Unable to lock down named pipe {name}: {e}"))?;
    }
    Ok(())
}

fn is_name_taken_io(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(is_name_taken_code)
}

/// `CreateNamedPipeW` with `FILE_FLAG_FIRST_PIPE_INSTANCE` on a name that already exists fails
/// with access denied; pipe busy is the other code Windows uses for a name that has no room.
fn is_name_taken_code(code: i32) -> bool {
    [ERROR_ACCESS_DENIED.0, ERROR_PIPE_BUSY.0]
        .into_iter()
        .any(|taken| i32::try_from(taken) == Ok(code))
}

/// A LocalAlloc'd security descriptor, freed on drop.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `descriptor` is a local out
        // pointer that receives a LocalAlloc'd buffer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|e| anyhow!("Unable to build the pipe security descriptor: {e}"))?;
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer came from ConvertStringSecurityDescriptorToSecurityDescriptorW,
        // which documents LocalFree as the way to release it.
        unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}

/// Closes the process token on every exit path.
struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is closed exactly once here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn current_user_sid() -> Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo handle from GetCurrentProcess needs no close; `token` is a local out
    // pointer.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }?;
    let token = TokenHandle(token);

    let mut needed = 0_u32;
    // SAFETY: a null buffer with length 0 only asks for the required size.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &raw mut needed) };
    // u64 elements give the TOKEN_USER the alignment it needs.
    let mut buffer = vec![0_u64; usize::try_from(needed)?.div_ceil(8).max(1)];
    // SAFETY: `buffer` holds at least `needed` bytes and outlives the call.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &raw mut needed,
        )
    }?;

    // SAFETY: GetTokenInformation filled `buffer` with a TOKEN_USER whose SID points into it.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut string = PWSTR::null();
    // SAFETY: `sid` is a valid SID inside `buffer`; `string` receives a LocalAlloc'd string.
    unsafe { ConvertSidToStringSidW(sid, &raw mut string) }?;
    // SAFETY: on success `string` is a valid NUL-terminated wide string until LocalFree.
    let text = unsafe { string.to_string() };
    // SAFETY: `string` was allocated by ConvertSidToStringSidW and is not used afterwards.
    unsafe { LocalFree(Some(HLOCAL(string.0.cast()))) };
    Ok(text?)
}

fn pool_exhausted() -> anyhow::Error {
    ListenerExhausted("Every named pipe instance was lost; the agent cannot serve clients any more")
        .into()
}

/// Re-arms instances: each idle one waits for a client in its own task, because Windows hands a
/// connecting client to any listening instance, not to one we picked.
struct Pool {
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
    fn new(handle: Handle) -> (Arc<Self>, mpsc::UnboundedReceiver<Ready>) {
        let (ready, connected) = mpsc::unbounded_channel();
        let pool = Arc::new(Self {
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

    fn spawn<F: std::future::Future<Output = ()> + Send + 'static>(
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

    /// Aborts every owning task, which drops their instances and releases the pipe.
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
        tracing::error!(%error, remaining, "Lost a named pipe instance");
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
                tracing::debug!(%error, "A named pipe connect failed; re-arming the instance");
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
                tracing::debug!(%error, attempt, "Resetting a named pipe instance failed; retrying");
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

/// DisconnectNamedPipe discards whatever the client has not read yet, so a reply written just
/// before the connection ends would be lost. FlushFileBuffers would wait for the client to read
/// it, but it blocks a thread and cannot be cancelled. Waiting for the client to close its end
/// instead means it has read everything it wanted, costs no thread, and the timeout bounds a
/// client that never closes.
async fn recycle_instance(mut server: NamedPipeServer, pool: Arc<Pool>) {
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
    if let Err(error) = reset_with_retry(&mut server).await {
        pool.lose(&error);
        return;
    }
    pool.arm(server);
}

/// An accepted pipe instance that goes back to the pool when the connection ends.
pub(crate) struct PooledPipe {
    server: Option<NamedPipeServer>,
    pool: Arc<Pool>,
}

impl PooledPipe {
    fn server(&mut self) -> io::Result<&mut NamedPipeServer> {
        self.server
            .as_mut()
            .ok_or_else(|| io::Error::other("the pipe instance was taken"))
    }
}

impl Drop for PooledPipe {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            self.pool.recycle(server);
        }
    }
}

impl AsyncRead for PooledPipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut().server() {
            Ok(server) => Pin::new(server).poll_read(cx, buf),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for PooledPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut().server() {
            Ok(server) => Pin::new(server).poll_write(cx, buf),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().server() {
            Ok(server) => Pin::new(server).poll_flush(cx),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().server() {
            Ok(server) => Pin::new(server).poll_shutdown(cx),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

// Gathers peer process info from a connected named pipe server handle.
//
// TODO: PM-30755 Add test coverage for peer info gathering once the connection handler
// is implemented and `PeerInfo` is observable via the SSH protocol exchange.
fn get_peer_info(server: &NamedPipeServer) -> Option<PeerInfo> {
    let mut pid: u32 = 0;
    let handle = HANDLE(server.as_raw_handle().cast());

    // SAFETY: `handle` is valid for the lifetime of this call (server is still alive),
    // and `pid` is a local stack variable that Windows writes the client PID into.
    if let Err(error) = unsafe { GetNamedPipeClientProcessId(handle, &raw mut pid) } {
        warn!(%error, "Failed to get named pipe client process id");
        return None;
    }

    PeerInfo::from_pid(pid)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use std::time::Duration;

    use tokio::net::windows::named_pipe::NamedPipeClient;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_MODE, OPEN_EXISTING,
    };

    use super::*;

    // The GitHub runner's own OpenSSH agent service owns PIPE_NAME, so tests bind to unique names.
    fn pipe_name() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\vk-ssh-test-{}-{}", std::process::id(), counter)
    }

    // GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE.
    const CLIENT_ACCESS: u32 = 0x8000_0000 | 0x2 | 0x10 | 0x100 | 0x0010_0000;

    // GENERIC_WRITE (tokio's ClientOptions) includes FILE_CREATE_PIPE_INSTANCE, which the final
    // DACL withholds, so the client asks for exactly the rights the DACL grants.
    fn open_client(name: &str) -> io::Result<NamedPipeClient> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                CLIENT_ACCESS,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        }?;
        // SAFETY: `handle` is a fresh overlapped pipe handle that nothing else owns.
        unsafe { NamedPipeClient::from_raw_handle(handle.0) }
    }

    async fn accept_within(listener: &mut WindowsListener) -> Connection<PooledPipe> {
        tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("accept timed out after 10 s")
            .expect("accept failed")
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_new_creates_pipe() {
        WindowsListener::with_name(&pipe_name()).unwrap();
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_second_listener_is_refused_as_taken() {
        let name = pipe_name();
        let _first = WindowsListener::with_name(&name).unwrap();

        let error = WindowsListener::with_name(&name).err().unwrap();

        assert!(error.downcast_ref::<PipeNameTaken>().is_some());
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_name_owned_by_another_pipe_is_reported_as_taken() {
        let name = pipe_name();
        let mut other_owner = ServerOptions::new();
        other_owner.first_pipe_instance(true);
        let _other_owner = other_owner.create(&name).unwrap();

        let error = WindowsListener::with_name(&name).err().unwrap();

        let taken = error.downcast_ref::<PipeNameTaken>().unwrap();
        assert_eq!(taken.name, name);
    }

    #[test]
    fn test_only_name_collisions_count_as_taken() {
        assert!(is_name_taken_code(5));
        assert!(is_name_taken_code(231));
        assert!(!is_name_taken_code(2));
        assert!(!is_name_taken_code(0));
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_get_peer_info_connected_client_returns_some() {
        let name = pipe_name();
        let mut listener = WindowsListener::with_name(&name).unwrap();
        // Keep the client alive so the connection stays open for the duration of the check
        let _client = open_client(&name).unwrap();

        let connection = accept_within(&mut listener).await;

        assert!(connection.peer_info.is_some());
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_instance_is_recycled_after_the_client_disconnects() {
        let name = pipe_name();
        let mut listener = WindowsListener::with_name(&name).unwrap();
        for _ in 0..=POOL_SIZE {
            let client = open_client(&name).unwrap();
            let connection = accept_within(&mut listener).await;
            drop(connection);
            drop(client);
        }
    }
}
