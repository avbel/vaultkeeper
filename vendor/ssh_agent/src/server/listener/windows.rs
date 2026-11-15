//! Windows named pipe listener for the SSH agent server
//!
//! vk patch: the pipe ends up with an explicit DACL that withholds
//! `FILE_CREATE_PIPE_INSTANCE` from everyone, so no same-user process can add an instance and
//! steal the next client. The listener therefore builds a fixed pool of instances up front (from
//! a setup DACL that still allows it), applies the final DACL to each and recycles them after
//! their client disconnects (same approach as `vk-ipc`'s transport).

use std::{
    io,
    os::windows::io::AsRawHandle,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
};

use anyhow::{anyhow, Result};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    runtime::Handle,
    sync::mpsc,
    task::JoinSet,
};
use tracing::{info, warn};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, LocalFree, ERROR_ACCESS_DENIED, HANDLE, HLOCAL},
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

use super::Listener;
use crate::server::{connection::Connection, peer_info::PeerInfo};

/// The fixed named pipe path that OpenSSH clients expect on Windows
const PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

/// The DACL denies creating more instances later, so this is the ceiling for concurrent clients.
const POOL_SIZE: usize = 4;

/// Pause before re-arming an instance whose connect failed.
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

const SDDL_REVISION_1: u32 = 1;

/// Shown when another program already owns the pipe name; the OpenSSH service is the usual one.
const NAME_TAKEN_MESSAGE: &str = "The Windows OpenSSH Authentication Agent service is running; \
stop and disable it, or turn off Vaultkeeper's SSH agent";

/// Windows named pipe listener for the SSH agent server
pub(crate) struct WindowsListener {
    pool: Arc<Pool>,
    connected: mpsc::UnboundedReceiver<NamedPipeServer>,
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
        let servers = create_instances(name, &setup)?;
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
        self.pool.shutdown();
    }
}

#[async_trait::async_trait]
impl Listener for WindowsListener {
    type Stream = PooledPipe;

    async fn accept(&mut self) -> Result<Connection<Self::Stream>> {
        // `recv` is cancel safe: an instance that connected while nobody was accepting stays queued.
        let server = self
            .connected
            .recv()
            .await
            .ok_or_else(|| anyhow!("The named pipe pool is closed"))?;
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
            Err(e) if index == 0 && is_access_denied_io(&e) => {
                return Err(anyhow::Error::new(e).context(NAME_TAKEN_MESSAGE));
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

fn is_access_denied_io(error: &io::Error) -> bool {
    error.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED.0).ok()
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

/// Re-arms instances: each idle one waits for a client in its own task, because Windows hands a
/// connecting client to any listening instance, not to one we picked.
struct Pool {
    handle: Handle,
    ready: mpsc::UnboundedSender<NamedPipeServer>,
    /// `None` once the listener is gone, so late recycles drop their instance instead of arming it.
    tasks: Mutex<Option<JoinSet<()>>>,
}

impl Pool {
    fn new(handle: Handle) -> (Arc<Self>, mpsc::UnboundedReceiver<NamedPipeServer>) {
        let (ready, connected) = mpsc::unbounded_channel();
        let pool = Arc::new(Self {
            handle,
            ready,
            tasks: Mutex::new(Some(JoinSet::new())),
        });
        (pool, connected)
    }

    fn arm(&self, server: NamedPipeServer) {
        let mut guard = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(tasks) = guard.as_mut() else {
            return;
        };
        while tasks.try_join_next().is_some() {}
        let ready = self.ready.clone();
        tasks.spawn_on(wait_for_client(server, ready), &self.handle);
    }

    /// Aborting the armed tasks drops their instances, which releases the pipe.
    fn shutdown(&self) {
        self.tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}

/// A failed connect (a client that vanished early) must not shrink the fixed pool, so the instance
/// is disconnected and armed again after a pause that keeps a persistent error from spinning.
async fn wait_for_client(server: NamedPipeServer, ready: mpsc::UnboundedSender<NamedPipeServer>) {
    loop {
        match server.connect().await {
            Ok(()) => {
                let _ = ready.send(server);
                return;
            }
            Err(error) => {
                tracing::debug!(%error, "A named pipe connect failed; re-arming the instance");
                if server.disconnect().is_err() {
                    warn!("Unable to recycle a named pipe instance");
                    return;
                }
                tokio::time::sleep(RETRY_DELAY).await;
            }
        }
    }
}

fn recycle(pool: &Pool, server: NamedPipeServer) {
    if server.disconnect().is_err() {
        warn!("Unable to recycle a named pipe instance");
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
            recycle(&self.pool, server);
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
    async fn test_second_listener_is_refused_with_the_service_hint() {
        let name = pipe_name();
        let _first = WindowsListener::with_name(&name).unwrap();

        let error = WindowsListener::with_name(&name).err().unwrap();

        assert!(error.to_string().contains("OpenSSH Authentication Agent"));
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
