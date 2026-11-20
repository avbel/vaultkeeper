//! Unix domain sockets behind the transport seam.

use std::{
    io,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{
        UnixListener, UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
};

use super::Endpoint;
use crate::peer::{self, PeerCredentials};

/// A bound Unix domain socket.
#[derive(Debug)]
pub struct Listener {
    inner: UnixListener,
}

impl Listener {
    pub fn bind(endpoint: &Endpoint) -> io::Result<Self> {
        let path = socket_path(endpoint)?;
        Ok(Self {
            inner: UnixListener::bind(path)?,
        })
    }

    /// Accepts a connection together with the credentials of the process on its other end.
    pub async fn accept(&self) -> io::Result<(Stream, PeerCredentials)> {
        let (stream, _) = self.inner.accept().await?;
        let credentials = credentials(&stream)?;
        Ok((Stream { inner: stream }, credentials))
    }
}

/// A connected Unix domain socket.
#[derive(Debug)]
pub struct Stream {
    inner: UnixStream,
}

impl Stream {
    #[must_use]
    pub fn into_split(self) -> (ReadHalf, WriteHalf) {
        self.inner.into_split()
    }

    /// The credentials of the process on the other end, for a client that must check its server.
    pub fn peer_credentials(&self) -> io::Result<PeerCredentials> {
        credentials(&self.inner)
    }
}

impl From<UnixStream> for Stream {
    fn from(inner: UnixStream) -> Self {
        Self { inner }
    }
}

/// The read end of a [`Stream`], owned so it can move to its own task.
pub type ReadHalf = OwnedReadHalf;
/// The write end of a [`Stream`], owned so it can move to its own task.
pub type WriteHalf = OwnedWriteHalf;

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Connects to a socket path.
pub async fn connect(endpoint: &Endpoint) -> io::Result<Stream> {
    let stream = UnixStream::connect(socket_path(endpoint)?).await?;
    Ok(Stream { inner: stream })
}

/// Reads the peer pid, uid and audit token, then resolves the peer's executable path.
pub(crate) fn credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let (uid, pid, audit_token) = identify(stream)?;
    let executable = peer::executable_of(pid)
        .and_then(|path| path.canonicalize())
        .unwrap_or_default();
    Ok(PeerCredentials {
        uid,
        pid,
        executable,
        audit_token,
        #[cfg(target_os = "linux")]
        exe_identity: linux::exe_identity(stream, pid),
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use tokio::net::UnixStream;

    use crate::peer::FileIdentity;

    /// The identity of the peer's executable, or `None` when the peer exited before it was read
    /// (its pid may already name another process).
    pub(super) fn exe_identity(stream: &UnixStream, pid: i32) -> Option<FileIdentity> {
        let pidfd = match peer_pidfd(stream) {
            Ok(pidfd) => Some(pidfd),
            Err(error) => {
                // Kernels before 6.5; the security gate refuses those, so this is only a log line.
                tracing::warn!(%error, "no SO_PEERPIDFD; the peer identity is not pinned");
                None
            }
        };
        let identity = FileIdentity::of(std::path::Path::new(&format!("/proc/{pid}/exe")))
            .inspect_err(|error| tracing::warn!(%error, pid, "cannot identify the IPC peer"))
            .ok()?;
        match pidfd {
            Some(pidfd) if exited(&pidfd) => {
                tracing::warn!(pid, "the IPC peer exited while it was identified");
                None
            }
            _ => Some(identity),
        }
    }

    fn peer_pidfd(stream: &UnixStream) -> std::io::Result<OwnedFd> {
        let mut fd: libc::c_int = -1;
        let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>())
            .map_err(|_| std::io::Error::other("c_int size does not fit socklen_t"))?;
        // SAFETY: the socket fd is borrowed from `stream` for the call; `fd` and `len` are live,
        // writable locals of the sizes passed.
        let status = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                vk_linux::consts::SO_PEERPIDFD,
                (&raw mut fd).cast(),
                &raw mut len,
            )
        };
        if status != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the kernel returned a new pidfd that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// A pidfd polls readable once its process has exited; a poll error counts as exited too,
    /// so the check fails closed.
    fn exited(pidfd: &OwnedFd) -> bool {
        let mut poll = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd, zero timeout.
        let ready = unsafe { libc::poll(&raw mut poll, 1, 0) };
        ready != 0
    }
}

fn socket_path(endpoint: &Endpoint) -> io::Result<&Path> {
    endpoint.as_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "a Unix socket listener cannot bind a named pipe",
        )
    })
}

#[cfg(target_os = "macos")]
fn identify(stream: &UnixStream) -> io::Result<(u32, i32, Option<[u32; 8]>)> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is an open socket borrowed from `stream` for the whole call, and both out
    // pointers point at live, writable locals of the right type.
    if unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut token = [0_u32; 8];
    let mut len = libc::socklen_t::try_from(size_of_val(&token))
        .map_err(|_| io::Error::other("audit_token_t size does not fit socklen_t"))?;
    // SAFETY: `fd` is open (see above); `token` is a writable `audit_token_t`-sized buffer (eight
    // u32) and `len` a live in/out local, as getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN) requires.
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(len).ok() != Some(size_of_val(&token)) {
        return Err(io::Error::other("short audit token"));
    }
    // audit_token_t layout (bsm/libbsm.h, audit_token_to_pid): val[5] is the pid.
    let pid = i32::try_from(token[5]).map_err(|_| io::Error::other("pid out of range"))?;
    Ok((uid, pid, Some(token)))
}

#[cfg(not(target_os = "macos"))]
fn identify(stream: &UnixStream) -> io::Result<(u32, i32, Option<[u32; 8]>)> {
    let credentials = stream.peer_cred()?;
    let pid = credentials
        .pid()
        .ok_or_else(|| io::Error::other("the OS does not report the peer pid"))?;
    Ok((credentials.uid(), pid, None))
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU32, Ordering},
    };

    use super::*;

    static NEXT: AtomicU32 = AtomicU32::new(0);

    fn temp_dir() -> PathBuf {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("vk-transport-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[tokio::test]
    async fn a_connection_arrives_with_our_credentials() {
        let dir = temp_dir();
        let endpoint = Endpoint::path(dir.join("test.sock"));
        let listener = Listener::bind(&endpoint).expect("bind");

        let (accepted, connected) = tokio::join!(listener.accept(), connect(&endpoint));
        let (_server, credentials) = accepted.expect("accept");
        let _client = connected.expect("connect");

        assert_eq!(credentials.uid, peer::own_uid());
        assert_eq!(
            credentials.pid,
            i32::try_from(std::process::id()).expect("pid fits")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_pipe_endpoint_is_refused_on_unix() {
        let endpoint = Endpoint::pipe(r"\\.\pipe\vaultkeeper.test");
        let error = Listener::bind(&endpoint).expect_err("named pipes are Windows-only");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let error = connect(&endpoint).await.expect_err("no pipe support");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
