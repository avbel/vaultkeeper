//! How the UI process reaches the daemon: `ui.sock` on macOS; the channel the daemon passes with
//! `--ui-pipe` elsewhere, a pipe handle on Windows and a socket fd on Linux.

use std::path::Path;

use vk_ipc::{EventStream, IpcError, RemoteVault};

/// Fails before any connection attempt when the arguments do not fit this OS.
pub fn check(pipe: Option<usize>) -> anyhow::Result<()> {
    #[cfg(any(windows, target_os = "linux"))]
    if pipe.is_none() {
        anyhow::bail!(
            "the UI process is started by the daemon with --ui-pipe; do not run it by hand"
        );
    }
    #[cfg(target_os = "macos")]
    if pipe.is_some() {
        anyhow::bail!("--ui-pipe is not used on macOS");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub async fn connect(
    data_dir: &Path,
    _pipe: Option<usize>,
) -> Result<(RemoteVault, EventStream), IpcError> {
    RemoteVault::connect(crate::os::layout::ui_endpoint(data_dir)).await
}

/// Adopts the socket the daemon passed and refuses it unless the process on the other end is our
/// parent: a stray fd number would otherwise make the UI talk to whatever it names.
#[cfg(target_os = "linux")]
pub async fn connect(
    _data_dir: &Path,
    pipe: Option<usize>,
) -> Result<(RemoteVault, EventStream), IpcError> {
    use std::os::fd::{FromRawFd, RawFd};

    let fd = pipe
        .and_then(|value| RawFd::try_from(value).ok())
        .ok_or(IpcError::Protocol("the UI socket fd is missing"))?;
    // SAFETY: the daemon cleared close-on-exec on exactly this fd for this process, and nothing
    // else here has taken ownership of it.
    let socket = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    socket.set_nonblocking(true)?;
    let socket = tokio::net::UnixStream::from_std(socket)?;
    if socket.peer_cred()?.pid() != Some(vk_ipc::parent_pid()) {
        return Err(IpcError::Protocol(
            "the UI socket does not lead to the daemon that started us",
        ));
    }
    RemoteVault::from_stream(socket.into()).await
}

#[cfg(windows)]
pub async fn connect(
    _data_dir: &Path,
    pipe: Option<usize>,
) -> Result<(RemoteVault, EventStream), IpcError> {
    let handle = pipe.ok_or(IpcError::Protocol("the UI pipe handle is missing"))?;
    // SAFETY: the daemon passed this handle through the process handle list as the only inherited
    // handle, and nothing else in this process has seen its value.
    let (stream, daemon_pid) = unsafe { vk_ipc::transport::adopt_ui_pipe(handle) }?;
    // Set once: `connect` runs once per UI process.
    let _ = DAEMON_PID.set(daemon_pid);
    RemoteVault::from_stream(stream).await
}

#[cfg(windows)]
static DAEMON_PID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// The daemon's pid as the verified UI channel reported it, for `AllowSetForegroundWindow`.
#[cfg(windows)]
#[must_use]
pub fn daemon_pid() -> Option<u32> {
    DAEMON_PID.get().copied()
}
