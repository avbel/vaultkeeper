//! How the UI process reaches the daemon: `ui.sock` on macOS, the pipe handle the daemon passes
//! with `--ui-pipe` on Windows.

use std::path::Path;

use vk_ipc::{EventStream, IpcError, RemoteVault};

/// Fails before any connection attempt when the arguments do not fit this OS.
pub fn check(pipe: Option<usize>) -> anyhow::Result<()> {
    #[cfg(windows)]
    if pipe.is_none() {
        anyhow::bail!(
            "the UI process is started by the daemon with --ui-pipe; do not run it by hand"
        );
    }
    #[cfg(not(windows))]
    if pipe.is_some() {
        anyhow::bail!("--ui-pipe is only supported on Windows");
    }
    Ok(())
}

#[cfg(not(windows))]
pub async fn connect(
    data_dir: &Path,
    _pipe: Option<usize>,
) -> Result<(RemoteVault, EventStream), IpcError> {
    RemoteVault::connect(crate::os::layout::ui_endpoint(data_dir)).await
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
