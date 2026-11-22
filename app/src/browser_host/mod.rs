//! Native messaging host. This process never initializes the vault or UI.

#[cfg(unix)]
mod launch;
mod native;
mod parent;

use std::io;
#[cfg(unix)]
use std::os::fd::AsFd as _;
#[cfg(windows)]
use std::os::windows::io::AsHandle as _;
#[cfg(unix)]
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::net::UnixStream;
use vk_ipc::{
    browser::{
        BROWSER_MAX_FRAME,
        protocol::{Caller, HostHello, PROTOCOL_VERSION},
    },
    frame::read_frame_with_limit,
    transport::Endpoint,
};
use zeroize::Zeroizing;

use crate::{cli::HostCaller, os::layout};

pub fn run(caller: HostCaller) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("start browser host runtime")?;
    let result = runtime.block_on(run_async(caller));
    // Tokio's stdin uses a blocking worker; do not wait for it if the daemon disconnects first.
    runtime.shutdown_background();
    result
}

// Not cancel-safe mid-frame; cancellation closes the socket and ends the host process.
async fn run_async(caller: HostCaller) -> anyhow::Result<()> {
    let parent = parent::identify(&caller);
    let caller = match caller {
        HostCaller::Chromium { origin } => Caller::Chromium { origin },
        HostCaller::Firefox { extension_id } => Caller::Firefox { extension_id },
    };
    let endpoint = layout::browser_endpoint(&layout::data_dir()?);
    let mut stream = match connect_endpoint(&endpoint).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(%error, "browser daemon unavailable");
            unavailable("not_running").await?;
            return Ok(());
        }
    };
    #[cfg(target_os = "linux")]
    if let Err(error) = verify_daemon(&endpoint, &stream) {
        tracing::warn!(%error, "the browser socket is not Vaultkeeper's");
        unavailable("untrusted_daemon").await?;
        return Ok(());
    }
    let hello = HostHello {
        protocol: PROTOCOL_VERSION,
        caller,
        parent,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&hello)?);
    write_socket(&mut stream, &bytes).await?;
    let welcome = read_frame_with_limit(&mut stream, BROWSER_MAX_FRAME)
        .await?
        .context("browser daemon closed during handshake")?;
    let welcome: serde_json::Value = serde_json::from_slice(&welcome)?;
    if welcome.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let reason = welcome
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("internal");
        unavailable(reason).await?;
        return Ok(());
    }
    // The welcome means the daemon has verified this host by its exe.
    vk_platform::hardening::harden_after_handshake()?;
    #[cfg(unix)]
    let (mut read, mut write) = stream.into_split();
    #[cfg(not(unix))]
    let (mut read, mut write) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    #[cfg(unix)]
    let mut stdout = std::fs::File::from(std::io::stdout().as_fd().try_clone_to_owned()?);
    #[cfg(windows)]
    let mut stdout = std::fs::File::from(std::io::stdout().as_handle().try_clone_to_owned()?);
    let upstream = async {
        while let Some(body) = native::read_message(&mut stdin).await? {
            write_socket(&mut write, &body).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let downstream = async {
        while let Some(body) = read_frame_with_limit(&mut read, BROWSER_MAX_FRAME).await? {
            native::write_message_unbuffered(&mut stdout, &body)?;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! { result = upstream => result, result = downstream => result }
}

/// The daemon is non-dumpable, so it is checked by its socket and cgroup, not its exe.
#[cfg(target_os = "linux")]
fn verify_daemon(endpoint: &Endpoint, stream: &UnixStream) -> io::Result<()> {
    vk_ipc::daemon_check::check_socket(&layout::socket_path(endpoint)?)?;
    let binding = vk_ipc::daemon_check::check_peer(stream)?;
    tracing::debug!(?binding, "browser daemon check passed");
    Ok(())
}

// Not cancel-safe mid-frame; cancellation closes the socket.
async fn write_socket<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> io::Result<()> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|_| body.len() <= BROWSER_MAX_FRAME)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "browser frame too large"))?;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(body).await
}

// Not cancel-safe mid-frame; callers terminate the host on cancellation.
async fn unavailable(reason: &str) -> io::Result<()> {
    let body = Zeroizing::new(serde_json::to_vec(
        &serde_json::json!({"event":"unavailable", "reason":reason}),
    )?);
    native::write_message(&mut tokio::io::stdout(), &body).await
}

#[cfg(unix)]
async fn connect_endpoint(endpoint: &Endpoint) -> io::Result<UnixStream> {
    connect(&layout::socket_path(endpoint)?).await
}

#[cfg(windows)]
type Socket = vk_ipc::transport::Stream;

#[cfg(windows)]
const ERROR_PIPE_BUSY: i32 = 231;

// Both a missing pipe (no daemon yet) and a busy one (daemon between two clients) are worth
// another try.
#[cfg(windows)]
fn daemon_not_ready(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(ERROR_PIPE_BUSY)
}

// Cancel-safe: cancelling a connection attempt drops its socket.
#[cfg(windows)]
async fn connect_endpoint(endpoint: &Endpoint) -> io::Result<Socket> {
    match vk_ipc::transport::connect(endpoint).await {
        Ok(stream) => return Ok(stream),
        // A busy pipe is a running daemon: a second launch would only show its Manager window.
        Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {}
        Err(error) if daemon_not_ready(&error) => crate::os::detached::start_daemon()?,
        Err(error) => return Err(error),
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        match vk_ipc::transport::connect(endpoint).await {
            Ok(stream) => return Ok(stream),
            Err(error) if daemon_not_ready(&error) && tokio::time::Instant::now() < deadline => {}
            Err(error) => return Err(error),
        }
    }
}

// Cancel-safe: cancelling a connection attempt drops its socket.
#[cfg(unix)]
async fn connect(path: &Path) -> io::Result<UnixStream> {
    match UnixStream::connect(path).await {
        Ok(stream) => return Ok(stream),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) => {}
        Err(error) => return Err(error),
    }
    // A running daemon whose browser listener is not up must not be launched again: the second
    // launch would only show its Manager window. It may still be binding, so it gets the wait.
    if !instance_running() {
        launch::start_daemon().await?;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        match UnixStream::connect(path).await {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) && tokio::time::Instant::now() < deadline => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
fn instance_running() -> bool {
    match layout::data_dir() {
        Ok(data_dir) => vk_platform::single_instance::running_in(&layout::socket_dir(&data_dir)),
        Err(error) => {
            tracing::warn!(%error, "cannot locate the single-instance socket");
            false
        }
    }
}
