//! Native messaging host. This process never initializes the vault or UI.

mod native;
mod parent;

use std::io;
#[cfg(unix)]
use std::os::fd::AsFd as _;
#[cfg(windows)]
use std::os::windows::io::AsHandle as _;
#[cfg(unix)]
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

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
    let connected = match layout::socket_path(&endpoint) {
        Ok(socket) => connect(&socket).await,
        Err(error) => Err(error),
    };
    let mut stream = match connected {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(%error, "browser daemon unavailable");
            unavailable("not_running").await?;
            return Ok(());
        }
    };
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

// Windows: step 5f - the browser host speaks to a named pipe; until then it reports the
// daemon as unavailable.
#[cfg(not(unix))]
type Socket = tokio::io::DuplexStream;

#[cfg(not(unix))]
#[allow(clippy::unused_async, reason = "same signature as the Unix connect")]
async fn connect(_path: &std::path::Path) -> io::Result<Socket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the browser socket is not available on this platform yet",
    ))
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
    start_daemon()?;
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
fn bundle_path(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle.extension().is_some_and(|ext| ext == "app"))
    .then(|| bundle.to_path_buf())
}

#[cfg(unix)]
fn start_daemon() -> io::Result<()> {
    let exe = std::env::current_exe()?;
    let mut command = if let Some(bundle) = bundle_path(&exe) {
        let mut command = Command::new("/usr/bin/open");
        command
            .arg("-g")
            .arg("-a")
            .arg(bundle)
            .args(["--args", "--tray"]);
        command
    } else {
        let mut command = Command::new(exe);
        command.arg("--tray");
        command
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}
