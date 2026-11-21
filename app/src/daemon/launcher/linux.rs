//! Starts the UI process on Linux with its end of a socket pair as the channel to the daemon
//! (linux-plan.md 2d): there is no `ui.sock` for another process of the user to squat or connect
//! to, and the UI checks that the other end is its parent before it says anything.

use std::{
    io,
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
};

use vk_ipc::UiSink;

use super::ui_args_with_pipe;

/// Creates the pair, spawns the UI with one end and gives the other to the daemon's IPC server.
/// Must run inside the Tokio runtime that serves the channel.
pub fn spawn(
    exe: &Path,
    first_unlock: bool,
    no_activate: bool,
    sink: &UiSink,
) -> io::Result<tokio::process::Child> {
    // Both ends are close-on-exec; only the child clears it on its own copy, after the fork, so a
    // process another thread spawns at the same time never inherits the channel.
    let (ours, theirs) = UnixStream::pair()?;
    let fd = theirs.as_raw_fd();
    let mut command = tokio::process::Command::new(exe);
    command
        .args(ui_args_with_pipe(
            first_unlock,
            no_activate,
            usize::try_from(fd).map_err(io::Error::other)?,
        ))
        .stdin(std::process::Stdio::null())
        .kill_on_drop(false);
    if let Some(token) = crate::os::linux::activation::take() {
        command.env("XDG_ACTIVATION_TOKEN", token);
    }
    // SAFETY: the hook runs in the forked child before exec and only calls fcntl, which is
    // async-signal-safe; `fd` stays open in the parent until the spawn returns.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    tracing::info!(
        pid = child.id(),
        "UI process started with an inherited channel"
    );
    // The child owns its copy now; keeping ours would hold the channel open after the UI dies.
    drop(theirs);
    ours.set_nonblocking(true)?;
    let stream = tokio::net::UnixStream::from_std(ours)?;
    sink.offer(stream.into()).map_err(io::Error::other)?;
    Ok(child)
}
