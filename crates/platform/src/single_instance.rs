//! Ensures one running instance; a second launch asks the first one to show its window.
//!
//! An exclusive `flock` on `instance.lock` (Unix) or a SID-scoped named mutex (Windows) decides who
//! is first. The kernel drops it when a process dies, so a crash never blocks the next launch; the
//! winner then serves one command per later launch. Unix uses a socket in the data dir; Windows a
//! machine-wide pipe named with the user's SID.

use std::path::Path;

use crate::Result;

/// Held for the process lifetime. Dropping it stops the listener and releases the lock.
#[must_use = "dropping the guard lets another instance start"]
pub struct InstanceGuard {
    #[cfg(unix)]
    _guard: unix::Guard,
    #[cfg(windows)]
    _guard: windows::Guard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    ShowManager,
    ShowQuickPanel,
    /// Stop the running daemon; used by the installer, uninstaller and updater.
    Quit,
}

impl Command {
    const fn code(self) -> u8 {
        match self {
            Self::ShowManager => 1,
            Self::ShowQuickPanel => 2,
            Self::Quit => 3,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ShowManager),
            2 => Some(Self::ShowQuickPanel),
            3 => Some(Self::Quit),
            _ => None,
        }
    }
}

/// First byte of every command message, so stray connections are told apart from commands.
const MESSAGE_TAG: u8 = 0xB1;

/// The machine-wide single-instance pipe, SID-scoped so two users keep separate daemons.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only the Windows single instance uses it")
)]
fn instance_pipe_name(sid: &str) -> String {
    format!(r"\\.\pipe\vaultkeeper.{sid}.instance")
}

/// The named mutex that decides which launch is first. `global` names the `Global\` namespace,
/// shared across the user's console and RDP sessions; a normal process may lack the privilege it
/// needs, so the Windows code falls back to the per-session `Local\`.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only the Windows single instance uses it")
)]
fn mutex_name(sid: &str, global: bool) -> String {
    let scope = if global { "Global" } else { "Local" };
    format!("{scope}\\Vaultkeeper-{sid}")
}

/// Waits until process `pid` has exited, at most `timeout`; returns whether it did. An updated
/// app started by the old one waits here, so it does not find the old one still holding the lock.
#[cfg(unix)]
#[must_use]
pub fn wait_for_exit(pid: i32, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        // SAFETY: signal 0 only checks that the process exists; no signal is sent.
        let alive = unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        if !alive {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// [`wait_for_exit`] on Windows: `OpenProcess(SYNCHRONIZE)` + `WaitForSingleObject`.
#[cfg(windows)]
#[must_use]
pub fn wait_for_exit(pid: i32, timeout: std::time::Duration) -> bool {
    windows::wait_for_exit(pid, timeout)
}

/// `--quit`: asks the running instance to quit and waits up to `timeout` for it to release the
/// instance lock. Succeeds when nothing is running; fails when the command was not delivered or
/// the instance outlived the timeout.
pub fn quit_running(timeout: std::time::Duration) -> Result<()> {
    #[cfg(unix)]
    {
        unix::quit_running(&crate::paths::data_dir()?, timeout)
    }
    #[cfg(windows)]
    {
        windows::quit_running(timeout)
    }
}

/// Returns the guard if we are the first instance; otherwise forwards `command` to the
/// running instance and returns [`crate::Error::AlreadyRunning`]. `on_command` runs on a
/// background thread for commands from later launches.
pub fn acquire(
    command: Command,
    on_command: impl Fn(Command) + Send + 'static,
) -> Result<InstanceGuard> {
    acquire_in(&crate::paths::data_dir()?, command, on_command)
}

/// [`acquire`] with the lock and socket in `dir` instead of the data dir. `dir` must exist and
/// should be private to the user; the socket path must stay under the 104-byte `sun_path` limit.
/// Windows ignores `dir`: the mutex and pipe names are SID-scoped and machine-wide.
pub fn acquire_in(
    dir: &Path,
    command: Command,
    on_command: impl Fn(Command) + Send + 'static,
) -> Result<InstanceGuard> {
    #[cfg(unix)]
    {
        Ok(InstanceGuard {
            _guard: unix::acquire(dir, command, on_command)?,
        })
    }
    #[cfg(windows)]
    {
        Ok(InstanceGuard {
            _guard: windows::acquire(dir, command, on_command)?,
        })
    }
}

#[cfg(unix)]
mod unix {
    use std::{
        fs::{File, OpenOptions, TryLockError},
        io::{self, Read, Write},
        os::unix::fs::OpenOptionsExt,
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread::JoinHandle,
        time::{Duration, Instant},
    };

    use interprocess::local_socket::{
        GenericFilePath, Listener, ListenerOptions, Stream, ToFsName, prelude::*,
    };

    use super::{Command, MESSAGE_TAG};
    use crate::{Error, Result};

    const LOCK_FILE: &str = "instance.lock";
    const SOCKET_FILE: &str = "instance.sock";
    /// First byte of every message, so stray connections are told apart from commands.
    const WAKE_CODE: u8 = 0;
    const READ_TIMEOUT: Duration = Duration::from_secs(1);
    /// The first instance may hold the lock but not have bound the socket yet.
    const CONNECT_ATTEMPTS: u32 = 20;
    const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);
    const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
    const QUIT_POLL: Duration = Duration::from_millis(50);

    pub(super) struct Guard {
        socket: PathBuf,
        stop: Arc<AtomicBool>,
        listener: Option<JoinHandle<()>>,
        _lock: File,
    }

    pub(super) fn acquire(
        dir: &Path,
        command: Command,
        on_command: impl Fn(Command) + Send + 'static,
    ) -> Result<Guard> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(dir.join(LOCK_FILE))?;
        let socket = dir.join(SOCKET_FILE);
        match lock.try_lock() {
            Ok(()) => listen(lock, socket, on_command),
            Err(TryLockError::WouldBlock) => {
                let _ = forward(&socket, command);
                Err(Error::AlreadyRunning)
            }
            Err(TryLockError::Error(err)) => Err(err.into()),
        }
    }

    pub(super) fn quit_running(dir: &Path, timeout: Duration) -> Result<()> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(dir.join(LOCK_FILE))?;
        let deadline = Instant::now() + timeout;
        let mut sent = false;
        loop {
            match lock.try_lock() {
                Ok(()) => return Ok(()),
                Err(TryLockError::Error(err)) => return Err(err.into()),
                Err(TryLockError::WouldBlock) => {}
            }
            if !sent {
                forward(&dir.join(SOCKET_FILE), Command::Quit)?;
                sent = true;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Vaultkeeper accepted the quit request but is still running",
                )
                .into());
            }
            std::thread::sleep(QUIT_POLL);
        }
    }

    fn listen(
        lock: File,
        socket: PathBuf,
        on_command: impl Fn(Command) + Send + 'static,
    ) -> Result<Guard> {
        // Holding the lock proves any existing socket file is stale.
        match std::fs::remove_file(&socket) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err.into()),
            _ => {}
        }
        let listener = ListenerOptions::new()
            .name(socket.as_path().to_fs_name::<GenericFilePath>()?)
            .create_sync()?;
        let stop = Arc::new(AtomicBool::new(false));
        let serve_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("vk-single-instance".into())
            .spawn(move || serve(&listener, &serve_stop, &on_command))?;
        Ok(Guard {
            socket,
            stop,
            listener: Some(thread),
            _lock: lock,
        })
    }

    fn serve(listener: &Listener, stop: &AtomicBool, on_command: &impl Fn(Command)) {
        loop {
            let accepted = listener.accept();
            if stop.load(Ordering::Acquire) {
                return;
            }
            match accepted {
                Ok(stream) => match read_command(stream) {
                    Ok(Some(command)) => on_command(command),
                    Ok(None) => tracing::debug!("ignored unknown single-instance message"),
                    Err(err) => tracing::debug!(error = %err, "bad single-instance message"),
                },
                Err(err) => {
                    tracing::warn!(error = %err, "single-instance accept failed");
                    std::thread::sleep(ACCEPT_ERROR_BACKOFF);
                }
            }
        }
    }

    fn read_command(mut stream: Stream) -> io::Result<Option<Command>> {
        // macOS rejects this with EINVAL once the peer has closed, which a sender does right
        // after writing; its bytes are still buffered and the read cannot block then.
        if let Err(err) = stream.set_recv_timeout(Some(READ_TIMEOUT)) {
            tracing::trace!(error = %err, "could not set single-instance read timeout");
        }
        let mut message = [0_u8; 2];
        stream.read_exact(&mut message)?;
        Ok(match message {
            [MESSAGE_TAG, code] => Command::from_code(code),
            _ => None,
        })
    }

    fn send(socket: &Path, code: u8) -> io::Result<()> {
        let mut stream = Stream::connect(socket.to_fs_name::<GenericFilePath>()?)?;
        stream.write_all(&[MESSAGE_TAG, code])?;
        stream.flush()
    }

    fn forward(socket: &Path, command: Command) -> io::Result<()> {
        let mut last_error = None;
        for _ in 0..CONNECT_ATTEMPTS {
            match send(socket, command.code()) {
                Ok(()) => return Ok(()),
                Err(err) => last_error = Some(err),
            }
            std::thread::sleep(CONNECT_RETRY_DELAY);
        }
        let err = last_error.unwrap_or_else(|| io::Error::other("no attempt was made"));
        tracing::warn!(error = %err, "running instance did not accept the command");
        Err(err)
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let Some(thread) = self.listener.take() else {
                return;
            };
            // accept() only returns on a connection; without one the thread would block forever.
            match send(&self.socket, WAKE_CODE) {
                Ok(()) => {
                    if thread.join().is_err() {
                        tracing::error!("single-instance listener panicked");
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "could not wake single-instance listener");
                }
            }
        }
    }
}

#[cfg(windows)]
mod windows;

#[cfg(all(test, unix))]
mod tests {
    use std::{sync::mpsc, time::Duration};

    use super::*;
    use crate::Error;

    const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

    fn recorder() -> (mpsc::Receiver<Command>, impl Fn(Command) + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        (rx, move |command| tx.send(command).expect("receiver alive"))
    }

    #[test]
    fn command_codes_round_trip() {
        for command in [Command::ShowManager, Command::ShowQuickPanel, Command::Quit] {
            assert_eq!(Command::from_code(command.code()), Some(command));
        }
        assert_eq!(Command::from_code(0), None);
        assert_eq!(Command::from_code(4), None);
    }

    #[test]
    fn second_launch_forwards_its_command_and_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (rx, on_command) = recorder();
        let guard = acquire_in(dir.path(), Command::ShowManager, on_command).expect("first");

        let second = acquire_in(dir.path(), Command::ShowQuickPanel, |_| {});
        assert!(matches!(second, Err(Error::AlreadyRunning)));
        assert_eq!(
            rx.recv_timeout(DELIVERY_TIMEOUT),
            Ok(Command::ShowQuickPanel)
        );

        let third = acquire_in(dir.path(), Command::ShowManager, |_| {});
        assert!(matches!(third, Err(Error::AlreadyRunning)));
        assert_eq!(rx.recv_timeout(DELIVERY_TIMEOUT), Ok(Command::ShowManager));
        drop(guard);
    }

    #[test]
    fn releasing_the_guard_lets_the_next_launch_become_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = acquire_in(dir.path(), Command::ShowManager, |_| {}).expect("first");
        drop(first);
        assert!(
            !dir.path().join("instance.sock").exists(),
            "socket removed on drop"
        );

        let (rx, on_command) = recorder();
        let _next = acquire_in(dir.path(), Command::ShowManager, on_command).expect("next");
        let refused = acquire_in(dir.path(), Command::ShowQuickPanel, |_| {});
        assert!(matches!(refused, Err(Error::AlreadyRunning)));
        assert_eq!(
            rx.recv_timeout(DELIVERY_TIMEOUT),
            Ok(Command::ShowQuickPanel)
        );
    }

    #[test]
    fn stale_socket_from_a_crashed_instance_is_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("instance.sock");
        drop(std::os::unix::net::UnixListener::bind(&socket).expect("stale listener"));
        assert!(
            socket.exists(),
            "std leaves the socket file behind, like a crash"
        );

        let (rx, on_command) = recorder();
        let _guard = acquire_in(dir.path(), Command::ShowManager, on_command).expect("first");
        let refused = acquire_in(dir.path(), Command::ShowQuickPanel, |_| {});
        assert!(matches!(refused, Err(Error::AlreadyRunning)));
        assert_eq!(
            rx.recv_timeout(DELIVERY_TIMEOUT),
            Ok(Command::ShowQuickPanel)
        );
    }

    #[test]
    fn garbage_connections_are_ignored() {
        use std::io::Write;

        let dir = tempfile::tempdir().expect("tempdir");
        let (rx, on_command) = recorder();
        let _guard = acquire_in(dir.path(), Command::ShowManager, on_command).expect("first");
        let socket = dir.path().join("instance.sock");
        let mut stray = std::os::unix::net::UnixStream::connect(&socket).expect("connect");
        stray.write_all(b"GET / HTTP/1.1\r\n").expect("write");
        drop(stray);
        drop(std::os::unix::net::UnixStream::connect(&socket).expect("empty connection"));

        let refused = acquire_in(dir.path(), Command::ShowQuickPanel, |_| {});
        assert!(matches!(refused, Err(Error::AlreadyRunning)));
        assert_eq!(
            rx.recv_timeout(DELIVERY_TIMEOUT),
            Ok(Command::ShowQuickPanel)
        );
        assert!(rx.try_recv().is_err(), "only the real command is delivered");
    }

    #[test]
    fn quit_running_succeeds_when_nothing_runs() {
        let dir = tempfile::tempdir().expect("tempdir");
        unix::quit_running(dir.path(), Duration::from_secs(1)).expect("nothing to stop");
    }

    #[test]
    fn quit_running_delivers_quit_and_waits_for_the_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (rx, on_command) = recorder();
        let guard = acquire_in(dir.path(), Command::ShowManager, on_command).expect("first");
        let releaser = std::thread::spawn(move || {
            assert_eq!(rx.recv_timeout(DELIVERY_TIMEOUT), Ok(Command::Quit));
            drop(guard);
        });
        unix::quit_running(dir.path(), DELIVERY_TIMEOUT).expect("quit and exit");
        releaser.join().expect("releaser");
    }

    #[test]
    fn quit_running_times_out_when_the_instance_stays() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = acquire_in(dir.path(), Command::ShowManager, |_| {}).expect("first");
        let error = unix::quit_running(dir.path(), Duration::from_millis(300)).expect_err("stays");
        assert!(matches!(error, Error::Io(err) if err.kind() == std::io::ErrorKind::TimedOut));
    }

    #[test]
    fn missing_dir_is_an_io_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing");
        let result = acquire_in(&missing, Command::ShowManager, |_| {});
        assert!(
            matches!(result, Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound)
        );
    }
}

#[cfg(test)]
mod portable_tests {
    use super::{instance_pipe_name, mutex_name};

    #[test]
    fn the_instance_pipe_is_sid_scoped() {
        assert_eq!(
            instance_pipe_name("S-1-5-21-1-2-3-1001"),
            r"\\.\pipe\vaultkeeper.S-1-5-21-1-2-3-1001.instance"
        );
        assert_ne!(
            instance_pipe_name("S-1-5-18"),
            instance_pipe_name("S-1-5-19")
        );
    }

    #[test]
    fn the_mutex_name_picks_its_namespace() {
        assert_eq!(mutex_name("S-1-5-18", true), r"Global\Vaultkeeper-S-1-5-18");
        assert_eq!(mutex_name("S-1-5-18", false), r"Local\Vaultkeeper-S-1-5-18");
    }
}
