//! Ensures one running instance; a second launch asks the first one to show its window.
//!
//! An exclusive `flock` on `instance.lock` decides who is first. The kernel drops it when a
//! process dies, so a crash never blocks the next launch; the winner then replaces any stale
//! `instance.sock` left behind. Later launches connect to that socket and send one command.

use std::path::Path;

use crate::Result;

/// Held for the process lifetime. Dropping it stops the listener and releases the lock.
#[must_use = "dropping the guard lets another instance start"]
pub struct InstanceGuard {
    #[cfg(unix)]
    _guard: unix::Guard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    ShowManager,
    ShowQuickPanel,
}

impl Command {
    const fn code(self) -> u8 {
        match self {
            Self::ShowManager => 1,
            Self::ShowQuickPanel => 2,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ShowManager),
            2 => Some(Self::ShowQuickPanel),
            _ => None,
        }
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
    #[cfg(not(unix))]
    {
        let _ = (dir, command, on_command);
        Err(crate::Error::Unsupported)
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
        time::Duration,
    };

    use interprocess::local_socket::{
        GenericFilePath, Listener, ListenerOptions, Stream, ToFsName, prelude::*,
    };

    use super::Command;
    use crate::{Error, Result};

    const LOCK_FILE: &str = "instance.lock";
    const SOCKET_FILE: &str = "instance.sock";
    /// First byte of every message, so stray connections are told apart from commands.
    const MESSAGE_TAG: u8 = 0xB1;
    const WAKE_CODE: u8 = 0;
    const READ_TIMEOUT: Duration = Duration::from_secs(1);
    /// The first instance may hold the lock but not have bound the socket yet.
    const CONNECT_ATTEMPTS: u32 = 20;
    const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);
    const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

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
                forward(&socket, command);
                Err(Error::AlreadyRunning)
            }
            Err(TryLockError::Error(err)) => Err(err.into()),
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

    fn forward(socket: &Path, command: Command) {
        let mut last_error = None;
        for _ in 0..CONNECT_ATTEMPTS {
            match send(socket, command.code()) {
                Ok(()) => return,
                Err(err) => last_error = Some(err),
            }
            std::thread::sleep(CONNECT_RETRY_DELAY);
        }
        if let Some(err) = last_error {
            tracing::warn!(error = %err, "running instance did not accept the command");
        }
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
        for command in [Command::ShowManager, Command::ShowQuickPanel] {
            assert_eq!(Command::from_code(command.code()), Some(command));
        }
        assert_eq!(Command::from_code(0), None);
        assert_eq!(Command::from_code(3), None);
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
    fn missing_dir_is_an_io_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing");
        let result = acquire_in(&missing, Command::ShowManager, |_| {});
        assert!(
            matches!(result, Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound)
        );
    }
}
