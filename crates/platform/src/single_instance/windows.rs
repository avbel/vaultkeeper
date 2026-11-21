//! Windows single instance: a SID-scoped named mutex decides who is first; the winner serves
//! [`Command`]s on a machine-wide pipe. vk-platform has no Tokio, so this uses synchronous
//! overlapped `CreateNamedPipeW`/`ConnectNamedPipe` on a dedicated thread that a stop event wakes.

use std::{
    io, mem,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle},
    path::Path,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_IO_PENDING, ERROR_PIPE_BUSY,
        ERROR_PIPE_CONNECTED, ERROR_PRIVILEGE_NOT_HELD, GetLastError, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FlushFileBuffers, PIPE_ACCESS_DUPLEX,
        ReadFile, SYNCHRONIZE, WriteFile,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
            GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeW,
        },
        Threading::{
            CreateEventW, CreateMutexW, INFINITE, OpenProcess, SetEvent, WaitForMultipleObjects,
            WaitForSingleObject,
        },
    },
};

use super::{Command, MESSAGE_TAG, instance_pipe_name, mutex_name};
use crate::{Error, Result};

/// Byte-mode commands are a fixed two-byte frame; the buffers only need to hold one.
const BUFFER_SIZE: u32 = 256;
/// The first instance may hold the mutex but not have created the pipe yet.
const CONNECT_ATTEMPTS: u32 = 20;
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);
/// How long a second launch waits through a busy pipe before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// A client that connects and then says nothing must not hold the single listener hostage.
const READ_TIMEOUT_MS: u32 = 2_000;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
/// The server's reply once it has read a command, so a client knows it was taken.
const ACK: u8 = 1;

pub(super) struct Guard {
    stop: Arc<AtomicBool>,
    stop_event: Arc<OwnedHandle>,
    listener: Option<JoinHandle<()>>,
    _mutex: OwnedHandle,
}

/// What the serve thread owns: the pipe instance and the events it waits on.
struct Server {
    pipe: OwnedHandle,
    stop: Arc<AtomicBool>,
    stop_event: Arc<OwnedHandle>,
    io_event: OwnedHandle,
}

pub(super) fn acquire(
    dir: &Path,
    command: Command,
    activation_token: Option<&str>,
    on_command: impl Fn(Command, Option<String>) + Send + 'static,
) -> Result<Guard> {
    let _ = (dir, activation_token);
    let sid = vk_win::current_user_sid()?;
    let Some(mutex) = create_owned_mutex(&sid)? else {
        // The mutex can be held by a process that serves no pipe (another session's daemon, or a
        // squatter); that must not look like a successful hand-over.
        forward(&instance_pipe_name(&sid), command).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Vaultkeeper seems to be running but did not answer: {error}"),
            )
        })?;
        return Err(Error::AlreadyRunning);
    };
    let pipe_name = instance_pipe_name(&sid);
    // Created before the guard is returned, so the wake on drop can always connect to it.
    let pipe = create_server_pipe(&pipe_name, &sid)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_event = Arc::new(new_event()?);
    let server = Server {
        pipe,
        stop: Arc::clone(&stop),
        stop_event: Arc::clone(&stop_event),
        io_event: new_event()?,
    };
    let listener = std::thread::Builder::new()
        .name("vk-single-instance".into())
        .spawn(move || serve(&server, &on_command))?;
    Ok(Guard {
        stop,
        stop_event,
        listener: Some(listener),
        _mutex: mutex,
    })
}

/// `--quit`: asks the running daemon to quit and waits for its process to end. Nothing running
/// is success.
pub(super) fn quit_running(timeout: Duration) -> Result<()> {
    let sid = vk_win::current_user_sid()?;
    let pipe_name = instance_pipe_name(&sid);
    let deadline = Instant::now() + timeout;
    let mut last_error = None;
    for _ in 0..CONNECT_ATTEMPTS {
        if create_owned_mutex(&sid)?.is_some() {
            return Ok(());
        }
        match send(&pipe_name, Command::Quit.code()) {
            Ok(pid) => {
                let pid = i32::try_from(pid).unwrap_or(0);
                return if wait_for_exit(pid, deadline.saturating_duration_since(Instant::now())) {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Vaultkeeper accepted the quit request but is still running",
                    )
                    .into())
                };
            }
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(CONNECT_RETRY_DELAY);
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::other("no answer from the running Vaultkeeper"))
        .into())
}

pub(super) fn wait_for_exit(pid: i32, timeout: Duration) -> bool {
    let pid = u32::try_from(pid).unwrap_or(0);
    // SAFETY: SYNCHRONIZE only; a dead or non-existent pid yields a null handle.
    let process = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        return true;
    }
    // SAFETY: `OpenProcess` returned a handle this process owns.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: the handle is live for the wait.
    let waited = unsafe { WaitForSingleObject(process.as_raw_handle(), millis) };
    waited == WAIT_OBJECT_0
}

/// Creates the mutex; `None` means it already existed, so another daemon is running.
fn create_owned_mutex(sid: &str) -> Result<Option<OwnedHandle>> {
    let descriptor = vk_win::SecurityDescriptor::from_sddl(&vk_win::sddl::mutex(sid)?)?;
    let attributes = descriptor.as_attributes(false);

    let global = mutex_name(sid, true);
    match create_mutex(&global, &attributes) {
        Ok(outcome) => return Ok(outcome),
        Err(error) if is_os_error(&error, ERROR_PRIVILEGE_NOT_HELD) => {
            tracing::warn!("cannot create a Global\\ mutex; falling back to Local\\");
        }
        Err(error) if is_os_error(&error, ERROR_ACCESS_DENIED) => {
            return Err(io::Error::new(
                error.kind(),
                format!("another program owns the Vaultkeeper mutex {global}"),
            )
            .into());
        }
        Err(error) => return Err(error.into()),
    }

    let local = mutex_name(sid, false);
    match create_mutex(&local, &attributes) {
        Ok(outcome) => Ok(outcome),
        Err(error) if is_os_error(&error, ERROR_ACCESS_DENIED) => Err(io::Error::new(
            error.kind(),
            format!("another program owns the Vaultkeeper mutex {local}"),
        )
        .into()),
        Err(error) => Err(error.into()),
    }
}

/// `Ok(None)` when the mutex already existed. `CreateMutexW` reports that through `GetLastError`,
/// not a null handle, so the check runs after a successful call.
fn create_mutex(name: &str, attributes: &SECURITY_ATTRIBUTES) -> io::Result<Option<OwnedHandle>> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is NUL-terminated and `attributes` outlives the call; we do not request
    // initial ownership, so this process is only ever first when the mutex is new.
    let handle = unsafe { CreateMutexW(attributes, 0, wide.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateMutexW` returned a handle this process owns.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    // SAFETY: the last error is only meaningful immediately after the call that set it.
    let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    Ok((!already).then_some(handle))
}

fn create_server_pipe(name: &str, sid: &str) -> io::Result<OwnedHandle> {
    let descriptor = vk_win::SecurityDescriptor::from_sddl(&vk_win::sddl::pipe(sid)?)?;
    let attributes = descriptor.as_attributes(false);
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is NUL-terminated and `attributes` outlives the call. The first-instance flag
    // turns a name owned by another program into an error instead of attaching to its pipe.
    let handle = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            &raw const attributes,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        if is_os_error(&error, ERROR_ACCESS_DENIED) {
            return Err(io::Error::new(
                error.kind(),
                format!("another program is serving the Vaultkeeper pipe {name}"),
            ));
        }
        return Err(error);
    }
    // SAFETY: `CreateNamedPipeW` returned a handle this process owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn new_event() -> io::Result<OwnedHandle> {
    // SAFETY: null attributes and name; manual-reset, initially unsignaled.
    let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateEventW` returned a handle this process owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn serve(server: &Server, on_command: &impl Fn(Command, Option<String>)) {
    let pipe = server.pipe.as_raw_handle();
    while !server.stop.load(Ordering::Acquire) {
        let outcome = match accept(server) {
            Ok(()) => handle_client(server),
            Err(error) => {
                if server.stop.load(Ordering::Acquire) {
                    break;
                }
                tracing::warn!(error = %error, "single-instance ConnectNamedPipe failed");
                std::thread::sleep(ACCEPT_ERROR_BACKOFF);
                Ok(None)
            }
        };
        // SAFETY: every path, including a client that vanished or stalled, must disconnect the
        // instance before it waits for the next client.
        unsafe {
            DisconnectNamedPipe(pipe);
        }
        match outcome {
            Ok(Some(command)) => on_command(command, None),
            Ok(None) => {}
            Err(error) => tracing::debug!(error = %error, "bad single-instance message"),
        }
    }
}

fn accept(server: &Server) -> io::Result<()> {
    let pipe = server.pipe.as_raw_handle();
    // SAFETY: the pipe handle is live and `overlapped` outlives the wait inside `overlapped_io`.
    let result = overlapped_io(server, INFINITE, |overlapped| unsafe {
        ConnectNamedPipe(pipe, overlapped)
    });
    match result {
        // A client connected between creation (or the last disconnect) and this call.
        Err(error) if is_os_error(&error, ERROR_PIPE_CONNECTED) => Ok(()),
        other => other.map(drop),
    }
}

fn handle_client(server: &Server) -> io::Result<Option<Command>> {
    verify_client(&server.pipe)?;
    let command = read_command(server)?;
    if command.is_some()
        && let Err(error) = write_ack(server)
    {
        tracing::debug!(error = %error, "single-instance client left before the reply");
    }
    Ok(command)
}

/// Refuses a client that is not this exact executable in this session, so a same-user process
/// cannot stop or drive the daemon.
fn verify_client(pipe: &OwnedHandle) -> io::Result<()> {
    let mut client_pid = 0_u32;
    // SAFETY: the pipe handle is live and connected; `client_pid` is ours.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &raw mut client_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let own = vk_win::ImageIdentity::of_current_exe()?;
    let client = vk_win::ImageIdentity::of_pid(client_pid)?;
    let same_session = vk_win::process_session_id(client_pid)? == vk_win::current_session_id()?;
    if client == own && same_session {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the single-instance client is not this Vaultkeeper executable",
        ))
    }
}

fn read_command(server: &Server) -> io::Result<Option<Command>> {
    let mut message = [0_u8; 2];
    read_exact(server, &mut message)?;
    Ok(match message {
        [MESSAGE_TAG, code] => Command::from_code(code),
        _ => None,
    })
}

fn read_exact(server: &Server, mut buf: &mut [u8]) -> io::Result<()> {
    let pipe = server.pipe.as_raw_handle();
    let deadline = Instant::now() + Duration::from_millis(u64::from(READ_TIMEOUT_MS));
    while !buf.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let wait_ms = u32::try_from(remaining.as_millis().max(1)).unwrap_or(READ_TIMEOUT_MS);
        let len = u32::try_from(buf.len()).expect("command frames are tiny");
        let target = buf.as_mut_ptr();
        // SAFETY: `buf` stays borrowed, and `overlapped_io` does not return before the read has
        // completed or been cancelled and drained.
        let read = overlapped_io(server, wait_ms, |overlapped| unsafe {
            ReadFile(pipe, target.cast(), len, ptr::null_mut(), overlapped)
        })?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the single-instance client disconnected",
            ));
        }
        buf = &mut buf[usize::try_from(read).expect("u32 fits usize on 64-bit")..];
    }
    Ok(())
}

fn write_ack(server: &Server) -> io::Result<()> {
    let pipe = server.pipe.as_raw_handle();
    let reply = [ACK];
    // SAFETY: `reply` outlives the call, which drains the write before returning.
    overlapped_io(server, READ_TIMEOUT_MS, |overlapped| unsafe {
        WriteFile(pipe, reply.as_ptr(), 1, ptr::null_mut(), overlapped)
    })?;
    // SAFETY: the handle is live. DisconnectNamedPipe discards bytes the client has not read yet,
    // so wait until it has taken the reply.
    if unsafe { FlushFileBuffers(pipe) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Runs one overlapped operation to completion, the stop event or `timeout_ms`. An operation that
/// is abandoned is cancelled and drained before this returns, because the kernel may still touch
/// the caller's buffer and the `OVERLAPPED` until then.
fn overlapped_io(
    server: &Server,
    timeout_ms: u32,
    start: impl FnOnce(*mut OVERLAPPED) -> i32,
) -> io::Result<u32> {
    // SAFETY: `OVERLAPPED` is plain data and all-zero is its documented initial state.
    let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
    overlapped.hEvent = server.io_event.as_raw_handle();
    if start(&raw mut overlapped) == 0 {
        let error = io::Error::last_os_error();
        if !is_os_error(&error, ERROR_IO_PENDING) {
            return Err(error);
        }
    }
    let pipe = server.pipe.as_raw_handle();
    let events: [RawHandle; 2] = [
        server.io_event.as_raw_handle(),
        server.stop_event.as_raw_handle(),
    ];
    // SAFETY: both handles are live for the wait.
    let waited = unsafe { WaitForMultipleObjects(2, events.as_ptr(), 0, timeout_ms) };
    if waited != WAIT_OBJECT_0 {
        let abandoned = if waited == WAIT_OBJECT_0 + 1 {
            io::Error::from(io::ErrorKind::Interrupted)
        } else if waited == WAIT_TIMEOUT {
            io::Error::from(io::ErrorKind::TimedOut)
        } else {
            io::Error::last_os_error()
        };
        let mut drained = 0_u32;
        // SAFETY: the operation is still pending on this pipe and `overlapped`; cancelling it and
        // waiting for the result is what makes dropping both afterwards sound.
        unsafe {
            CancelIoEx(pipe, &raw const overlapped);
            GetOverlappedResult(pipe, &raw const overlapped, &raw mut drained, 1);
        }
        return Err(abandoned);
    }
    let mut transferred = 0_u32;
    // SAFETY: the event is signaled, so the operation has finished.
    if unsafe { GetOverlappedResult(pipe, &raw const overlapped, &raw mut transferred, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(transferred)
}

fn write_all(pipe: &OwnedHandle, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let mut written = 0_u32;
        // SAFETY: `buf` is readable, `written` is an out pointer and the handle is live.
        let ok = unsafe {
            WriteFile(
                pipe.as_raw_handle(),
                buf.as_ptr().cast(),
                u32::try_from(buf.len()).expect("command frames are tiny"),
                &raw mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            return Err(io::Error::other(
                "the single-instance write made no progress",
            ));
        }
        buf = &buf[usize::try_from(written).expect("u32 fits usize on 64-bit")..];
    }
    Ok(())
}

/// Waits for the server's reply; the server ends the connection without one for a client it
/// refused or could not read.
fn read_ack(pipe: &OwnedHandle) -> io::Result<()> {
    let mut reply = [0_u8; 1];
    let mut read = 0_u32;
    // SAFETY: `reply` is writable, `read` is an out pointer and the handle is live; the client
    // handle is not overlapped, so this read is synchronous.
    let ok = unsafe {
        ReadFile(
            pipe.as_raw_handle(),
            reply.as_mut_ptr(),
            1,
            &raw mut read,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if read == 1 && reply[0] == ACK {
        Ok(())
    } else {
        Err(io::Error::other(
            "the running instance did not take the command",
        ))
    }
}

fn forward(pipe_name: &str, command: Command) -> io::Result<()> {
    let mut last_error = None;
    for _ in 0..CONNECT_ATTEMPTS {
        match send(pipe_name, command.code()) {
            Ok(_) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(CONNECT_RETRY_DELAY);
    }
    let error = last_error.unwrap_or_else(|| io::Error::other("no attempt was made"));
    tracing::warn!(error = %error, "running instance did not accept the command");
    Err(error)
}

/// Delivers one command and returns the pid of the server that took it.
fn send(pipe_name: &str, code: u8) -> io::Result<u32> {
    let client = connect_client(pipe_name)?;
    let server_pid = verify_server(&client)?;
    write_all(&client, &[MESSAGE_TAG, code])?;
    read_ack(&client)?;
    Ok(server_pid)
}

/// Opens a client handle, waiting through the brief window where the first instance holds the mutex
/// but has not created the pipe yet.
fn connect_client(name: &str) -> io::Result<OwnedHandle> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        let error = match vk_win::open_pipe_client(name, false) {
            Ok(handle) => return Ok(handle),
            Err(error) => error,
        };
        if !is_os_error(&error, ERROR_PIPE_BUSY) {
            return Err(error);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(error);
        }
        let wait_ms =
            u32::try_from(remaining.as_millis().max(1)).expect("the remaining wait fits a u32");
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        if unsafe { WaitNamedPipeW(wide.as_ptr(), wait_ms) } == 0 {
            let wait_error = io::Error::last_os_error();
            if !is_os_error(&wait_error, ERROR_PIPE_BUSY) {
                return Err(wait_error);
            }
        }
    }
}

/// Refuses a server that is not this exact executable in this session. The pipe name is
/// SID-scoped, so a mismatch means a same-user process squatted the name or the daemon is stale.
fn verify_server(client: &OwnedHandle) -> io::Result<u32> {
    let mut server_pid = 0_u32;
    // SAFETY: the client handle is live and connected; `server_pid` is ours.
    if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &raw mut server_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let own = vk_win::ImageIdentity::of_current_exe()?;
    let server = vk_win::ImageIdentity::of_pid(server_pid)?;
    let same_session = vk_win::process_session_id(server_pid)? == vk_win::current_session_id()?;
    if server == own && same_session {
        return Ok(server_pid);
    }
    // The image path only picks the message: a stale build of our own binary is worth a restart
    // hint, anything else is refused outright.
    let same_path = match (
        vk_win::image_path_of_pid(server_pid),
        std::env::current_exe(),
    ) {
        (Ok(server_path), Ok(own_path)) => server_path == own_path,
        _ => false,
    };
    Err(if same_path {
        io::Error::other("Vaultkeeper was updated; restart it")
    } else {
        io::Error::other("another program is serving Vaultkeeper's pipe")
    })
}

fn is_os_error(error: &io::Error, code: u32) -> bool {
    error.raw_os_error() == i32::try_from(code).ok()
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let Some(thread) = self.listener.take() else {
            return;
        };
        // SAFETY: the event handle is live; signaling it ends any wait the thread is in.
        if unsafe { SetEvent(self.stop_event.as_raw_handle()) } == 0 {
            tracing::error!(error = %io::Error::last_os_error(), "could not stop the single-instance listener");
            return;
        }
        if thread.join().is_err() {
            tracing::error!("single-instance listener panicked");
        }
    }
}
