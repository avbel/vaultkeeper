//! Windows single instance: a SID-scoped named mutex decides who is first; the winner serves
//! [`Command`]s on a machine-wide pipe. vk-platform has no Tokio, so this uses synchronous
//! `CreateNamedPipeW`/`ConnectNamedPipe` on a dedicated thread.

use std::{
    io,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
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
        ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_NO_DATA, ERROR_PIPE_BUSY,
        ERROR_PIPE_CONNECTED, ERROR_PRIVILEGE_NOT_HELD, GENERIC_READ, GENERIC_WRITE, GetLastError,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
        SYNCHRONIZE, WriteFile,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerProcessId,
            PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeW,
        },
        Threading::{CreateMutexW, OpenProcess, WaitForSingleObject},
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

pub(super) struct Guard {
    stop: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
    _mutex: OwnedHandle,
    pipe_name: String,
}

pub(super) fn acquire(
    dir: &Path,
    command: Command,
    on_command: impl Fn(Command) + Send + 'static,
) -> Result<Guard> {
    let _ = dir;
    let sid = vk_win::current_user_sid()?;
    let Some(mutex) = create_owned_mutex(&sid)? else {
        forward(&instance_pipe_name(&sid), command);
        return Err(Error::AlreadyRunning);
    };
    let pipe_name = instance_pipe_name(&sid);
    // Created before the guard is returned, so the wake on drop can always connect to it.
    let pipe = create_server_pipe(&pipe_name, &sid)?;
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let listener = std::thread::Builder::new()
        .name("vk-single-instance".into())
        .spawn(move || serve(&pipe, &serve_stop, &on_command))?;
    Ok(Guard {
        stop,
        listener: Some(listener),
        _mutex: mutex,
        pipe_name,
    })
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
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
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

fn serve(pipe: &OwnedHandle, stop: &AtomicBool, on_command: &impl Fn(Command)) {
    while !stop.load(Ordering::Acquire) {
        // SAFETY: the pipe handle is live; a null overlapped waits synchronously for a client.
        let connected = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), ptr::null_mut()) };
        if connected == 0 {
            let error = io::Error::last_os_error();
            if is_os_error(&error, ERROR_PIPE_CONNECTED) {
                // A client connected between creation and the first wait; read it as usual.
            } else if is_os_error(&error, ERROR_NO_DATA) {
                // A client connected and disconnected before we could read it.
                continue;
            } else {
                tracing::warn!(error = %error, "single-instance ConnectNamedPipe failed");
                continue;
            }
        }
        // The connection that unblocks us on shutdown must not be read as a command.
        if stop.load(Ordering::Acquire) {
            break;
        }
        match read_command(pipe) {
            Ok(Some(command)) => on_command(command),
            Ok(None) => tracing::debug!("ignored unknown single-instance message"),
            Err(error) => tracing::debug!(error = %error, "bad single-instance message"),
        }
        // SAFETY: the instance must be disconnected before it waits for the next client.
        unsafe {
            DisconnectNamedPipe(pipe.as_raw_handle());
        }
    }
}

fn read_command(pipe: &OwnedHandle) -> io::Result<Option<Command>> {
    let mut message = [0_u8; 2];
    read_exact(pipe, &mut message)?;
    Ok(match message {
        [MESSAGE_TAG, code] => Command::from_code(code),
        _ => None,
    })
}

fn read_exact(pipe: &OwnedHandle, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let mut read = 0_u32;
        // SAFETY: `buf` is writable, `read` is an out pointer and the handle is live; a null
        // overlapped makes this a synchronous read.
        let ok = unsafe {
            ReadFile(
                pipe.as_raw_handle(),
                buf.as_mut_ptr().cast(),
                u32::try_from(buf.len()).expect("command frames are tiny"),
                &raw mut read,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
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

fn forward(pipe_name: &str, command: Command) {
    let mut last_error = None;
    for _ in 0..CONNECT_ATTEMPTS {
        match send(pipe_name, command.code()) {
            Ok(()) => return,
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(CONNECT_RETRY_DELAY);
    }
    if let Some(error) = last_error {
        tracing::warn!(error = %error, "running instance did not accept the command");
    }
}

fn send(pipe_name: &str, code: u8) -> io::Result<()> {
    let client = connect_client(pipe_name)?;
    verify_server(&client)?;
    write_all(&client, &[MESSAGE_TAG, code])?;
    Ok(())
}

/// Opens a client handle, waiting through the brief window where the first instance holds the mutex
/// but has not created the pipe yet.
fn connect_client(name: &str) -> io::Result<OwnedHandle> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        // SAFETY: `wide` is NUL-terminated and outlives the call. Named-pipe clients need an
        // exclusive share mode, and this handle must not be inherited.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            // SAFETY: `CreateFileW` returned a handle this process owns.
            return Ok(unsafe { OwnedHandle::from_raw_handle(handle) });
        }
        let error = io::Error::last_os_error();
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
fn verify_server(client: &OwnedHandle) -> io::Result<()> {
    let mut server_pid = 0_u32;
    // SAFETY: the client handle is live and connected; `server_pid` is ours.
    if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &raw mut server_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let own = vk_win::ImageIdentity::of_current_exe()?;
    let server = vk_win::ImageIdentity::of_pid(server_pid)?;
    let same_session = vk_win::process_session_id(server_pid)? == vk_win::current_session_id()?;
    if server == own && same_session {
        return Ok(());
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

/// Connects to the pipe and drops the handle, which unblocks the listener's `ConnectNamedPipe` so
/// the serve thread can observe the stop flag and exit.
fn wake(pipe_name: &str) {
    let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        tracing::warn!(
            error = %io::Error::last_os_error(),
            "could not wake the single-instance listener"
        );
        return;
    }
    // SAFETY: `CreateFileW` returned a handle this process owns.
    drop(unsafe { OwnedHandle::from_raw_handle(handle) });
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
        // ConnectNamedPipe only returns on a connection; connect once so the thread wakes and sees
        // the stop flag.
        wake(&self.pipe_name);
        if thread.join().is_err() {
            tracing::error!("single-instance listener panicked");
        }
    }
}
