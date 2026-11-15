//! The daemon-to-UI channel on Windows: a pipe the daemon creates, opens the client end of and
//! hands to the UI process it spawns, so no name has to be trusted
//! (`docs/solutions/windows-support.md` §5.2).

use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle},
    ptr,
};

use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Security::{
        Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        Pipes::GetNamedPipeClientProcessId,
    },
};

use super::{
    ui_pipe_name,
    windows::{Stream, credentials},
};

/// Names tried before giving up: a failed attempt means a same-user process connected to the
/// pipe between its creation and our open, which does not repeat by accident.
const ATTEMPTS: usize = 4;

/// What the UI is granted on its end. Writing needs `FILE_WRITE_DATA`, not the generic write
/// right: that one includes `FILE_CREATE_PIPE_INSTANCE`, which the pipe DACL withholds.
const CLIENT_ACCESS: u32 = vk_win::PIPE_CLIENT_ACCESS;

/// A pipe with its server end and an inheritable client end, until the launcher has spawned the UI
/// process that takes the client end over.
pub struct UiPipe {
    server: NamedPipeServer,
    client: Option<OwnedHandle>,
}

impl UiPipe {
    /// Creates the pipe and the UI's end, and checks the connection on the server end is ours.
    /// Must run inside the Tokio runtime that will serve the pipe.
    pub fn create() -> io::Result<Self> {
        let sid = vk_win::current_user_sid()?;
        let sddl = vk_win::sddl::pipe(&sid)?;
        for _ in 0..ATTEMPTS {
            let name = ui_pipe_name(random_bytes()?);
            if let Some(pipe) = try_create(&name, &sddl)? {
                return Ok(pipe);
            }
            tracing::warn!(
                "another process connected to the UI pipe first; retrying with a new name"
            );
        }
        Err(io::Error::other(
            "cannot open a UI pipe nobody else connects to",
        ))
    }

    /// The handle value to pass in the child's handle list.
    #[must_use]
    pub fn client_handle(&self) -> Option<RawHandle> {
        self.client.as_ref().map(OwnedHandle::as_raw_handle)
    }

    /// Closes the daemon's copy of the client end; call it once the child has been created, since
    /// the child holds its own by then.
    pub fn close_client(&mut self) {
        drop(self.client.take());
    }

    /// The server end, to serve as the UI connection.
    #[must_use]
    pub fn into_stream(self) -> Stream {
        // The client was open before the first read: a pipe instance whose client is already
        // connected is in the connected state without `ConnectNamedPipe`.
        Stream::server(self.server)
    }
}

/// `None` when the connected process on the server end is not us.
fn try_create(name: &str, sddl: &str) -> io::Result<Option<UiPipe>> {
    let descriptor = vk_win::SecurityDescriptor::from_sddl(sddl)?;
    let mut attributes = descriptor.as_attributes(false);
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1);
    // SAFETY: `attributes` is a live, initialised SECURITY_ATTRIBUTES whose descriptor is
    // `descriptor`; both outlive the call.
    let server =
        unsafe { options.create_with_security_attributes_raw(name, (&raw mut attributes).cast()) }?;
    let client = open_inheritable_client(name)?;

    let mut client_pid = 0_u32;
    // SAFETY: the server handle is live and its client just connected; `client_pid` is ours.
    if unsafe { GetNamedPipeClientProcessId(server.as_raw_handle(), &raw mut client_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if client_pid != std::process::id() {
        return Ok(None);
    }
    Ok(Some(UiPipe {
        server,
        client: Some(client),
    }))
}

fn open_inheritable_client(name: &str) -> io::Result<OwnedHandle> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES is far below 4 GiB"),
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: `wide` is NUL-terminated and `attributes` is initialised; both outlive the call.
    // Overlapped, because tokio only accepts overlapped pipe handles.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            CLIENT_ACCESS,
            0,
            &raw const attributes,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateFileW` returned a fresh handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn random_bytes() -> io::Result<[u8; 16]> {
    let mut bytes = [0_u8; 16];
    // SAFETY: the buffer is valid for 16 bytes; a null algorithm with the system-preferred flag is
    // the documented way to ask the OS CSPRNG.
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            16,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "the OS random generator failed: NTSTATUS {status:#x}"
        )));
    }
    Ok(bytes)
}

/// Takes over the pipe handle the daemon passed with `--ui-pipe`, after checking that this
/// process was started by our own executable and that the pipe's server is that process.
///
/// Anything else could be a same-user program that started `--ui --ui-pipe <its own pipe>` to
/// receive the master password. Returns the stream and the daemon's pid.
///
/// Must run inside the Tokio runtime that will drive the pipe.
///
/// # Safety
///
/// `handle` must be a handle this process owns and nothing else uses, such as one inherited
/// through the process handle list; it is closed when the returned stream drops.
pub unsafe fn adopt_ui_pipe(handle: usize) -> io::Result<(Stream, u32)> {
    let raw = handle as RawHandle;
    let parent = parent_process_id()?;
    let server_pid = u32::try_from(credentials(raw, true)?.pid)
        .map_err(|_| io::Error::other("the pipe server's pid is negative"))?;
    if server_pid != parent {
        return Err(io::Error::other(
            "the UI pipe is not served by the process that started this one",
        ));
    }
    if vk_win::ImageIdentity::of_pid(parent)? != vk_win::ImageIdentity::of_current_exe()? {
        return Err(io::Error::other(
            "the process that started this UI is not this Vaultkeeper executable",
        ));
    }
    // SAFETY: the caller guarantees sole ownership of `handle`; the checks above proved it is a
    // pipe whose server is the daemon.
    let client = unsafe { NamedPipeClient::from_raw_handle(raw) }?;
    Ok((Stream::client(client), server_pid))
}

/// The pid of the process that created this one, from the process snapshot.
fn parent_process_id() -> io::Result<u32> {
    let own = std::process::id();
    // SAFETY: a plain snapshot request with no pointers.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateToolhelp32Snapshot` returned a fresh handle that nothing else owns.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>())
            .expect("PROCESSENTRY32W is far below 4 GiB"),
        ..PROCESSENTRY32W::default()
    };
    // SAFETY: the snapshot is live and `entry.dwSize` is set, as both calls require.
    let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    while more {
        if entry.th32ProcessID == own {
            return Ok(entry.th32ParentProcessID);
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    }
    Err(io::Error::other("this process is not in the process list"))
}
