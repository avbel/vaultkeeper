//! Win32 wrappers for the SID and security-descriptor helpers this step introduces. Each `unsafe`
//! call carries its own SAFETY note; handles are owned by `OwnedHandle` or freed by `LocalFree`.

use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt as _, OsStringExt as _},
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
    sync::OnceLock,
};

use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ID_128, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING,
    },
    System::{
        RemoteDesktop::ProcessIdToSessionId,
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
            PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        },
    },
};

use crate::identity::ImageIdentity;

// The struct is a few dozen bytes, so the cast cannot truncate.
#[expect(clippy::cast_possible_truncation)]
const SECURITY_ATTRIBUTES_LEN: u32 = size_of::<SECURITY_ATTRIBUTES>() as u32;
// `FILE_ID_INFO` is 24 bytes, so the cast cannot truncate.
#[expect(clippy::cast_possible_truncation)]
const FILE_ID_INFO_LEN: u32 = size_of::<FILE_ID_INFO>() as u32;

/// The current user's SID as `S-1-…` text, read from the process token.
pub fn current_user_sid() -> io::Result<String> {
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no closing and is valid for
    // the lifetime of the process.
    let process = unsafe { GetCurrentProcess() };

    let mut raw = ptr::null_mut();
    // SAFETY: `process` is a valid handle; `raw` is an out pointer we own.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `OpenProcessToken` returned a handle this process owns, so `OwnedHandle` may close
    // it once `token` drops.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };

    let mut needed = 0_u32;
    // SAFETY: a null buffer with a zero length queries the required size and only writes `needed`.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            ptr::null_mut(),
            0,
            &raw mut needed,
        );
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }

    // `Vec<u64>` keeps the buffer 8-byte aligned, which the `TOKEN_USER` header requires; the SID
    // it points at sits inside the same allocation.
    let mut buffer = vec![
        0_u64;
        usize::try_from(needed)
            .expect("u32 fits in usize on 64-bit")
            .div_ceil(size_of::<u64>())
    ];
    // SAFETY: `buffer` is at least `needed` bytes and correctly aligned; the call writes at most
    // `needed` bytes into it.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the call succeeded, so `buffer` starts with a `TOKEN_USER` whose `Sid` points into
    // the buffer; both stay valid until `buffer` drops.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_to_string(user.User.Sid)
}

/// The session the current process runs in (the console/RDP session number).
pub fn current_session_id() -> io::Result<u32> {
    // SAFETY: `GetCurrentProcessId` takes no arguments.
    process_session_id(unsafe { GetCurrentProcessId() })
}

/// The session `pid` runs in (the console/RDP session number).
pub fn process_session_id(pid: u32) -> io::Result<u32> {
    let mut session = 0_u32;
    // SAFETY: `pid` is caller-supplied and `session` is an out pointer we own; the call reports a
    // dead pid with a zero return rather than touching invalid memory.
    if unsafe { ProcessIdToSessionId(pid, &raw mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(session)
}

impl ImageIdentity {
    /// Identity of the running executable.
    ///
    /// Resolved once and cached: a rename of the running exe followed by a planted file at the
    /// same path must not change what "our own exe" means mid-run.
    pub fn of_current_exe() -> io::Result<Self> {
        static CURRENT: OnceLock<io::Result<ImageIdentity>> = OnceLock::new();
        match CURRENT.get_or_init(|| {
            let path = std::env::current_exe()?;
            Self::of_path(&path)
        }) {
            Ok(identity) => Ok(*identity),
            // `io::Error` is not `Copy`, so hand back an equivalent error for the cached failure.
            Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
        }
    }

    /// Identity of the executable behind `pid`, read from the image path the kernel reports.
    pub fn of_pid(pid: u32) -> io::Result<Self> {
        Self::of_path(&image_path_of_pid(pid)?)
    }

    /// Identity of the file at `path`, for callers that hold a path rather than a pid.
    pub fn of_path(path: &Path) -> io::Result<Self> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is NUL-terminated and lives for the call; opening attributes only does
        // not need write access, and share-all lets the loader and an update proceed alongside.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `CreateFileW` returned a handle this process owns; `OwnedHandle` closes it.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };

        let mut info = FILE_ID_INFO {
            VolumeSerialNumber: 0,
            FileId: FILE_ID_128 {
                Identifier: [0; 16],
            },
        };
        // SAFETY: the handle is valid and `info` outlives the call with the exact size the class
        // expects.
        if unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle().cast(),
                FileIdInfo,
                (&raw mut info).cast::<c_void>(),
                FILE_ID_INFO_LEN,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            volume_serial: info.VolumeSerialNumber,
            file_id: info.FileId.Identifier,
        })
    }
}

/// The full Win32 path of the executable image `pid` is running.
pub fn image_path_of_pid(pid: u32) -> io::Result<PathBuf> {
    // SAFETY: `OpenProcess` reports failure with a null handle for a pid that is gone or not
    // ours.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `OpenProcess` returned a handle this process owns.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };

    let mut buffer = vec![0_u16; 260];
    loop {
        let mut len = u32::try_from(buffer.len()).expect("buffer length fits in u32");
        // SAFETY: `buffer` is writable for `len` UTF-16 units and the handle is valid.
        if unsafe {
            QueryFullProcessImageNameW(
                process.as_raw_handle().cast(),
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                &raw mut len,
            )
        } != 0
        {
            let len = usize::try_from(len).expect("u32 fits in usize on 64-bit");
            return Ok(std::ffi::OsString::from_wide(&buffer[..len]).into());
        }

        let error = io::Error::last_os_error();
        let too_small =
            i32::try_from(ERROR_INSUFFICIENT_BUFFER).expect("Win32 error codes fit in i32");
        if error.raw_os_error() != Some(too_small) {
            return Err(error);
        }
        let grown = buffer.len() * 2;
        buffer.resize(grown, 0);
    }
}

/// An owned security descriptor allocated by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW` and freed with `LocalFree` on drop.
pub struct SecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
}

// SAFETY: the descriptor is immutable once created and owned exclusively, so it may cross threads.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: sharing the pointer only ever reads it.
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    /// Parses an SDDL string into an owned descriptor.
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = ptr::null_mut();
        let mut size = 0_u32;
        // SAFETY: `wide` is NUL-terminated and lives for the call; the two out pointers are ours.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                &raw mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { descriptor })
    }

    /// Wraps the descriptor for a `Create*` call, setting whether child processes inherit it.
    #[must_use]
    pub fn as_attributes(&self, inherit: bool) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: SECURITY_ATTRIBUTES_LEN,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: i32::from(inherit),
        }
    }

    /// The raw descriptor pointer, for callers that need it without the attributes wrapper.
    #[must_use]
    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.descriptor
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: the pointer came from `ConvertStringSecurityDescriptorToSecurityDescriptorW`,
            // which allocates with `LocalAlloc`, so `LocalFree` is the matching deallocator.
            unsafe {
                LocalFree(self.descriptor);
            }
        }
    }
}

fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text = ptr::null_mut();
    // SAFETY: `sid` points into a live buffer; `text` is an out pointer the call fills with a
    // LocalAlloc'd NUL-terminated string.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `text` is a NUL-terminated UTF-16 string.
    let result = unsafe { from_wide(text) };
    // SAFETY: `LocalFree` matches the allocation `ConvertSidToStringSidW` made.
    unsafe {
        LocalFree(text.cast::<c_void>());
    }
    Ok(result)
}

/// SAFETY: `text` must point to a NUL-terminated UTF-16 string.
unsafe fn from_wide(text: *const u16) -> String {
    let mut len = 0;
    // SAFETY: the string is NUL-terminated, so this loop terminates within its allocation.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `text..text+len` is a valid, in-bounds slice of the allocation.
    let slice = unsafe { std::slice::from_raw_parts(text, len) };
    String::from_utf16_lossy(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_exe_identity_is_stable_and_matches_of_pid() {
        let own = ImageIdentity::of_current_exe().expect("current exe identity");
        assert_eq!(own, ImageIdentity::of_current_exe().expect("cached"));

        // SAFETY: `GetCurrentProcessId` takes no arguments.
        let pid = unsafe { GetCurrentProcessId() };
        assert_eq!(
            own,
            ImageIdentity::of_pid(pid).expect("identity of own pid")
        );
        assert_eq!(
            current_session_id().expect("current session"),
            process_session_id(pid).expect("session of own pid")
        );
    }

    #[test]
    fn of_pid_rejects_a_missing_process() {
        assert!(ImageIdentity::of_pid(0).is_err());
    }
}
