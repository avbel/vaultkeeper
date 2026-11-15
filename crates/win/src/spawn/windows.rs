//! `CreateProcessW` with a pre-set process DACL, an explicit handle list and mitigation policies.
//!
//! std's `Command::spawn_with_attributes` is still unstable, and even when it lands the UI process
//! must be locked down before its first instruction, so this talks to `CreateProcessW` directly.

use std::{
    ffi::{OsStr, c_void},
    future::Future,
    io,
    mem::size_of,
    os::windows::{
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle},
        process::ExitStatusExt as _,
    },
    path::Path,
    pin::Pin,
    process::ExitStatus,
    ptr,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    thread,
};

use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
        UpdateProcThreadAttribute, WaitForSingleObject,
    },
};

use crate::{SecurityDescriptor, spawn::command_line};

// `STARTUPINFOEXW` is far below 4 GiB, so the cast cannot truncate.
#[expect(clippy::cast_possible_truncation)]
const STARTUPINFOEXW_LEN: u32 = size_of::<STARTUPINFOEXW>() as u32;

/// What `spawn_hardened` changes compared with a plain `CreateProcessW`.
#[derive(Clone, Debug, Default)]
pub struct SpawnOptions {
    /// SDDL for the child's process DACL, normally `sddl::process(sid)`.
    pub process_sddl: Option<String>,
    /// SDDL for the child's initial thread, normally `sddl::thread(sid)`.
    pub thread_sddl: Option<String>,
    /// Handles the child inherits. Every handle must have been created inheritable.
    ///
    /// The handle list replaces default inheritance, so std handles must be listed explicitly when
    /// the child needs them; an empty list means `bInheritHandles` is false.
    pub inherit_handles: Vec<RawHandle>,
    /// `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` flags; zero adds no attribute.
    pub mitigation_policy: u64,
    /// Extra `CreateProcessW` creation flags. `CREATE_UNICODE_ENVIRONMENT` is always added.
    pub creation_flags: u32,
}

/// A spawned process owned by us, with the creation handle that keeps full access even after the
/// child's DACL is locked down.
pub struct Child {
    handle: Arc<OwnedHandle>,
    pid: u32,
}

impl Child {
    /// The new process's id.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Terminates the process.
    ///
    /// Works after hardening because the handle comes from creation and carries `PROCESS_ALL_ACCESS`,
    /// which a DACL on the process cannot revoke.
    pub fn kill(&self) -> io::Result<()> {
        // SAFETY: `handle` is a live process handle owned by this `Child`, and the exit code is
        // just a number the kernel stores.
        if unsafe { TerminateProcess(self.handle.as_raw_handle(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Waits for the process to exit without blocking the calling thread.
    #[must_use]
    pub fn wait(&self) -> Wait {
        Wait {
            handle: Some(Arc::clone(&self.handle)),
            state: Arc::new(Mutex::new(WaitState::Pending(None))),
        }
    }
}

/// Starts `exe` with `args`, applying `options` before the child runs.
pub fn spawn_hardened(
    exe: &Path,
    args: &[impl AsRef<OsStr>],
    options: &SpawnOptions,
) -> io::Result<Child> {
    let exe_wide = nul_terminated(exe.as_os_str());
    let mut command_line = command_line(exe.as_os_str(), args);

    let process_descriptor = options
        .process_sddl
        .as_deref()
        .map(SecurityDescriptor::from_sddl)
        .transpose()?;
    let thread_descriptor = options
        .thread_sddl
        .as_deref()
        .map(SecurityDescriptor::from_sddl)
        .transpose()?;
    let process_attributes = process_descriptor
        .as_ref()
        .map(|descriptor| descriptor.as_attributes(false));
    let thread_attributes = thread_descriptor
        .as_ref()
        .map(|descriptor| descriptor.as_attributes(false));

    let mut attributes = AttributeList::new(options)?;
    attributes.apply()?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = STARTUPINFOEXW_LEN;
    startup.lpAttributeList = attributes.list();

    let inherit = i32::from(!options.inherit_handles.is_empty());
    let flags = options.creation_flags | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;

    let mut process_info = PROCESS_INFORMATION::default();
    // SAFETY: both wide buffers are NUL-terminated and live for the call; the security attributes
    // (when present) point at descriptors owned until `spawn_hardened` returns; `startup` is the
    // extended struct `EXTENDED_STARTUPINFO_PRESENT` promises, and `process_info` is a fresh out
    // value. A null environment inherits ours, which is what every caller wants.
    let created = unsafe {
        CreateProcessW(
            exe_wide.as_ptr(),
            command_line.as_mut_ptr(),
            process_attributes
                .as_ref()
                .map_or(ptr::null(), ptr::from_ref),
            thread_attributes
                .as_ref()
                .map_or(ptr::null(), ptr::from_ref),
            inherit,
            flags,
            ptr::null(),
            ptr::null(),
            (&raw const startup).cast::<STARTUPINFOW>(),
            &raw mut process_info,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: on success `CreateProcessW` hands us both handles and they are ours to close.
    let process = unsafe { OwnedHandle::from_raw_handle(process_info.hProcess) };
    // SAFETY: as above; the primary thread is only closed, never used.
    drop(unsafe { OwnedHandle::from_raw_handle(process_info.hThread) });

    Ok(Child {
        handle: Arc::new(process),
        pid: process_info.dwProcessId,
    })
}

/// The attribute list buffer must stay put while the kernel reads it, so it is heap allocated and
/// only ever referenced by pointer. `UpdateProcThreadAttribute` stores the value pointers rather
/// than copying the values, so the policy and handle list live here until the list is deleted.
struct AttributeList {
    buffer: Vec<usize>,
    initialized: bool,
    policy: Box<u64>,
    handles: Box<[HANDLE]>,
}

impl AttributeList {
    fn new(options: &SpawnOptions) -> io::Result<Self> {
        let count = u32::from(options.mitigation_policy != 0)
            + u32::from(!options.inherit_handles.is_empty());
        if count == 0 {
            return Ok(Self {
                buffer: Vec::new(),
                initialized: false,
                policy: Box::new(0),
                handles: Box::default(),
            });
        }

        let mut required = 0_usize;
        // SAFETY: the documented sizing call takes a null list and writes only to `required`.
        let sized = unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &raw mut required)
        };
        if sized == 0 {
            let error = io::Error::last_os_error();
            let too_small =
                i32::try_from(ERROR_INSUFFICIENT_BUFFER).expect("Win32 error codes fit in i32");
            if error.raw_os_error() != Some(too_small) {
                return Err(error);
            }
        }
        if required == 0 {
            return Err(io::Error::other(
                "InitializeProcThreadAttributeList reported no size",
            ));
        }

        // `usize` keeps the buffer pointer-aligned, which the opaque attribute list needs.
        let mut buffer = vec![0_usize; required.div_ceil(size_of::<usize>())];
        // SAFETY: `buffer` is at least `required` bytes, aligned, and outlives the list.
        if unsafe {
            InitializeProcThreadAttributeList(
                buffer.as_mut_ptr().cast::<c_void>(),
                count,
                0,
                &raw mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            buffer,
            initialized: true,
            policy: Box::new(options.mitigation_policy),
            handles: options.inherit_handles.iter().copied().collect(),
        })
    }

    fn apply(&mut self) -> io::Result<()> {
        if *self.policy != 0 {
            // SAFETY: the list is initialized for two attributes at most, and `policy` is a boxed
            // 8-byte value owned by `self`, so its address stays valid until the list is deleted
            // in `Drop`, after `CreateProcessW` has read it.
            if unsafe {
                UpdateProcThreadAttribute(
                    self.list(),
                    0,
                    usize::try_from(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)
                        .expect("attribute ids fit in usize"),
                    (&raw const *self.policy).cast::<c_void>(),
                    size_of::<u64>(),
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }

        if !self.handles.is_empty() {
            let bytes = self.handles.len() * size_of::<HANDLE>();
            // SAFETY: the list is initialized, the boxed slice is owned by `self` and outlives the
            // list, and the byte count matches `HANDLE` elements.
            if unsafe {
                UpdateProcThreadAttribute(
                    self.list(),
                    0,
                    usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
                        .expect("attribute ids fit in usize"),
                    self.handles.as_ptr().cast::<c_void>(),
                    bytes,
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    fn list(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        if self.initialized {
            self.buffer.as_ptr().cast::<c_void>().cast_mut()
        } else {
            ptr::null_mut()
        }
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: the list was initialized and has not been deleted yet.
            unsafe {
                DeleteProcThreadAttributeList(self.list());
            }
        }
    }
}

/// A `WaitForSingleObject` running on a helper thread, woken through the future's waker. It keeps
/// `vk-win` free of an async runtime: both callers already have one, but this crate does not.
pub struct Wait {
    handle: Option<Arc<OwnedHandle>>,
    state: Arc<Mutex<WaitState>>,
}

enum WaitState {
    Pending(Option<Waker>),
    Done(io::Result<ExitStatus>),
}

impl Future for Wait {
    type Output = io::Result<ExitStatus>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut state = this.state.lock().expect("wait state poisoned");

        match &mut *state {
            WaitState::Done(_) => {
                let WaitState::Done(result) = std::mem::replace(
                    &mut *state,
                    WaitState::Done(Err(io::Error::other("process wait polled again"))),
                ) else {
                    unreachable!("just matched as Done");
                };
                Poll::Ready(result)
            }
            WaitState::Pending(waker) => {
                *waker = Some(cx.waker().clone());
                let Some(handle) = this.handle.take() else {
                    return Poll::Pending;
                };
                let shared = Arc::clone(&this.state);
                drop(state);

                let spawned = thread::Builder::new()
                    .name("vk-win-process-wait".to_owned())
                    .spawn(move || {
                        let result = wait_for(&handle);
                        let waker = {
                            let mut state = shared.lock().expect("wait state poisoned");
                            let waker = match &mut *state {
                                WaitState::Pending(waker) => waker.take(),
                                WaitState::Done(_) => None,
                            };
                            *state = WaitState::Done(result);
                            waker
                        };
                        if let Some(waker) = waker {
                            waker.wake();
                        }
                    });

                if let Err(error) = spawned {
                    let kind = error.kind();
                    *this.state.lock().expect("wait state poisoned") = WaitState::Done(Err(error));
                    return Poll::Ready(Err(io::Error::new(
                        kind,
                        "failed to start the process wait thread",
                    )));
                }
                Poll::Pending
            }
        }
    }
}

fn wait_for(handle: &OwnedHandle) -> io::Result<ExitStatus> {
    // SAFETY: the handle is a live process handle kept alive by the `Arc` the thread owns.
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), INFINITE) } {
        WAIT_OBJECT_0 => {}
        WAIT_FAILED => return Err(io::Error::last_os_error()),
        WAIT_TIMEOUT => return Err(io::Error::other("infinite wait timed out")),
        other => return Err(io::Error::other(format!("unexpected wait status {other}"))),
    }

    let mut code = 0_u32;
    // SAFETY: the process has signalled, the handle is live, and `code` is an out pointer.
    if unsafe { GetExitCodeProcess(handle.as_raw_handle(), &raw mut code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ExitStatus::from_raw(code))
}

fn nul_terminated(value: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;

    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: &str = r"C:\Windows\System32\cmd.exe";

    #[test]
    fn spawns_a_child_and_reports_its_exit_code() {
        let child = spawn_hardened(
            Path::new(CMD),
            &["/c", "exit", "3"],
            &SpawnOptions::default(),
        )
        .expect("spawn");

        assert_ne!(child.pid(), 0);
        let status = wait_for(&child.handle).expect("wait");
        assert_eq!(status.code(), Some(3));
    }

    #[test]
    fn spawns_with_a_mitigation_policy_and_a_handle_list() {
        use windows_sys::Win32::{Foundation::TRUE, Security::SECURITY_ATTRIBUTES};

        let inheritable = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("small"),
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: TRUE,
        };
        // SAFETY: the attributes are a live struct for the call and the name is null.
        let event = unsafe {
            windows_sys::Win32::System::Threading::CreateEventW(
                &raw const inheritable,
                1,
                0,
                ptr::null(),
            )
        };
        assert!(!event.is_null(), "{}", io::Error::last_os_error());
        // SAFETY: `event` is a fresh handle we own.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };

        let options = SpawnOptions {
            // PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE
            mitigation_policy: 0x1,
            inherit_handles: vec![event.as_raw_handle()],
            ..SpawnOptions::default()
        };
        let child = spawn_hardened(Path::new(CMD), &["/c", "exit", "0"], &options).expect("spawn");
        let status = wait_for(&child.handle).expect("wait");
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn the_creation_handle_can_still_kill_a_child_behind_the_process_dacl() {
        let sid = crate::current_user_sid().expect("user sid");
        let options = SpawnOptions {
            process_sddl: Some(crate::sddl::process(&sid).expect("process sddl")),
            thread_sddl: Some(crate::sddl::thread(&sid).expect("thread sddl")),
            ..SpawnOptions::default()
        };

        let child = spawn_hardened(
            Path::new(CMD),
            &["/c", "ping", "-n", "30", "127.0.0.1"],
            &options,
        )
        .expect("spawn");

        child.kill().expect("kill through the creation handle");
        let status = wait_for(&child.handle).expect("wait");
        assert!(!status.success());
    }
}
