//! Read-only look at Windows' own "OpenSSH Authentication Agent" service.

use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE,
    SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STOPPED,
};

const SERVICE_NAME: &str = "ssh-agent";

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW or OpenServiceW and is closed exactly once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// Whether the `ssh-agent` service is running or starting; any failure to ask counts as no.
pub fn openssh_service_running() -> bool {
    // SAFETY: null machine and database names select the local active database.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return false;
    }
    let manager = ServiceHandle(manager);

    let name: Vec<u16> = SERVICE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `manager` is a live handle and `name` is NUL-terminated and outlives the call.
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        return false;
    }
    let service = ServiceHandle(service);

    let mut status = SERVICE_STATUS {
        dwServiceType: 0,
        dwCurrentState: SERVICE_STOPPED,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: `service` is a live handle with SERVICE_QUERY_STATUS and `status` is a local out
    // struct.
    let queried = unsafe { QueryServiceStatus(service.0, &raw mut status) };
    queried != 0 && status.dwCurrentState != SERVICE_STOPPED
}
