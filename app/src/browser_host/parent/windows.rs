//! Gathers the process records for `chain` and checks the parent's Authenticode signer.

use std::{
    collections::HashMap,
    io,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
};

use vk_ipc::browser::protocol::ParentInfo;
use windows_sys::Win32::{
    Foundation::{FILETIME, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            GetCurrentProcessId, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

use super::chain::{ProcessRecord, browser_for_signer, select_parent};
use crate::cli::HostCaller;

pub fn identify(caller: &HostCaller) -> ParentInfo {
    let unknown = ParentInfo {
        pid: 0,
        executable: String::new(),
        browser: None,
    };
    let snapshot = match snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::warn!(%error, "cannot list processes");
            return unknown;
        }
    };
    // SAFETY: takes no arguments and cannot fail.
    let own_pid = unsafe { GetCurrentProcessId() };
    let find = |pid| record(&snapshot, pid);
    let Some(parent) = find(own_pid).and_then(|own| select_parent(&own, find)) else {
        return unknown;
    };
    let path = match vk_win::image_path_of_pid(parent.pid) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(%error, pid = parent.pid, "cannot read the parent's image path");
            return unknown;
        }
    };
    let browser = match vk_win::authenticode::signer_subject(&path) {
        Ok(Some(signer)) => browser_for_signer(&signer, caller),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, "cannot check the parent's signature");
            None
        }
    };
    ParentInfo {
        pid: i32::try_from(parent.pid).unwrap_or(0),
        executable: path.to_string_lossy().into_owned(),
        browser,
    }
}

struct Entry {
    parent_pid: u32,
    name: String,
}

fn snapshot() -> io::Result<HashMap<u32, Entry>> {
    // SAFETY: a process snapshot takes no pointers; failure is reported as INVALID_HANDLE_VALUE.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateToolhelp32Snapshot` returned a handle this process owns.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };

    // SAFETY: PROCESSENTRY32W is plain data for which all-zero is valid.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap_or(u32::MAX);
    let mut processes = HashMap::new();
    // SAFETY: the handle is a live snapshot and `entry.dwSize` is set.
    let mut more = unsafe { Process32FirstW(handle.as_raw_handle(), &raw mut entry) } != 0;
    while more {
        let len = entry
            .szExeFile
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(entry.szExeFile.len());
        processes.insert(
            entry.th32ProcessID,
            Entry {
                parent_pid: entry.th32ParentProcessID,
                name: String::from_utf16_lossy(&entry.szExeFile[..len]),
            },
        );
        // SAFETY: same handle and entry as above.
        more = unsafe { Process32NextW(handle.as_raw_handle(), &raw mut entry) } != 0;
    }
    Ok(processes)
}

fn record(snapshot: &HashMap<u32, Entry>, pid: u32) -> Option<ProcessRecord> {
    let entry = snapshot.get(&pid)?;
    Some(ProcessRecord {
        pid,
        parent_pid: entry.parent_pid,
        created: creation_time(pid).ok()?,
        name: entry.name.clone(),
    })
}

fn creation_time(pid: u32) -> io::Result<u64> {
    // SAFETY: `OpenProcess` reports failure with a null handle.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `OpenProcess` returned a handle this process owns.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: the handle is valid and all four out-pointers refer to live FILETIMEs.
    let ok = unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}
