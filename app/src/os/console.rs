//! Windows: gives the CLI a terminal to print to. The manifest's detached console policy starts
//! the process with no console at all, so a command run from a shell would print into nothing
//! unless it joins the shell's console itself (docs/solutions/windows-support.md §7.11).

/// Joins the parent's console and points any std output handle that is missing at it. Handles the
/// shell redirected (`| cmd`, `> file`) are valid already and stay untouched.
#[cfg(windows)]
pub fn attach_parent_console() {
    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };

    let missing: Vec<_> = [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
        .into_iter()
        .filter(|&which| !is_usable(which))
        .collect();
    if missing.is_empty() {
        return;
    }
    // SAFETY: takes a process id constant and has no pointer arguments; failure (no parent
    // console, for example when started from Explorer) just leaves the process without output.
    if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } == 0 {
        return;
    }
    for which in missing {
        reopen(which);
    }
}

#[cfg(windows)]
fn is_usable(which: u32) -> bool {
    use windows_sys::Win32::{Foundation::INVALID_HANDLE_VALUE, System::Console::GetStdHandle};

    // SAFETY: reads one of the process's own standard handles.
    let handle = unsafe { GetStdHandle(which) };
    !handle.is_null() && handle != INVALID_HANDLE_VALUE
}

#[cfg(windows)]
fn reopen(which: u32) {
    use std::{fs::OpenOptions, os::windows::io::IntoRawHandle as _};

    use windows_sys::Win32::System::Console::SetStdHandle;

    let Ok(console) = OpenOptions::new().read(true).write(true).open("CONOUT$") else {
        return;
    };
    // Rust's stdout and stderr look the handle up on every write; the process keeps this one open
    // for as long as it runs.
    let raw = console.into_raw_handle();
    // SAFETY: `raw` is a console handle this process owns and never closes.
    unsafe { SetStdHandle(which, raw.cast()) };
}

#[cfg(not(windows))]
pub const fn attach_parent_console() {}
