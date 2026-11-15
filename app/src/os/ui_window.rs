//! Which window the system's biometric prompt is parented to (Windows Hello needs its dialog in the
//! foreground, and only the UI process owns a window). The UI reads its own `HWND` here; the daemon
//! checks the one it receives against the UI child it spawned.

/// The handle to forward, or `None` when it must not be trusted: no UI child is known, or the
/// window does not belong to it. A peer that is allowed to talk to the daemon can still send any
/// number, and parenting the prompt to another process's window would put the dialog where that
/// process chooses.
#[cfg(any(windows, test))]
fn accept_window(
    hwnd: Option<u64>,
    ui_pid: Option<u32>,
    owner_pid: impl FnOnce(u64) -> Option<u32>,
) -> Option<u64> {
    let hwnd = hwnd?;
    let ui_pid = ui_pid?;
    (owner_pid(hwnd)? == ui_pid).then_some(hwnd)
}

#[cfg(windows)]
pub use windows::{
    allow_foreground, bring_to_front, clear_ui_pid, exclude_from_capture, set_capture_exclusion,
    set_ui_pid, trusted_parent_window, window_handle,
};

#[cfg(not(windows))]
pub const fn allow_foreground(_pid: u32) {}

#[cfg(not(windows))]
pub const fn bring_to_front(_window: &slint::Window) {}

#[cfg(not(windows))]
pub const fn exclude_from_capture(_window: &slint::Window) {}

#[cfg(not(windows))]
pub const fn set_capture_exclusion(_enabled: bool) {}

/// macOS has no parent window for the Touch ID sheet.
#[cfg(not(windows))]
#[must_use]
pub const fn trusted_parent_window(_requested: Option<u64>) -> Option<u64> {
    None
}

/// macOS has no parent window for the Touch ID sheet.
#[cfg(not(windows))]
#[must_use]
pub const fn window_handle(_window: &slint::Window) -> Option<u64> {
    None
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::c_void,
        ptr,
        sync::atomic::{AtomicBool, AtomicU32, Ordering},
    };

    use slint::winit_030::{
        WinitWindowAccessor,
        winit::raw_window_handle::{HasWindowHandle, RawWindowHandle},
    };
    use windows_sys::{
        Win32::{
            Foundation::{HWND, LPARAM},
            System::Threading::GetCurrentThreadId,
            UI::WindowsAndMessaging::{
                AllowSetForegroundWindow, EnumThreadWindows, GetWindowThreadProcessId, IsWindow,
                SetForegroundWindow, SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE,
            },
        },
        core::BOOL,
    };

    use super::accept_window;

    /// Zero is never a valid pid for a child process.
    static UI_PID: AtomicU32 = AtomicU32::new(0);

    pub fn set_ui_pid(pid: u32) {
        UI_PID.store(pid, Ordering::Release);
    }

    /// Only clears the pid it was set for, so a late exit of an old UI cannot erase its successor.
    pub fn clear_ui_pid(pid: u32) {
        let _ = UI_PID.compare_exchange(pid, 0, Ordering::AcqRel, Ordering::Acquire);
    }

    /// The Win32 handle of a Slint window; `None` before it has a native window.
    #[must_use]
    pub fn window_handle(window: &slint::Window) -> Option<u64> {
        window
            .with_winit_window(|winit| match winit.window_handle().ok()?.as_raw() {
                RawWindowHandle::Win32(handle) => u64::try_from(handle.hwnd.get()).ok(),
                _ => None,
            })
            .flatten()
    }

    /// Lets `pid` take the foreground; Windows grants that only to a process that holds it itself
    /// or was allowed by one that does.
    pub fn allow_foreground(pid: u32) {
        // SAFETY: takes a pid by value and has no memory effects.
        if unsafe { AllowSetForegroundWindow(pid) } == 0 {
            tracing::debug!(pid, "AllowSetForegroundWindow failed");
        }
    }

    /// A shown window does not take the foreground by itself when the user was in another app.
    pub fn bring_to_front(window: &slint::Window) {
        let Some(hwnd) = window_handle(window).and_then(|hwnd| usize::try_from(hwnd).ok()) else {
            return;
        };
        // SAFETY: the handle belongs to this process's live window; a stale one only fails.
        if unsafe { SetForegroundWindow(ptr::with_exposed_provenance_mut::<c_void>(hwnd)) } == 0 {
            tracing::debug!("SetForegroundWindow refused");
        }
    }

    /// Whether windows shown from now on are excluded from capture; mirrors the setting.
    static CAPTURE_HIDDEN: AtomicBool = AtomicBool::new(false);

    /// Applies the setting to the windows that are already open and to every one shown later. A
    /// toggle must take effect without reopening windows, and `WDA_NONE` has to be set back
    /// explicitly because the exclusion is a property of the window, not of the process.
    pub fn set_capture_exclusion(enabled: bool) {
        CAPTURE_HIDDEN.store(enabled, Ordering::Release);
        // SAFETY: the callback only reads its `LPARAM` flag and calls a thread-safe Win32 API on
        // handles the enumeration just produced; it outlives the synchronous call.
        unsafe {
            EnumThreadWindows(
                GetCurrentThreadId(),
                Some(apply_to_thread_window),
                LPARAM::from(enabled),
            );
        }
    }

    unsafe extern "system" fn apply_to_thread_window(hwnd: HWND, enabled: LPARAM) -> BOOL {
        set_affinity(hwnd, enabled != 0);
        1
    }

    /// Called when a window is shown; the native window only exists from then on.
    pub fn exclude_from_capture(window: &slint::Window) {
        if !CAPTURE_HIDDEN.load(Ordering::Acquire) {
            return;
        }
        if let Some(hwnd) = window_handle(window).and_then(|hwnd| usize::try_from(hwnd).ok()) {
            set_affinity(ptr::with_exposed_provenance_mut::<c_void>(hwnd), true);
        }
    }

    fn set_affinity(hwnd: HWND, hidden: bool) {
        let affinity = if hidden {
            WDA_EXCLUDEFROMCAPTURE
        } else {
            WDA_NONE
        };
        // SAFETY: takes a handle value and a flag; a stale or foreign handle only makes it fail.
        if unsafe { SetWindowDisplayAffinity(hwnd, affinity) } == 0 {
            tracing::debug!(hidden, "SetWindowDisplayAffinity failed");
        }
    }

    /// `requested` if it is a live window of the UI process this daemon spawned.
    #[must_use]
    pub fn trusted_parent_window(requested: Option<u64>) -> Option<u64> {
        let ui_pid = Some(UI_PID.load(Ordering::Acquire)).filter(|pid| *pid != 0);
        let accepted = accept_window(requested, ui_pid, owner_pid);
        if requested.is_some() && accepted.is_none() {
            tracing::warn!("ignoring a Hello parent window that is not the UI's");
        }
        accepted
    }

    fn owner_pid(hwnd: u64) -> Option<u32> {
        let hwnd = ptr::with_exposed_provenance_mut::<c_void>(usize::try_from(hwnd).ok()?);
        // SAFETY: `IsWindow` only inspects the handle value and is safe for stale or foreign ones.
        if unsafe { IsWindow(hwnd) } == 0 {
            return None;
        }
        let mut pid = 0_u32;
        // SAFETY: the out-param points at a live local; a handle that went stale in between makes
        // the call return 0 and leave `pid` at 0, which no spawned child has.
        let thread = unsafe { GetWindowThreadProcessId(hwnd, &raw mut pid) };
        (thread != 0 && pid != 0).then_some(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::accept_window;

    #[test]
    fn a_window_of_the_ui_child_is_accepted() {
        assert_eq!(accept_window(Some(7), Some(42), |_| Some(42)), Some(7));
    }

    #[test]
    fn a_window_of_another_process_is_ignored() {
        assert_eq!(accept_window(Some(7), Some(42), |_| Some(43)), None);
    }

    #[test]
    fn a_dead_window_is_ignored() {
        assert_eq!(accept_window(Some(7), Some(42), |_| None), None);
    }

    #[test]
    fn nothing_is_accepted_without_a_ui_child_or_a_request() {
        assert_eq!(accept_window(Some(7), None, |_| Some(42)), None);
        assert_eq!(
            accept_window(None, Some(42), |_| panic!("no lookup without a handle")),
            None
        );
    }
}
