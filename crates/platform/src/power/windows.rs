//! Windows half of [`super::subscribe`]: a hidden top-level window on its own thread receives the
//! three kinds of notification the daemon needs, because all of them arrive as window messages.
//! It is top-level because message-only windows are not sent `WM_QUERYENDSESSION` or
//! `WM_ENDSESSION`; it is never shown, so the daemon stays windowless from Slint's view.
//!
//! Layout and rationale: docs/solutions/windows-support.md §7.3.

use std::{
    ffi::c_void,
    io, ptr,
    sync::{
        Condvar, Mutex, PoisonError,
        atomic::{AtomicIsize, Ordering},
        mpsc::Sender,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use tracing::warn;
use windows_sys::Win32::{
    Foundation::{ERROR_CLASS_ALREADY_EXISTS, HWND, LPARAM, LRESULT, WPARAM},
    System::{
        LibraryLoader::GetModuleHandleW,
        Power::{
            HPOWERNOTIFY, RegisterSuspendResumeNotification, UnregisterSuspendResumeNotification,
        },
        RemoteDesktop::{
            NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification,
            WTSUnRegisterSessionNotification,
        },
    },
    UI::WindowsAndMessaging::{
        CREATESTRUCTW, CreateWindowExW, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW, DestroyWindow,
        DispatchMessageW, GWLP_USERDATA, GetMessageW, GetWindowLongPtrW, MSG, PostMessageW,
        PostQuitMessage, RegisterClassW, SetWindowLongPtrW, TranslateMessage, UnregisterClassW,
        WM_CLOSE, WM_DESTROY, WM_ENDSESSION, WM_NCCREATE, WM_POWERBROADCAST, WM_QUERYENDSESSION,
        WM_WTSSESSION_CHANGE, WNDCLASSW,
    },
};

use super::PowerEvent;

/// How long `WM_ENDSESSION` waits for the daemon to lock and flush. Windows kills a process that
/// does not return from the message reasonably soon, so the wait must stay bounded.
const END_SESSION_WAIT: Duration = Duration::from_secs(5);

static END_SESSION_ACK: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

/// Called by the daemon once it has locked and flushed after [`PowerEvent::SessionEnding`], which
/// lets the blocked `WM_ENDSESSION` return.
pub(super) fn session_end_handled() {
    *END_SESSION_ACK
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = true;
    END_SESSION_ACK.1.notify_all();
}

fn wait_for_session_end_handled() {
    let (flag, condvar) = &END_SESSION_ACK;
    let guard = flag.lock().unwrap_or_else(PoisonError::into_inner);
    let _ = condvar
        .wait_timeout_while(guard, END_SESSION_WAIT, |handled| !*handled)
        .unwrap_or_else(PoisonError::into_inner);
}

/// Owns the watcher's window and thread; dropping posts `WM_CLOSE` and joins.
pub(super) struct Subscription {
    hwnd: AtomicIsize,
    thread: Option<JoinHandle<()>>,
}

impl Subscription {
    pub(super) fn new(tx: Sender<PowerEvent>) -> io::Result<Self> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = thread::Builder::new()
            .name("vaultkeeper-power".to_owned())
            .spawn(move || run(tx, &ready_tx))
            .map_err(|error| {
                io::Error::other(format!("cannot start the power watcher thread: {error}"))
            })?;
        match ready_rx.recv() {
            Ok(Ok(hwnd)) => Ok(Self {
                hwnd: AtomicIsize::new(hwnd),
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other(
                    "the power watcher thread exited before it was ready",
                ))
            }
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let hwnd = self.hwnd.load(Ordering::Relaxed);
        if hwnd != 0 {
            // SAFETY: `hwnd` is a valid window created by this watcher; WM_CLOSE makes its window
            // procedure destroy it and free the Sender, ending the message loop.
            unsafe {
                PostMessageW(hwnd as HWND, WM_CLOSE, 0, 0);
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(tx: Sender<PowerEvent>, ready: &Sender<io::Result<isize>>) {
    let Some((hwnd, class)) = create_window(tx, ready) else {
        return;
    };

    register_session(hwnd);
    let power = register_power(hwnd);
    let _ = ready.send(Ok(hwnd as isize));

    message_loop();

    if let Some(handle) = power {
        // SAFETY: `handle` came from RegisterSuspendResumeNotification and is released once.
        unsafe {
            UnregisterSuspendResumeNotification(handle);
        }
    }
    // SAFETY: if WM_CLOSE already destroyed the window this returns 0 harmlessly; otherwise it
    // runs WM_DESTROY, which frees the Sender.
    unsafe {
        DestroyWindow(hwnd);
    }
    // SAFETY: the class was registered at startup; unregistering while no window of it remains is
    // safe, and it is a no-op if a concurrent subscription still holds a window.
    unsafe {
        UnregisterClassW(class, GetModuleHandleW(ptr::null()));
    }
}

/// Registers the class and creates the hidden top-level window. Reports the hwnd (or the error) on
/// `ready`; returns `None` only after an error was already reported.
fn create_window(
    tx: Sender<PowerEvent>,
    ready: &Sender<io::Result<isize>>,
) -> Option<(HWND, *const u16)> {
    let instance = get_module();
    let class = windows_sys::w!("VaultkeeperPower");
    let wnd_class = WNDCLASSW {
        lpfnWndProc: Some(wnd_proc),
        hInstance: instance,
        lpszClassName: class,
        ..WNDCLASSW::default()
    };
    // SAFETY: `wnd_class` lives until the class is unregistered at the end of `run`.
    if unsafe { RegisterClassW(&raw const wnd_class) } == 0 {
        let error = io::Error::last_os_error();
        // A second subscription (or a repeated subscribe in tests) reuses the same class; that is
        // not an error, only a first registration is expected to succeed.
        if error.raw_os_error() != i32::try_from(ERROR_CLASS_ALREADY_EXISTS).ok() {
            let _ = ready.send(Err(error));
            return None;
        }
    }

    let sender = Box::into_raw(Box::new(tx));
    // SAFETY: `sender` is freed by WM_DESTROY on success; on failure it is freed just below.
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class,
            ptr::null(),
            0,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            sender.cast(),
        )
    };
    if hwnd.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: no window was created, so nothing else owns `sender`.
        unsafe {
            drop(Box::from_raw(sender));
        }
        let _ = ready.send(Err(error));
        return None;
    }
    Some((hwnd, class))
}

fn get_module() -> *mut c_void {
    // SAFETY: a null module name yields the running exe's module, which is always present.
    unsafe { GetModuleHandleW(ptr::null()) }
}

fn register_session(hwnd: HWND) {
    // SAFETY: `hwnd` is a live window created by this thread; the registration lasts until the
    // matching unregister in WM_DESTROY.
    if unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } != 0 {
        return;
    }
    warn!(
        error = %io::Error::last_os_error(),
        "no screen lock events; lock on screen lock is off"
    );
}

fn register_power(hwnd: HWND) -> Option<HPOWERNOTIFY> {
    // SAFETY: `hwnd` is a live window of this thread; the handle is unregistered in `run`.
    let handle = unsafe { RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE) };
    if handle == 0 {
        warn!(
            error = %io::Error::last_os_error(),
            "no sleep/wake events; lock on sleep is off"
        );
        return None;
    }
    Some(handle)
}

fn message_loop() {
    let mut message = MSG::default();
    loop {
        // SAFETY: `message` is a valid out-pointer for GetMessageW and is only read after it
        // returns a positive result.
        let result = unsafe { GetMessageW(&raw mut message, ptr::null_mut(), 0, 0) };
        match result {
            0 => break,
            -1 => {
                warn!(
                    error = %io::Error::last_os_error(),
                    "power watcher message loop failed"
                );
                break;
            }
            _ => {
                // SAFETY: `message` was filled by GetMessageW above.
                unsafe {
                    TranslateMessage(&raw const message);
                    DispatchMessageW(&raw const message);
                }
            }
        }
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_NCCREATE => {
            // SAFETY: `lparam` of WM_NCCREATE is a pointer to the CREATESTRUCTW whose
            // lpCreateParams we stored the Sender in.
            let create = unsafe { &*(lparam as *const CREATESTRUCTW) };
            // SAFETY: storing the Sender in the window's user data; read back on every event and
            // freed once in WM_DESTROY.
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize);
            }
            1
        }
        WM_WTSSESSION_CHANGE => {
            if let Some(event) = PowerEvent::from_session_change(wparam) {
                emit(hwnd, event);
            }
            0
        }
        WM_POWERBROADCAST => {
            if let Some(event) = PowerEvent::from_power_broadcast(wparam) {
                emit(hwnd, event);
            }
            1
        }
        WM_QUERYENDSESSION => 1,
        WM_ENDSESSION => {
            if wparam != 0 {
                // The process may be terminated as soon as this returns, so wait for the daemon.
                *END_SESSION_ACK
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = false;
                emit(hwnd, PowerEvent::SessionEnding);
                wait_for_session_end_handled();
            }
            0
        }
        WM_CLOSE => {
            // SAFETY: destroying the window runs WM_DESTROY, which frees the Sender and quits.
            unsafe {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            // Microsoft requires the unregister before the window is gone; for a window that was
            // never registered it fails harmlessly.
            // SAFETY: `hwnd` is still a valid window while WM_DESTROY runs.
            unsafe {
                WTSUnRegisterSessionNotification(hwnd);
            }
            // SAFETY: reading back the value installed in WM_NCCREATE.
            let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut Sender<PowerEvent>;
            if !raw.is_null() {
                // SAFETY: `raw` is the Sender installed in WM_NCCREATE; it is cleared here and
                // freed exactly once, so no later message can reach a dangling pointer.
                unsafe {
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    drop(Box::from_raw(raw));
                }
            }
            // SAFETY: ends this thread's message loop.
            unsafe {
                PostQuitMessage(0);
            }
            0
        }
        _ => {
            // SAFETY: delegating all unhandled messages is the standard window-procedure contract.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
    }
}

fn emit(hwnd: HWND, event: PowerEvent) {
    // SAFETY: GWLP_USERDATA holds the Sender until WM_DESTROY frees it; this runs on the window's
    // own thread, so the borrow cannot outlive the box.
    let sender =
        unsafe { (GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Sender<PowerEvent>).as_ref() };
    if let Some(sender) = sender {
        let _ = sender.send(event);
    }
}
