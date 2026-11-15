//! A transparent, topmost window the daemon owns, so the Windows Hello dialog has an owner to
//! come up in front of when no UI window exists (a silent browser fill with the daemon alone).

use std::{
    ptr,
    sync::mpsc,
    thread::{self, JoinHandle},
};

use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, WPARAM},
    System::Threading::GetCurrentThreadId,
    UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, DispatchMessageW, GetMessageW, MSG, PostThreadMessageW,
        SW_SHOWNOACTIVATE, SetForegroundWindow, SetLayeredWindowAttributes, ShowWindow,
        TranslateMessage, WM_QUIT, WS_EX_LAYERED, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
    },
};

const LWA_ALPHA: u32 = 0x2;

pub(super) struct OwnerWindow {
    hwnd: usize,
    thread_id: u32,
    thread: Option<JoinHandle<()>>,
}

impl OwnerWindow {
    pub(super) fn create() -> Option<Self> {
        let (ready, created) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("hello-owner".to_owned())
            .spawn(move || run(&ready))
            .ok()?;
        if let Ok(Some((hwnd, thread_id))) = created.recv() {
            Some(Self {
                hwnd,
                thread_id,
                thread: Some(thread),
            })
        } else {
            let _ = thread.join();
            None
        }
    }

    pub(super) const fn hwnd(&self) -> usize {
        self.hwnd
    }
}

impl Drop for OwnerWindow {
    fn drop(&mut self) {
        // SAFETY: posts WM_QUIT to the message loop of the thread this value created.
        unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, 0 as WPARAM, 0 as LPARAM) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// The window lives on the thread that pumps its messages: an unpumped window is flagged as not
// responding and the system dialog would not treat it as a usable owner.
fn run(ready: &mpsc::Sender<Option<(usize, u32)>>) {
    let class: Vec<u16> = "STATIC\0".encode_utf16().collect();
    // SAFETY: `class` is NUL-terminated and outlives the call; every other argument is a plain
    // value or null, which `CreateWindowExW` accepts for a parentless popup.
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_LAYERED,
            class.as_ptr(),
            ptr::null(),
            WS_POPUP,
            0,
            0,
            1,
            1,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
        )
    };
    if hwnd.is_null() {
        let _ = ready.send(None);
        return;
    }
    // SAFETY: `hwnd` is the live window created above, owned by this thread.
    unsafe {
        SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        SetForegroundWindow(hwnd);
    }
    // SAFETY: no arguments.
    let thread_id = unsafe { GetCurrentThreadId() };
    if ready.send(Some((hwnd.addr(), thread_id))).is_err() {
        destroy(hwnd);
        return;
    }
    // SAFETY: `message` is a live local; a null window handle reads this thread's queue.
    unsafe {
        let mut message: MSG = std::mem::zeroed();
        while GetMessageW(&raw mut message, ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&raw const message);
            DispatchMessageW(&raw const message);
        }
    }
    destroy(hwnd);
}

fn destroy(hwnd: HWND) {
    // SAFETY: the window belongs to the calling thread.
    unsafe { DestroyWindow(hwnd) };
}
