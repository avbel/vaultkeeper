//! Auto-type on Windows with `SendInput`, driven by the same timer state machine as macOS.
//!
//! The `KEYEVENTF_UNICODE` down/up pairs and the check of `SendInput`'s inserted count follow
//! Bitwarden's desktop_native (`autotype/src/type_input/windows.rs`, GPL-3.0).
//!
//! The daemon reads the foreground window's process when the hotkey fires and the UI only gets the
//! pid, so the window to restore is the top-most visible window of that process: the foreground
//! window is the top-most one of all, hence also of its process.

use std::{cell::RefCell, mem, ptr, time::Instant};

use super::{
    HookError, Observed, Phase, Step, Stroke, TICK, TypingTarget,
    keys::{KeyEvent, events},
    step, stopped,
};
use crate::hooks::{AutoTypeDone, HookResult};
use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, HWND, LPARAM},
        System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        },
        UI::{
            Input::KeyboardAndMouse::{
                GetAsyncKeyState, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP,
                KEYEVENTF_UNICODE, SendInput, VK_CONTROL, VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT,
            },
            WindowsAndMessaging::{
                EnumWindows, GetForegroundWindow, GetWindowTextLengthW, GetWindowThreadProcessId,
                IsIconic, IsWindowVisible, SW_RESTORE, SetForegroundWindow, ShowWindow,
            },
        },
    },
    core::BOOL,
};

/// The reason shown when Windows refuses the input: UIPI drops it for a window of a higher
/// integrity level and `SendInput` then returns less than it was given.
const BLOCKED: &str = "Windows blocked the keystrokes; the app may be running as administrator";

/// One stroke goes out per timer tick, which lets the state machine notice a focus change between
/// characters.
struct Session {
    timer: slint::Timer,
    target: TypingTarget,
    strokes: Vec<Stroke>,
    phase: Phase,
    started: Instant,
    done: AutoTypeDone,
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

fn pid_of(hwnd: HWND) -> Option<u32> {
    let mut pid = 0_u32;
    // SAFETY: the out pointer is a live local; a stale handle makes the call return 0 and leave
    // `pid` at 0, which is filtered out.
    let thread = unsafe { GetWindowThreadProcessId(hwnd, &raw mut pid) };
    (thread != 0 && pid != 0).then_some(pid)
}

fn foreground_pid() -> Option<u32> {
    // SAFETY: no arguments; returns null when no window has the foreground.
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.is_null() {
        return None;
    }
    pid_of(hwnd)
}

/// The executable's file stem, which is what the user knows an app by.
fn process_name(pid: u32) -> Option<String> {
    // SAFETY: plain handle query; the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut buffer = [0_u16; 520];
    let mut len = u32::try_from(buffer.len()).unwrap_or(0);
    // SAFETY: `buffer` holds `len` units and the call writes at most that many; `process` is the
    // handle opened above.
    let ok = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &raw mut len) };
    // SAFETY: `process` was opened above and is closed once.
    unsafe { CloseHandle(process) };
    if ok == 0 {
        return None;
    }
    let path = String::from_utf16_lossy(buffer.get(..usize::try_from(len).ok()?)?);
    std::path::Path::new(&path)
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
}

pub(super) fn frontmost_any() -> Option<TypingTarget> {
    let pid = foreground_pid()?;
    let name = process_name(pid).unwrap_or_else(|| "The app".to_owned());
    Some(TypingTarget {
        pid: i32::try_from(pid).ok()?,
        name,
    })
}

pub(super) fn frontmost() -> Option<TypingTarget> {
    frontmost_any().filter(|target| u32::try_from(target.pid).ok() != Some(std::process::id()))
}

struct Lookup {
    pid: u32,
    found: HWND,
}

unsafe extern "system" fn first_of_pid(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: `lparam` is the `&mut Lookup` that `window_of` passed and that outlives the call.
    let lookup = unsafe { &mut *(lparam as *mut Lookup) };
    // SAFETY: both calls only inspect the handle `EnumWindows` handed in.
    let usable = unsafe { IsWindowVisible(hwnd) != 0 && GetWindowTextLengthW(hwnd) > 0 };
    if usable && pid_of(hwnd) == Some(lookup.pid) {
        lookup.found = hwnd;
        return 0;
    }
    1
}

/// Windows are enumerated top to bottom; titleless ones are helper windows (IME, message sinks).
fn window_of(pid: u32) -> Option<HWND> {
    let mut lookup = Lookup {
        pid,
        found: ptr::null_mut(),
    };
    // SAFETY: the callback only dereferences `lparam` as the `Lookup` that lives across the call.
    // A stopped enumeration reports failure, so the result is read from `found` instead.
    unsafe { EnumWindows(Some(first_of_pid), (&raw mut lookup) as LPARAM) };
    (!lookup.found.is_null()).then_some(lookup.found)
}

fn activate(target: &TypingTarget) -> HookResult<()> {
    let window = u32::try_from(target.pid)
        .ok()
        .and_then(window_of)
        .ok_or_else(|| HookError::Failed(format!("Auto-type stopped: {} quit", target.name)))?;
    // SAFETY: the handle comes from the enumeration just now; a stale one only fails.
    unsafe {
        if IsIconic(window) != 0 {
            ShowWindow(window, SW_RESTORE);
        }
        if SetForegroundWindow(window) == 0 {
            tracing::warn!(app = target.name, "foreground request refused");
        }
    }
    Ok(())
}

pub(super) fn give_focus_back(target: &TypingTarget) {
    // The panel also closes when the user clicks into another app; that app keeps the front.
    if foreground_pid() != Some(std::process::id()) {
        return;
    }
    if let Err(error) = activate(target) {
        tracing::debug!(%error, "cannot give the focus back");
    }
}

pub(super) fn start(target: TypingTarget, strokes: Vec<Stroke>, done: AutoTypeDone) {
    if SESSION.with_borrow(Option::is_some) {
        done(Err(HookError::Failed(
            "Auto-type is already running".to_owned(),
        )));
        return;
    }
    if let Err(error) = activate(&target) {
        done(Err(error));
        return;
    }
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, TICK, tick);
    SESSION.with_borrow_mut(|session| {
        *session = Some(Session {
            timer,
            target,
            strokes,
            phase: Phase::Activating,
            started: Instant::now(),
            done,
        });
    });
}

pub(super) fn cancel() {
    if let Some(session) = SESSION.with_borrow_mut(Option::take) {
        session.timer.stop();
        finish(session, Err(HookError::Cancelled));
    }
}

fn finish(session: Session, outcome: HookResult<()>) {
    if let Err(error) = &outcome {
        tracing::warn!(%error, app = session.target.name, "auto-type stopped");
    }
    let Session { timer, done, .. } = session;
    // A Slint timer is not dropped from inside its own callback.
    slint::Timer::single_shot(std::time::Duration::ZERO, move || drop(timer));
    done(outcome);
}

fn modifiers_held() -> bool {
    [VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN]
        .into_iter()
        // SAFETY: reads the asynchronous state of a virtual key; no pointers.
        .any(|key| unsafe { GetAsyncKeyState(i32::from(key)) } < 0)
}

fn tick() {
    let finished = SESSION.with_borrow_mut(|slot| {
        let session = slot.as_mut()?;
        let seen = Observed {
            frontmost: foreground_pid().and_then(|pid| i32::try_from(pid).ok()),
            modifiers_held: modifiers_held(),
            elapsed: session.started.elapsed(),
        };
        let (phase, action) = step(
            session.phase,
            session.target.pid,
            session.strokes.len(),
            seen,
        );
        session.phase = phase;
        let outcome = match action {
            Step::Wait => return None,
            Step::Post(index) => {
                if send(&session.strokes[index]) {
                    return None;
                }
                Err(HookError::Failed(format!("Auto-type stopped: {BLOCKED}")))
            }
            Step::Done => Ok(()),
            Step::Abort(reason) => Err(stopped(&session.target, reason)),
        };
        session.timer.stop();
        slot.take().map(|session| (session, outcome))
    });
    if let Some((session, outcome)) = finished {
        finish(session, outcome);
    }
}

fn input(key: KeyEvent) -> INPUT {
    let unicode = key.vk == 0;
    let mut flags = if unicode { KEYEVENTF_UNICODE } else { 0 };
    if key.up {
        flags |= KEYEVENTF_KEYUP;
    }
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: key.vk,
                wScan: key.scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Whether all of the stroke's events were inserted; fewer means UIPI or another thread's hook
/// blocked them.
fn send(stroke: &Stroke) -> bool {
    let mut inputs: Vec<INPUT> = events(stroke).iter().copied().map(input).collect();
    let Ok(count) = u32::try_from(inputs.len()) else {
        return false;
    };
    if count == 0 {
        return true;
    }
    let size = i32::try_from(mem::size_of::<INPUT>()).unwrap_or(0);
    // SAFETY: `inputs` holds `count` initialized `INPUT`s and `size` is the struct's size.
    let inserted = unsafe { SendInput(count, inputs.as_ptr(), size) };
    wipe(&mut inputs);
    if inserted != count {
        tracing::warn!(
            inserted,
            expected = count,
            "SendInput inserted fewer events"
        );
    }
    inserted == count
}

/// The scan codes of Unicode events are the typed characters.
fn wipe(inputs: &mut [INPUT]) {
    for slot in inputs {
        // SAFETY: `slot` is a valid exclusive reference; all-zero is a valid `INPUT`.
        unsafe { ptr::write_volatile(slot, mem::zeroed()) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
