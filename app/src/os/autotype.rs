//! Auto-type on macOS: Accessibility trust, the frontmost app, and posting the keystrokes.
//!
//! Everything runs on the UI thread from a repeating `slint::Timer`: `NSWorkspace` learns about
//! activation changes from main-run-loop notifications, so a blocking wait there would never see
//! the target come forward, and a timer tick is also the pause between keystrokes.

use std::time::Duration;

use crate::{
    autotype::Stroke,
    hooks::{AutoType, AutoTypeDone, HookError, TypingTarget},
};

/// Pause between keystrokes and between checks while waiting. Not measured: a common pace for
/// synthesized typing that browsers' per-key form handlers keep up with.
const TICK: Duration = Duration::from_millis(15);
/// How long the target may take to come back to the front.
const ACTIVATE_TIMEOUT: Duration = Duration::from_secs(1);
/// ⌘⇧ of the shortcut are usually still held when the target is active again; typing waits for
/// their release until this long after the start, because a held ⌘ would turn letters into
/// shortcuts in the target app.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(3);

pub const NOT_ACTIVATED: &str = "did not come to the front";
pub const FRONT_CHANGED: &str = "another app came to the front";
pub const KEYS_HELD: &str = "modifier keys were held down";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Activating,
    /// The target is in front; waiting for the shortcut's modifiers to be released.
    Releasing,
    /// The next stroke to post.
    Typing(usize),
}

/// What one timer tick saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    pub frontmost: Option<i32>,
    pub modifiers_held: bool,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Wait,
    Post(usize),
    Done,
    Abort(&'static str),
}

/// One tick of the typing state machine for `total` strokes into the app `target`.
#[must_use]
pub fn step(phase: Phase, target: i32, total: usize, seen: Observed) -> (Phase, Step) {
    let in_front = seen.frontmost == Some(target);
    match phase {
        Phase::Activating if in_front => (Phase::Releasing, Step::Wait),
        Phase::Activating if seen.elapsed >= ACTIVATE_TIMEOUT => {
            (phase, Step::Abort(NOT_ACTIVATED))
        }
        Phase::Activating => (phase, Step::Wait),
        _ if !in_front => (phase, Step::Abort(FRONT_CHANGED)),
        Phase::Releasing if !seen.modifiers_held => (Phase::Typing(0), Step::Wait),
        Phase::Releasing if seen.elapsed >= RELEASE_TIMEOUT => (phase, Step::Abort(KEYS_HELD)),
        Phase::Releasing => (phase, Step::Wait),
        Phase::Typing(_) if seen.modifiers_held => (phase, Step::Abort(KEYS_HELD)),
        Phase::Typing(next) if next >= total => (phase, Step::Done),
        Phase::Typing(next) => (Phase::Typing(next + 1), Step::Post(next)),
    }
}

/// The user-facing message for an abort `reason` from [`step`].
#[must_use]
pub fn stopped(target: &TypingTarget, reason: &str) -> HookError {
    if reason == NOT_ACTIVATED {
        HookError::Failed(format!("Auto-type stopped: {} {reason}", target.name))
    } else {
        HookError::Failed(format!("Auto-type stopped: {reason}"))
    }
}

pub struct SystemAutoType;

impl AutoType for SystemAutoType {
    fn frontmost(&self) -> Option<TypingTarget> {
        #[cfg(target_os = "macos")]
        {
            macos::frontmost()
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    fn is_trusted(&self, prompt: bool) -> bool {
        #[cfg(target_os = "macos")]
        {
            macos::is_trusted(prompt)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = prompt;
            false
        }
    }

    fn start(&self, target: TypingTarget, strokes: Vec<Stroke>, done: AutoTypeDone) {
        #[cfg(target_os = "macos")]
        macos::start(target, strokes, done);
        #[cfg(not(target_os = "macos"))]
        {
            drop((target, strokes));
            done(Err(HookError::Unavailable("Auto-type")));
        }
    }

    fn cancel(&self) {
        #[cfg(target_os = "macos")]
        macos::cancel();
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{cell::RefCell, time::Instant};

    use objc2::{MainThreadMarker, rc::Retained, runtime::NSObjectProtocol, sel};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationOptions, NSRunningApplication, NSWorkspace,
    };
    use objc2_core_foundation::{CFBoolean, CFDictionary, CFRetained, CFString, kCFBooleanTrue};
    use objc2_core_graphics::{
        CGEvent, CGEventFlags, CGEventSource, CGEventSourceStateID, CGEventTapLocation, CGKeyCode,
    };

    use super::{HookError, Observed, Phase, Step, Stroke, TICK, TypingTarget, step, stopped};
    use crate::hooks::{AutoTypeDone, HookResult};

    /// kVK_Tab (HIToolbox `Events.h`).
    const TAB_KEY: CGKeyCode = 0x30;
    /// Unicode strokes carry their text in the event; the key code is only a placeholder.
    const TEXT_KEY: CGKeyCode = 0;

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn AXIsProcessTrusted() -> u8;
        fn AXIsProcessTrustedWithOptions(options: Option<&CFDictionary>) -> u8;
        static kAXTrustedCheckOptionPrompt: &'static CFString;
    }

    struct Session {
        timer: slint::Timer,
        target: TypingTarget,
        strokes: Vec<Stroke>,
        phase: Phase,
        started: Instant,
        source: CFRetained<CGEventSource>,
        done: AutoTypeDone,
    }

    thread_local! {
        static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
    }

    pub(super) fn is_trusted(prompt: bool) -> bool {
        // SAFETY: no arguments; the call only reads this process's TCC state.
        if unsafe { AXIsProcessTrusted() } != 0 {
            return true;
        }
        if prompt {
            // SAFETY: the key is an immutable framework constant and the value a CF singleton.
            let (key, yes) = unsafe { (kAXTrustedCheckOptionPrompt, kCFBooleanTrue) };
            if let Some(yes) = yes {
                let options = CFDictionary::<CFString, CFBoolean>::from_slices(&[key], &[yes]);
                // SAFETY: a valid dictionary with the documented key and a CFBoolean value.
                return unsafe { AXIsProcessTrustedWithOptions(Some(options.as_ref())) } != 0;
            }
        }
        false
    }

    fn frontmost_app() -> Option<Retained<NSRunningApplication>> {
        NSWorkspace::sharedWorkspace().frontmostApplication()
    }

    fn own_pid() -> i32 {
        i32::try_from(std::process::id()).unwrap_or(-1)
    }

    pub(super) fn frontmost() -> Option<TypingTarget> {
        let app = frontmost_app()?;
        let pid = app.processIdentifier();
        if pid == own_pid() {
            return None;
        }
        let name = app
            .localizedName()
            .map_or_else(|| "The app".to_owned(), |name| name.to_string());
        Some(TypingTarget { pid, name })
    }

    pub(super) fn start(target: TypingTarget, strokes: Vec<Stroke>, done: AutoTypeDone) {
        let Some(mtm) = MainThreadMarker::new() else {
            done(Err(HookError::Failed(
                "Auto-type must start on the main thread".to_owned(),
            )));
            return;
        };
        if SESSION.with_borrow(Option::is_some) {
            done(Err(HookError::Failed(
                "Auto-type is already running".to_owned(),
            )));
            return;
        }
        let Some(source) = CGEventSource::new(CGEventSourceStateID::Private) else {
            done(Err(HookError::Failed(
                "Cannot create key events".to_owned(),
            )));
            return;
        };
        if let Err(error) = activate(mtm, &target) {
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
                source,
                done,
            });
        });
    }

    fn activate(mtm: MainThreadMarker, target: &TypingTarget) -> HookResult<()> {
        let app = NSRunningApplication::runningApplicationWithProcessIdentifier(target.pid)
            .ok_or_else(|| HookError::Failed(format!("Auto-type stopped: {} quit", target.name)))?;
        let me = NSApplication::sharedApplication(mtm);
        // macOS 14+ only activates another app that the active one yielded to.
        if me.respondsToSelector(sel!(yieldActivationToApplication:)) {
            me.yieldActivationToApplication(&app);
        }
        #[allow(deprecated)]
        let options = NSApplicationActivationOptions::ActivateIgnoringOtherApps;
        if !app.activateWithOptions(options) {
            tracing::warn!(app = target.name, "activation request refused");
        }
        Ok(())
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
        let held = CGEventSource::flags_state(CGEventSourceStateID::HIDSystemState);
        held.intersects(
            CGEventFlags::MaskCommand
                | CGEventFlags::MaskShift
                | CGEventFlags::MaskAlternate
                | CGEventFlags::MaskControl,
        )
    }

    fn tick() {
        let finished = SESSION.with_borrow_mut(|slot| {
            let session = slot.as_mut()?;
            let seen = Observed {
                frontmost: frontmost_app().map(|app| app.processIdentifier()),
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
                    if post(&session.source, &session.strokes[index]) {
                        return None;
                    }
                    Err(HookError::Failed(
                        "Auto-type stopped: cannot create key events".to_owned(),
                    ))
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

    fn post(source: &CGEventSource, stroke: &Stroke) -> bool {
        let (key, units) = match stroke {
            Stroke::Tab => (TAB_KEY, None),
            Stroke::Text(units) => (TEXT_KEY, Some(units)),
        };
        for down in [true, false] {
            let Some(event) = CGEvent::new_keyboard_event(Some(source), key, down) else {
                return false;
            };
            // The user's own modifiers must not ride along on the synthesized keys.
            CGEvent::set_flags(Some(&event), CGEventFlags::empty());
            if let Some(units) = units {
                // SAFETY: `units` is a live UTF-16 buffer of exactly this length.
                unsafe {
                    CGEvent::keyboard_set_unicode_string(
                        Some(&event),
                        units.len() as _,
                        units.as_ptr(),
                    );
                }
            }
            CGEvent::post(CGEventTapLocation::HIDEventTap, Some(&event));
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: i32 = 42;
    const OTHER: i32 = 7;

    fn seen(frontmost: Option<i32>, modifiers_held: bool, millis: u64) -> Observed {
        Observed {
            frontmost,
            modifiers_held,
            elapsed: Duration::from_millis(millis),
        }
    }

    #[test]
    fn waits_for_the_target_then_the_release_then_types_every_stroke() {
        let mut phase = Phase::Activating;
        let mut posted = Vec::new();
        let ticks = [
            seen(None, true, 15),
            seen(Some(APP), true, 30),
            seen(Some(APP), true, 45),
            seen(Some(APP), false, 60),
            seen(Some(APP), false, 75),
            seen(Some(APP), false, 90),
            seen(Some(APP), false, 105),
        ];
        let mut last = Step::Wait;
        for observed in ticks {
            let (next, action) = step(phase, APP, 2, observed);
            phase = next;
            last = action;
            if let Step::Post(index) = action {
                posted.push(index);
            }
        }
        assert_eq!(posted, [0, 1]);
        assert_eq!(last, Step::Done);
    }

    #[test]
    fn a_target_that_never_comes_forward_aborts_after_a_second() {
        let (_, before) = step(Phase::Activating, APP, 3, seen(Some(OTHER), false, 999));
        assert_eq!(before, Step::Wait);
        let (_, after) = step(Phase::Activating, APP, 3, seen(Some(OTHER), false, 1000));
        assert_eq!(after, Step::Abort(NOT_ACTIVATED));
    }

    #[test]
    fn bw_lite_or_another_app_in_front_aborts_after_activation() {
        for phase in [Phase::Releasing, Phase::Typing(0), Phase::Typing(2)] {
            let (_, action) = step(phase, APP, 3, seen(Some(OTHER), false, 100));
            assert_eq!(action, Step::Abort(FRONT_CHANGED), "{phase:?}");
            let (_, action) = step(phase, APP, 3, seen(None, false, 100));
            assert_eq!(action, Step::Abort(FRONT_CHANGED), "{phase:?}");
        }
    }

    #[test]
    fn modifiers_held_too_long_or_pressed_mid_typing_abort() {
        let (_, waiting) = step(Phase::Releasing, APP, 3, seen(Some(APP), true, 2999));
        assert_eq!(waiting, Step::Wait);
        let (_, late) = step(Phase::Releasing, APP, 3, seen(Some(APP), true, 3000));
        assert_eq!(late, Step::Abort(KEYS_HELD));
        let (_, pressed) = step(Phase::Typing(1), APP, 3, seen(Some(APP), true, 200));
        assert_eq!(pressed, Step::Abort(KEYS_HELD));
    }

    #[test]
    fn nothing_to_type_finishes_at_once() {
        let (_, action) = step(Phase::Typing(0), APP, 0, seen(Some(APP), false, 50));
        assert_eq!(action, Step::Done);
    }

    #[test]
    fn abort_messages_name_the_app_only_when_it_did_not_come_forward() {
        let target = TypingTarget {
            pid: APP,
            name: "Safari".to_owned(),
        };
        assert_eq!(
            stopped(&target, NOT_ACTIVATED).to_string(),
            "Auto-type stopped: Safari did not come to the front"
        );
        assert_eq!(
            stopped(&target, FRONT_CHANGED).to_string(),
            "Auto-type stopped: another app came to the front"
        );
    }
}
