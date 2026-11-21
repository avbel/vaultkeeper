//! Auto-type on Linux (chain C-autotype). Wayland offers no way to type into another app or to
//! hand the focus back to it, so the chain is:
//!
//! 1. the RemoteDesktop portal's `NotifyKeyboardKeysym` on a persisted grant (GNOME, KDE),
//! 2. `zwp_virtual_keyboard_v1` with a keymap generated for the text (wlroots: Sway, Hyprland),
//! 3. unavailable, with the reason shown in the window.
//!
//! The previously focused window cannot be restored on Wayland. The Quick Panel closes itself
//! first and typing waits [`FOCUS_SETTLE`] for the compositor to refocus the window that was in
//! front; [`give_focus_back`] therefore has nothing to do. Typing runs on a thread of its own and
//! reports back through a timer on the UI thread, which is where the completion callback must run.
//! Typed text is never logged.

mod remote_desktop;
mod virtual_keyboard;

use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, TryRecvError},
    },
    time::Duration,
};

use zeroize::Zeroizing;

use super::keysym;
use crate::os::linux::portal_token::TokenStore;
use crate::{
    autotype::Stroke,
    hooks::{AutoTypeDone, HookError, TypingTarget},
    os::layout,
};

/// Pause between keystrokes. Not measured: the pace of the other platforms, which browsers'
/// per-key form handlers keep up with.
const PACE: Duration = Duration::from_millis(15);
/// How long the compositor gets to focus the window under the closed Quick Panel before the first
/// key. Not measured: a few frames of a slow machine plus the focus animation of common
/// compositors.
pub(super) const FOCUS_SETTLE: Duration = Duration::from_millis(350);
const POLL: Duration = Duration::from_millis(40);
/// Wayland tells a client nothing about other windows, so the "app to type into" is always the
/// window that gets the focus when the panel closes. A pid no process of ours can have.
const PREVIOUS_WINDOW_PID: i32 = 1;
const PREVIOUS_WINDOW: &str = "the previous window";

pub const NEEDS_WAYLAND: &str = "Auto-type needs a Wayland session; it cannot type in X11 sessions";

pub(super) enum Failure {
    /// This link cannot work here; the next one is tried.
    Unavailable(String),
    Stopped(String),
    /// The user closed the permission dialog.
    Dismissed,
    Cancelled,
}

impl Failure {
    fn reason(&self) -> String {
        match self {
            Self::Unavailable(reason) | Self::Stopped(reason) => reason.clone(),
            Self::Dismissed => "the keyboard permission dialog was dismissed".to_owned(),
            Self::Cancelled => "cancelled".to_owned(),
        }
    }

    fn into_hook(self) -> HookError {
        match self {
            Self::Unavailable(reason) => {
                HookError::Failed(format!("Auto-type is unavailable: {reason}"))
            }
            Self::Stopped(reason) => HookError::Failed(format!("Auto-type stopped: {reason}")),
            Self::Dismissed => HookError::Failed(
                "Auto-type stopped: the keyboard permission dialog was dismissed".to_owned(),
            ),
            Self::Cancelled => HookError::Cancelled,
        }
    }
}

struct Session {
    timer: slint::Timer,
    cancel: Arc<AtomicBool>,
    results: mpsc::Receiver<Result<(), Failure>>,
    done: AutoTypeDone,
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

pub(super) fn previous_window() -> TypingTarget {
    TypingTarget {
        pid: PREVIOUS_WINDOW_PID,
        name: PREVIOUS_WINDOW.to_owned(),
    }
}

/// Why typing cannot work in this session at all; the rest is only known by trying.
pub(super) fn session_problem() -> Option<&'static str> {
    problem_for(std::env::var_os("WAYLAND_DISPLAY").as_deref())
}

fn problem_for(wayland_display: Option<&std::ffi::OsStr>) -> Option<&'static str> {
    wayland_display
        .is_none_or(std::ffi::OsStr::is_empty)
        .then_some(NEEDS_WAYLAND)
}

pub(super) fn start(target: &TypingTarget, strokes: Vec<Stroke>, done: AutoTypeDone) {
    if SESSION.with_borrow(Option::is_some) {
        done(Err(HookError::Failed(
            "Auto-type is already running".to_owned(),
        )));
        return;
    }
    let keysyms = keysym::keysyms_of(&strokes);
    drop(strokes);
    let Ok(keysyms) = keysyms else {
        done(Err(HookError::Failed(
            "Auto-type stopped: the text has a character that cannot be typed".to_owned(),
        )));
        return;
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let (sender, results) = mpsc::channel();
    let worker_cancel = Arc::clone(&cancel);
    let spawned = std::thread::Builder::new()
        .name("vaultkeeper-autotype".to_owned())
        .spawn(move || {
            drop(sender.send(run(&keysyms, &worker_cancel)));
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, target = target.name, "cannot start the typing thread");
        done(Err(HookError::Failed(
            "Auto-type stopped: cannot start typing".to_owned(),
        )));
        return;
    }
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, POLL, poll);
    SESSION.with_borrow_mut(|session| {
        *session = Some(Session {
            timer,
            cancel,
            results,
            done,
        });
    });
}

pub(super) fn cancel() {
    if let Some(session) = SESSION.with_borrow_mut(Option::take) {
        session.cancel.store(true, Ordering::Relaxed);
        session.timer.stop();
        finish(session, Err(Failure::Cancelled));
    }
}

fn poll() {
    let finished = SESSION.with_borrow_mut(|slot| {
        let outcome = match slot.as_ref()?.results.try_recv() {
            Ok(outcome) => outcome,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Err(Failure::Stopped(
                "the typing thread ended unexpectedly".to_owned(),
            )),
        };
        slot.take().map(|session| (session, outcome))
    });
    if let Some((session, outcome)) = finished {
        finish(session, outcome);
    }
}

fn finish(session: Session, outcome: Result<(), Failure>) {
    let Session { timer, done, .. } = session;
    // A Slint timer is not dropped from inside its own callback.
    slint::Timer::single_shot(Duration::ZERO, move || drop(timer));
    let outcome = outcome.map_err(|failure| {
        tracing::warn!(reason = %failure.reason(), "auto-type did not finish");
        failure.into_hook()
    });
    done(outcome);
}

fn run(keysyms: &Zeroizing<Vec<u32>>, cancel: &AtomicBool) -> Result<(), Failure> {
    std::thread::sleep(FOCUS_SETTLE);
    if cancel.load(Ordering::Relaxed) {
        return Err(Failure::Cancelled);
    }
    let data_dir = layout::data_dir()
        .map_err(|error| Failure::Stopped(format!("no data directory ({error})")))?;
    chain(
        || {
            remote_desktop::type_keysyms(
                &TokenStore::new(data_dir.join(layout::AUTOTYPE_PORTAL_TOKEN_FILE)),
                keysyms,
                cancel,
            )
        },
        || virtual_keyboard::type_keysyms(keysyms, cancel),
    )
}

/// Only a link that cannot work here hands over to the next; a dismissed dialog, a failure
/// half-way or a cancel must not be answered by typing through another route.
fn chain(
    portal: impl FnOnce() -> Result<(), Failure>,
    wlroots: impl FnOnce() -> Result<(), Failure>,
) -> Result<(), Failure> {
    match portal() {
        Err(Failure::Unavailable(portal)) => match wlroots() {
            Err(Failure::Unavailable(wlroots)) => {
                Err(Failure::Unavailable(both_unavailable(&portal, &wlroots)))
            }
            other => other,
        },
        other => other,
    }
}

fn both_unavailable(portal: &str, wlroots: &str) -> String {
    format!("{portal}; {wlroots}")
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn no_wayland_display_means_no_auto_type() {
        assert_eq!(problem_for(None), Some(NEEDS_WAYLAND));
        assert_eq!(problem_for(Some(OsStr::new(""))), Some(NEEDS_WAYLAND));
        assert_eq!(problem_for(Some(OsStr::new("wayland-0"))), None);
    }

    #[test]
    fn the_reason_names_both_links_that_were_tried() {
        assert_eq!(
            both_unavailable("no RemoteDesktop portal", "no virtual keyboard"),
            "no RemoteDesktop portal; no virtual keyboard"
        );
    }

    fn unavailable(reason: &str) -> Result<(), Failure> {
        Err(Failure::Unavailable(reason.to_owned()))
    }

    #[test]
    fn an_unavailable_portal_hands_over_to_the_virtual_keyboard() {
        assert!(chain(|| unavailable("no portal"), || Ok(())).is_ok());
        let both = chain(|| unavailable("no portal"), || unavailable("no keyboard"));
        assert!(
            matches!(both, Err(Failure::Unavailable(text)) if text == "no portal; no keyboard")
        );
    }

    #[test]
    fn a_portal_that_got_as_far_as_failing_is_final() {
        let called = std::cell::Cell::new(false);
        let next = || {
            called.set(true);
            Ok(())
        };
        for failure in [
            Failure::Dismissed,
            Failure::Cancelled,
            Failure::Stopped("half-way".to_owned()),
        ] {
            assert!(chain(|| Err(failure), next).is_err());
        }
        assert!(!called.get());
        assert!(chain(|| Ok(()), next).is_ok());
        assert!(!called.get());
    }

    #[test]
    fn failures_read_as_hook_errors() {
        assert_eq!(
            Failure::Unavailable("x".to_owned()).into_hook().to_string(),
            "Auto-type is unavailable: x"
        );
        assert_eq!(
            Failure::Dismissed.into_hook().to_string(),
            "Auto-type stopped: the keyboard permission dialog was dismissed"
        );
        assert!(matches!(
            Failure::Cancelled.into_hook(),
            HookError::Cancelled
        ));
    }
}
