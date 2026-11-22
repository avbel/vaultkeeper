//! Auto-type on Linux (chain C-autotype). Wayland offers no way to type into another app or to
//! hand the focus back to it, so the chain is:
//!
//! 1. the RemoteDesktop portal's `NotifyKeyboardKeysym` on a persisted grant (GNOME, KDE), after
//!    a check that the active keyboard layout can type the text (`typeable`): GNOME drops
//!    characters the layout lacks, and the portal cannot choose the layout. KWin types any
//!    character, so there the layout is put back after the run (`kde_layout`) instead,
//! 2. `zwp_virtual_keyboard_v1` with a keymap generated for the text (wlroots: Sway, Hyprland),
//! 3. unavailable, with the reason shown in the window.
//!
//! The previously focused window cannot be restored on Wayland. The Quick Panel closes itself
//! first and typing waits [`FOCUS_SETTLE`] for the compositor to refocus the window that was in
//! front; [`give_focus_back`] therefore has nothing to do. Typing runs on a thread of its own and
//! reports back through a timer on the UI thread, which is where the completion callback must run.
//! Typed text is never logged.

mod focused_keyboard;
mod kde_layout;
mod remote_desktop;
mod typeable;
mod virtual_keyboard;
mod xkb;

use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, TryRecvError},
    },
    thread::JoinHandle,
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
    /// The portal would type the text wrong with this keyboard layout. Nothing was typed or asked
    /// for yet, so a link that brings its own keymap may type instead.
    Refused(String),
    Stopped(String),
    /// The user closed the permission dialog.
    Dismissed,
    Cancelled,
}

impl Failure {
    fn reason(&self) -> String {
        match self {
            Self::Unavailable(reason) | Self::Refused(reason) | Self::Stopped(reason) => {
                reason.clone()
            }
            Self::Dismissed => "the keyboard permission dialog was dismissed".to_owned(),
            Self::Cancelled => "cancelled".to_owned(),
        }
    }

    fn into_hook(self) -> HookError {
        match self {
            Self::Unavailable(reason) => {
                HookError::Failed(format!("Auto-type is unavailable: {reason}"))
            }
            Self::Refused(reason) | Self::Stopped(reason) => {
                HookError::Failed(format!("Auto-type stopped: {reason}"))
            }
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
    /// The keyboard as the Quick Panel last saw it, for the typing job that follows.
    static KEYBOARD: RefCell<Option<Result<typeable::Seen, String>>> = const { RefCell::new(None) };
    /// The last typing thread. A cancel ends the session at once, but the thread may still sit in
    /// the permission dialog holding the text and the layout to restore; a second job alongside it
    /// would type while that restore switches the layout.
    static WORKER: RefCell<Option<JoinHandle<()>>> = const { RefCell::new(None) };
}

const KEYBOARD_NOT_READ: &str = "it was not read before the Quick Panel closed";

/// Reads the keyboard for the typing job that follows, and answers at once when the job is
/// certain to be refused, so the Quick Panel can say so while it is still open.
pub(super) fn read_keyboard(focused: &slint::Window, strokes: &[Stroke]) -> Option<String> {
    let reading = focused_keyboard::read(focused);
    if let Err(reason) = &reading.keyboard {
        tracing::warn!(reason, "cannot read the keyboard layout");
    }
    let refusal = keysym::keysyms_of(strokes).ok().and_then(|keysyms| {
        early_refusal(
            typeable::Desktop::current(),
            reading.portal_only,
            reading.keyboard.as_ref().map_err(String::as_str),
            &keysyms,
        )
    });
    // A refused job never starts, so nothing is kept for one.
    KEYBOARD.set(refusal.is_none().then_some(reading.keyboard));
    refusal
}

/// Only the portal route depends on the layout; where the compositor also offers a virtual
/// keyboard, which of the two types is known only once the portal was tried.
fn early_refusal(
    desktop: typeable::Desktop,
    portal_only: bool,
    keyboard: Result<&typeable::Seen, &str>,
    keysyms: &[u32],
) -> Option<String> {
    if !portal_only {
        return None;
    }
    match typeable::examine(desktop, keyboard, keysyms) {
        typeable::Verdict::Refuse(refusal) => {
            Some(refusal_failure(&refusal).into_hook().to_string())
        }
        _ => None,
    }
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
    if SESSION.with_borrow(Option::is_some) || WORKER.with_borrow(|worker| busy(worker.as_ref())) {
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
    let keyboard = KEYBOARD
        .take()
        .unwrap_or_else(|| Err(KEYBOARD_NOT_READ.to_owned()));
    let cancel = Arc::new(AtomicBool::new(false));
    let (sender, results) = mpsc::channel();
    let worker_cancel = Arc::clone(&cancel);
    let spawned = std::thread::Builder::new()
        .name("vaultkeeper-autotype".to_owned())
        .spawn(move || {
            drop(sender.send(run(&keysyms, &keyboard, &worker_cancel)));
        });
    match spawned {
        Ok(worker) => WORKER.set(Some(worker)),
        Err(error) => {
            tracing::warn!(%error, target = target.name, "cannot start the typing thread");
            done(Err(HookError::Failed(
                "Auto-type stopped: cannot start typing".to_owned(),
            )));
            return;
        }
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

fn busy(worker: Option<&JoinHandle<()>>) -> bool {
    worker.is_some_and(|worker| !worker.is_finished())
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

fn run(
    keysyms: &Zeroizing<Vec<u32>>,
    keyboard: &Result<typeable::Seen, String>,
    cancel: &AtomicBool,
) -> Result<(), Failure> {
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
                keyboard.as_ref().map_err(String::as_str),
                typeable::Desktop::current(),
                cancel,
            )
        },
        || virtual_keyboard::type_keysyms(keysyms, cancel),
    )
}

/// A layout the portal cannot type with hands over to a link with a keymap of its own. A locked
/// modifier does not: the focused app's libxkbcommon still capitalizes one-level keys while Lock
/// is set, and compositors may merge the physical keyboard's modifier state into a virtual one
/// (Hyprland's `virtualkeyboard:share_states`, a seat-wide XKB state), so no route is safe.
fn refusal_failure(refusal: &typeable::Refusal) -> Failure {
    match refusal {
        typeable::Refusal::LockedModifier => Failure::Stopped(refusal.reason()),
        _ => Failure::Refused(refusal.reason()),
    }
}

/// Only a link that cannot work here, or that refused before doing anything, hands over to the
/// next; a dismissed dialog, a failure half-way or a cancel must not be answered by typing through
/// another route.
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
        Err(Failure::Refused(refusal)) => match wlroots() {
            // The user can act on the layout, not on a compositor without a virtual keyboard.
            Err(Failure::Unavailable(_)) => Err(Failure::Refused(refusal)),
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
    use typeable::Desktop;

    #[test]
    fn a_typing_thread_still_running_after_a_cancel_blocks_the_next_job() {
        let (release, wait) = mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let _released = wait.recv();
        });
        assert!(busy(Some(&worker)));
        drop(release);
        while !worker.is_finished() {
            std::thread::yield_now();
        }
        assert!(!busy(Some(&worker)));
        assert!(!busy(None));
    }

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
    fn a_text_the_portal_refuses_is_typed_by_the_virtual_keyboard_when_there_is_one() {
        let refused = || Err(Failure::Refused("the layout lacks characters".to_owned()));
        assert!(chain(refused, || Ok(())).is_ok());
        let alone = chain(refused, || unavailable("no keyboard"));
        assert_eq!(
            alone.map_err(|failure| failure.into_hook().to_string()),
            Err("Auto-type stopped: the layout lacks characters".to_owned())
        );
        let broke = chain(refused, || Err(Failure::Stopped("half-way".to_owned())));
        assert!(matches!(broke, Err(Failure::Stopped(text)) if text == "half-way"));
    }

    #[test]
    fn a_locked_modifier_stops_every_route_and_other_refusals_hand_over() {
        use typeable::Refusal;

        let called = std::cell::Cell::new(false);
        let next = || {
            called.set(true);
            Ok(())
        };
        let locked = chain(|| Err(refusal_failure(&Refusal::LockedModifier)), next);
        assert_eq!(
            locked.map_err(|failure| failure.into_hook().to_string()),
            Err(
                "Auto-type stopped: a locked modifier such as Caps Lock would change the text; turn it off"
                    .to_owned()
            )
        );
        assert!(!called.get());
        for refusal in [
            Refusal::Missing,
            Refusal::LayoutUnknown,
            Refusal::LayoutPerWindow,
            Refusal::Unchecked("no keyboard".to_owned()),
        ] {
            called.set(false);
            assert!(chain(|| Err(refusal_failure(&refusal)), next).is_ok());
            assert!(called.get(), "{refusal:?}");
        }
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
    fn a_text_the_layout_lacks_is_refused_while_the_panel_is_open_on_portal_desktops() {
        let seen = typeable::Seen {
            keymap: xkb::tests::US.to_vec(),
            layout: Some(0),
            locked_modifiers: 0,
        };
        let cyrillic = [keysym::keysym_of('Ж').expect("typeable")];
        assert_eq!(
            early_refusal(Desktop::Other, true, Ok(&seen), &cyrillic).as_deref(),
            Some(
                "Auto-type stopped: the active keyboard layout lacks some characters; switch it or copy"
            )
        );
        // A virtual keyboard brings its own keymap, so the layout may not matter at all.
        assert_eq!(
            early_refusal(Desktop::Other, false, Ok(&seen), &cyrillic),
            None
        );
        assert_eq!(
            early_refusal(Desktop::Other, false, Err("no keyboard"), &cyrillic),
            None
        );
        assert_eq!(
            early_refusal(Desktop::Other, true, Ok(&seen), &[0x61, keysym::TAB]),
            None
        );
        assert!(
            early_refusal(Desktop::Other, true, Err("no keyboard"), &cyrillic)
                .is_some_and(|text| text.ends_with("copy instead (no keyboard)"))
        );
    }

    #[test]
    fn on_kde_the_panel_refuses_only_a_locked_modifier() {
        let cyrillic = [keysym::keysym_of('Ж').expect("typeable")];
        let seen = |locked_modifiers| typeable::Seen {
            keymap: xkb::tests::US.to_vec(),
            layout: Some(0),
            locked_modifiers,
        };
        assert_eq!(
            early_refusal(Desktop::Kde, true, Ok(&seen(0)), &cyrillic),
            None
        );
        assert_eq!(
            early_refusal(Desktop::Kde, true, Ok(&seen(1 << 1)), &cyrillic).as_deref(),
            Some(
                "Auto-type stopped: a locked modifier such as Caps Lock would change the text; turn it off"
            )
        );
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
