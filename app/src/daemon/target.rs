//! Where auto-type goes: the app in front when the user asked for the Quick Panel. The daemon
//! reads it because it never comes to the front itself, while the UI process activates when it
//! starts (after its linger exit) and whenever it shows a window, so it would only see itself.

use std::time::Duration;

use crate::{hooks::TypingTarget, os::autotype};

/// How long a read from another thread waits for the main thread. Not measured: the main loop
/// only runs the tray and hotkey, so it answers within a frame; the margin covers a busy machine.
const MAIN_THREAD_WAIT: Duration = Duration::from_millis(500);

/// The frontmost app as macOS reports it, bw-lite's own processes included. Callable from any
/// thread; off the main thread it may block briefly.
pub trait FrontmostApp: Send + Sync {
    fn frontmost(&self) -> Option<TypingTarget>;
}

pub struct SystemFrontmost;

impl FrontmostApp for SystemFrontmost {
    fn frontmost(&self) -> Option<TypingTarget> {
        if autotype::on_main_thread() {
            return autotype::frontmost_any();
        }
        // SSH requests arrive on Tokio threads; `NSWorkspace` is only current on the main one.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let asked = slint::invoke_from_event_loop(move || {
            let _ = sender.send(autotype::frontmost_any());
        });
        if let Err(error) = asked {
            tracing::debug!(%error, "no main loop to read the frontmost app on");
            return None;
        }
        receiver.recv_timeout(MAIN_THREAD_WAIT).ok().flatten()
    }
}

/// `front`, unless it is one of the processes in `own` (the daemon, its UI child).
#[must_use]
pub fn outside(front: Option<TypingTarget>, own: &[u32]) -> Option<TypingTarget> {
    front.filter(|target| u32::try_from(target.pid).is_ok_and(|pid| pid > 0 && !own.contains(&pid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAEMON: u32 = 500;
    const UI: u32 = 501;

    fn app(pid: i32, name: &str) -> TypingTarget {
        TypingTarget {
            pid,
            name: name.to_owned(),
        }
    }

    #[test]
    fn another_app_in_front_is_the_target() {
        assert_eq!(
            outside(Some(app(812, "Safari")), &[DAEMON, UI]),
            Some(app(812, "Safari"))
        );
    }

    #[test]
    fn bw_lite_processes_and_bogus_pids_are_no_target() {
        let own = [DAEMON, UI];
        assert_eq!(outside(Some(app(500, "bw-lite")), &own), None, "the daemon");
        assert_eq!(
            outside(Some(app(501, "bw-lite")), &own),
            None,
            "its UI child"
        );
        assert_eq!(outside(Some(app(0, "kernel")), &own), None);
        assert_eq!(outside(Some(app(-1, "unknown")), &own), None);
        assert_eq!(outside(None, &own), None);
    }
}
