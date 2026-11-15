//! Windows: starts the daemon as a process of its own. A shell waits for console programs and a
//! process attached to a terminal dies when the terminal closes, so a daemon started from a console
//! (or by the browser host) re-launches itself without one (docs/solutions/windows-support.md §7.11).

#[cfg(any(windows, test))]
const DETACHED_MARKER: &str = "--detached";

/// `args` plus the marker that stops the child from re-launching itself.
#[cfg(any(windows, test))]
fn with_marker(args: &[String]) -> Vec<String> {
    let mut all = args.to_vec();
    if !all.iter().any(|arg| arg == DETACHED_MARKER) {
        all.push(DETACHED_MARKER.to_owned());
    }
    all
}

#[cfg(windows)]
pub use self::windows::{relaunch_if_attached, start_daemon};

#[cfg(windows)]
mod windows {
    use std::{io, path::Path};

    use vk_win::SpawnOptions;
    use windows_sys::Win32::System::{
        Console::GetConsoleWindow,
        Threading::{CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS},
    };

    use super::{DETACHED_MARKER, with_marker};

    /// Re-launches this exe with `args` plus `--detached` when it has a console and is not the
    /// detached copy already. `Ok(true)` means the caller should exit.
    pub fn relaunch_if_attached(args: &[String], detached: bool) -> io::Result<bool> {
        if detached || !has_console() {
            return Ok(false);
        }
        spawn_detached(&std::env::current_exe()?, &with_marker(args))?;
        Ok(true)
    }

    /// What the browser host does when no daemon answers: it has no terminal to lose, but it runs
    /// in the browser's job and the daemon must outlive both.
    pub fn start_daemon() -> io::Result<()> {
        let args = ["--tray".to_owned(), DETACHED_MARKER.to_owned()];
        spawn_detached(&std::env::current_exe()?, &args)
    }

    fn has_console() -> bool {
        // SAFETY: takes no arguments and only reads the process's console state.
        !unsafe { GetConsoleWindow() }.is_null()
    }

    fn spawn_detached(exe: &Path, args: &[String]) -> io::Result<()> {
        let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        let spawn = |creation_flags| {
            vk_win::spawn_hardened(
                exe,
                args,
                &SpawnOptions {
                    creation_flags,
                    ..SpawnOptions::default()
                },
            )
        };
        // A job without JOB_OBJECT_LIMIT_BREAKAWAY_OK refuses the flag; the daemon then stays in
        // the job, which beats not starting it.
        spawn(base | CREATE_BREAKAWAY_FROM_JOB)
            .or_else(|_| spawn(base))
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_is_added_once() {
        let args = vec!["--tray".to_owned()];
        assert_eq!(with_marker(&args), ["--tray", "--detached"]);
        assert_eq!(with_marker(&with_marker(&args)), ["--tray", "--detached"]);
    }
}
