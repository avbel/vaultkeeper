//! Starts `bw-lite --ui` on demand and reaps it. At most one UI process runs: none is started
//! while one is connected or still starting, and commands wait in the IPC event queue until it
//! connects.

use std::{
    path::PathBuf,
    process::Stdio,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

/// A UI that dies sooner than this after its start is treated as crashing: it is not restarted
/// just because commands are still queued, so a broken build cannot spin.
const HEALTHY_RUN: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spawn {
    /// A UI is connected or its process is still starting or exiting.
    NotNeeded,
    Start,
}

#[must_use]
pub const fn decide(ui_connected: bool, child_running: bool) -> Spawn {
    if ui_connected || child_running {
        Spawn::NotNeeded
    } else {
        Spawn::Start
    }
}

/// After the UI process exited: start a new one when commands are still waiting (they arrived
/// while the old one was on its way out), unless it crashed right after starting.
#[must_use]
pub fn restart_after_exit(commands_queued: bool, ran_for: Duration, quitting: bool) -> bool {
    commands_queued && !quitting && ran_for >= HEALTHY_RUN
}

/// The arguments of the UI process; `first_unlock` tells it that no unlock happened since the
/// daemon started, for "Require master password on app start".
#[must_use]
pub fn ui_args(first_unlock: bool) -> Vec<&'static str> {
    let mut args = vec!["--ui"];
    if first_unlock {
        args.push("--first-unlock");
    }
    args
}

pub struct Launcher {
    exe: Option<PathBuf>,
    /// Start time of the running child.
    running: Mutex<Option<Instant>>,
}

impl Launcher {
    /// `exe` is `None` when no UI process may be started (tests drive the daemon themselves).
    #[must_use]
    pub const fn new(exe: Option<PathBuf>) -> Self {
        Self {
            exe,
            running: Mutex::new(None),
        }
    }

    fn running(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running().is_some()
    }

    /// Spawns the UI unless one is connected or running. Must run inside the Tokio runtime
    /// (the child is reaped by a task); `on_exit` gets how long it ran.
    pub fn ensure(
        &self,
        ui_connected: bool,
        first_unlock: bool,
        on_exit: impl FnOnce(Duration) + Send + 'static,
    ) {
        let Some(exe) = &self.exe else {
            return;
        };
        let mut running = self.running();
        if decide(ui_connected, running.is_some()) == Spawn::NotNeeded {
            return;
        }
        let child = tokio::process::Command::new(exe)
            .args(ui_args(first_unlock))
            .stdin(Stdio::null())
            .kill_on_drop(false)
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                tracing::error!(%error, exe = %exe.display(), "cannot start the UI process");
                return;
            }
        };
        let started = Instant::now();
        *running = Some(started);
        drop(running);
        tracing::debug!(pid = child.id(), "UI process started");
        tokio::spawn(async move {
            match child.wait().await {
                Ok(status) => tracing::debug!(%status, "UI process exited"),
                Err(error) => tracing::warn!(%error, "lost track of the UI process"),
            }
            on_exit(started.elapsed());
        });
    }

    /// Called by the reaper before it decides about a restart.
    pub fn exited(&self) {
        *self.running() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_ui_at_a_time() {
        assert_eq!(decide(false, false), Spawn::Start);
        assert_eq!(decide(true, false), Spawn::NotNeeded, "connected");
        assert_eq!(decide(false, true), Spawn::NotNeeded, "still starting");
        assert_eq!(decide(true, true), Spawn::NotNeeded);
    }

    #[test]
    fn queued_commands_restart_a_ui_that_left_but_not_a_crashing_one() {
        let healthy = Duration::from_secs(130);
        assert!(restart_after_exit(true, healthy, false));
        assert!(!restart_after_exit(false, healthy, false), "nothing waits");
        assert!(
            !restart_after_exit(true, Duration::from_millis(300), false),
            "crashed at start"
        );
        assert!(
            !restart_after_exit(true, healthy, true),
            "the daemon is quitting"
        );
    }

    #[test]
    fn the_first_unlock_flag_is_passed_only_when_set() {
        assert_eq!(ui_args(false), ["--ui"]);
        assert_eq!(ui_args(true), ["--ui", "--first-unlock"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_started_child_is_tracked_until_it_exits() {
        let launcher = std::sync::Arc::new(Launcher::new(Some(PathBuf::from("/usr/bin/true"))));
        let (done, exited) = tokio::sync::oneshot::channel();
        let reaper = std::sync::Arc::clone(&launcher);
        launcher.ensure(false, false, move |ran| {
            reaper.exited();
            let _ = done.send(ran);
        });
        assert!(launcher.is_running());
        launcher.ensure(false, false, |_| panic!("a second UI must not start"));
        let ran = tokio::time::timeout(Duration::from_secs(5), exited)
            .await
            .expect("exits")
            .expect("reaped");
        assert!(ran < Duration::from_secs(5));
        assert!(!launcher.is_running());
    }

    #[test]
    fn without_an_executable_nothing_starts() {
        let launcher = Launcher::new(None);
        launcher.ensure(false, false, |_| panic!("disabled"));
        assert!(!launcher.is_running());
    }
}
