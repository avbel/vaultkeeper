//! Starts `vaultkeeper --ui` on demand, reaps it and kills it when it hangs. At most one UI process
//! runs: none is started while one is connected or still starting, and commands wait in the IPC
//! event queue until it connects.

#[cfg(windows)]
mod windows;

use std::{
    path::PathBuf,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use tokio::sync::oneshot;

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
pub fn ui_args(first_unlock: bool, no_activate: bool) -> Vec<&'static str> {
    ui_args_for(first_unlock, no_activate, crate::os::security_gate::skip())
}

/// A daemon started with `--skip-security-issues` passes it on, or its own UI would refuse.
fn ui_args_for(first_unlock: bool, no_activate: bool, skip: bool) -> Vec<&'static str> {
    let mut args = vec!["--ui"];
    if skip {
        args.push(crate::os::security_gate::SKIP_FLAG);
    }
    if first_unlock {
        args.push("--first-unlock");
    }
    if no_activate {
        args.push("--no-activate");
    }
    args
}

/// [`ui_args`] plus the inherited pipe handle's value, for the Windows UI process.
#[cfg(any(windows, test))]
#[must_use]
fn ui_args_with_pipe(first_unlock: bool, no_activate: bool, handle: usize) -> Vec<String> {
    let mut args: Vec<String> = ui_args(first_unlock, no_activate)
        .into_iter()
        .map(str::to_owned)
        .collect();
    args.push("--ui-pipe".to_owned());
    args.push(handle.to_string());
    args
}

/// What the daemon does about a command the UI has not acknowledged yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hang {
    /// Its main loop ran after the command arrived.
    Answered,
    /// A native modal dialog holds the main loop; the user is busy, not the UI hung.
    Wait,
    Kill,
}

/// After the hang timeout: `acked` is how many events the UI's main loop got through, `seq` the
/// number of the event being watched.
#[must_use]
pub const fn judge(acked: u64, seq: u64, modal: bool) -> Hang {
    if acked >= seq {
        Hang::Answered
    } else if modal {
        Hang::Wait
    } else {
        Hang::Kill
    }
}

struct Running {
    started: Instant,
    pid: Option<u32>,
    kill: Option<oneshot::Sender<()>>,
}

pub struct Launcher {
    exe: Option<PathBuf>,
    running: Mutex<Option<Running>>,
    /// Where the UI's pipe goes once the process is spawned (Windows).
    #[cfg(windows)]
    ui_sink: Option<vk_ipc::UiSink>,
}

impl Launcher {
    /// `exe` is `None` when no UI process may be started (tests drive the daemon themselves).
    #[must_use]
    pub const fn new(exe: Option<PathBuf>) -> Self {
        Self {
            exe,
            running: Mutex::new(None),
            #[cfg(windows)]
            ui_sink: None,
        }
    }

    /// Where the pipe to each new UI process is delivered; without it none can start.
    #[cfg(windows)]
    #[must_use]
    pub fn with_ui_sink(self, sink: vk_ipc::UiSink) -> Self {
        Self {
            ui_sink: Some(sink),
            ..self
        }
    }

    fn running(&self) -> std::sync::MutexGuard<'_, Option<Running>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running().is_some()
    }

    /// Whether this launcher starts UI processes at all.
    #[must_use]
    pub const fn can_start(&self) -> bool {
        self.exe.is_some()
    }

    /// Kills the running child (SIGKILL); the reaper then reports its exit as usual. Returns
    /// whether there was one to kill.
    pub fn kill(&self) -> bool {
        let kill = self
            .running()
            .as_mut()
            .and_then(|running| running.kill.take());
        kill.is_some_and(|kill| kill.send(()).is_ok())
    }

    /// Waits up to `limit` for the killed child to be reaped.
    #[cfg(windows)]
    pub async fn stopped(&self, limit: Duration) {
        let deadline = Instant::now() + limit;
        while self.is_running() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Spawns the UI unless one is connected or running. Must run inside the Tokio runtime
    /// (the child is reaped by a task); `on_exit` gets how long it ran.
    pub fn ensure(
        &self,
        ui_connected: bool,
        first_unlock: bool,
        no_activate: bool,
        on_exit: impl FnOnce(Duration) + Send + 'static,
    ) {
        let Some(exe) = &self.exe else {
            return;
        };
        let mut running = self.running();
        if decide(ui_connected, running.is_some()) == Spawn::NotNeeded {
            return;
        }
        let child = self.spawn(exe, first_unlock, no_activate);
        let child = match child {
            Ok(child) => child,
            Err(error) => {
                tracing::error!(%error, exe = %exe.display(), "cannot start the UI process");
                return;
            }
        };
        let started = Instant::now();
        let (kill, killed) = oneshot::channel();
        *running = Some(Running {
            started,
            pid: child.id(),
            kill: Some(kill),
        });
        drop(running);
        tracing::debug!(pid = child.id(), "UI process started");
        #[cfg(windows)]
        let ui_pid = child.id();
        #[cfg(windows)]
        if let Some(pid) = ui_pid {
            crate::os::ui_window::set_ui_pid(pid);
        }
        tokio::spawn(async move {
            child.reap(killed).await;
            #[cfg(windows)]
            if let Some(pid) = ui_pid {
                crate::os::ui_window::clear_ui_pid(pid);
            }
            on_exit(started.elapsed());
        });
    }

    #[cfg(not(windows))]
    #[allow(clippy::unused_self, reason = "Windows needs the channel sink")]
    fn spawn(
        &self,
        exe: &std::path::Path,
        first_unlock: bool,
        no_activate: bool,
    ) -> std::io::Result<UiChild> {
        tokio::process::Command::new(exe)
            .args(ui_args(first_unlock, no_activate))
            .stdin(std::process::Stdio::null())
            .kill_on_drop(false)
            .spawn()
            .map(UiChild)
    }

    #[cfg(windows)]
    fn spawn(
        &self,
        exe: &std::path::Path,
        first_unlock: bool,
        no_activate: bool,
    ) -> std::io::Result<UiChild> {
        let sink = self
            .ui_sink
            .as_ref()
            .ok_or_else(|| std::io::Error::other("no UI channel is wired to the launcher"))?;
        windows::spawn(exe, first_unlock, no_activate, sink).map(UiChild)
    }

    /// Called by the reaper before it decides about a restart.
    pub fn exited(&self) {
        *self.running() = None;
    }

    /// The running child's process id; `None` when none runs or it already exited.
    #[must_use]
    pub fn child_pid(&self) -> Option<u32> {
        self.running().as_ref().and_then(|running| running.pid)
    }

    /// How long the running child has been up.
    #[must_use]
    pub fn running_for(&self) -> Option<Duration> {
        self.running()
            .as_ref()
            .map(|running| running.started.elapsed())
    }
}

/// The UI process: a plain tokio child on macOS, a hardened one with a creation handle on Windows.
#[cfg(not(windows))]
struct UiChild(tokio::process::Child);
#[cfg(windows)]
struct UiChild(vk_win::Child);

impl UiChild {
    #[cfg(not(windows))]
    fn id(&self) -> Option<u32> {
        self.0.id()
    }

    #[cfg(windows)]
    #[allow(
        clippy::unnecessary_wraps,
        reason = "same signature as the tokio child"
    )]
    fn id(&self) -> Option<u32> {
        Some(self.0.pid())
    }

    /// Waits for the child, killing it first when asked to.
    #[cfg(not(windows))]
    async fn reap(mut self, killed: oneshot::Receiver<()>) {
        let child = &mut self.0;
        let status = tokio::select! {
            status = child.wait() => status,
            Ok(()) = killed => {
                tracing::warn!(pid = child.id(), "the UI process stopped answering; killing it");
                if let Err(error) = child.start_kill() {
                    tracing::warn!(%error, "cannot kill the UI process");
                }
                child.wait().await
            }
        };
        match status {
            Ok(status) => tracing::debug!(%status, "UI process exited"),
            Err(error) => tracing::warn!(%error, "lost track of the UI process"),
        }
    }

    #[cfg(windows)]
    async fn reap(self, killed: oneshot::Receiver<()>) {
        let child = self.0;
        let mut exit = std::pin::pin!(child.wait());
        let status = tokio::select! {
            status = &mut exit => status,
            Ok(()) = killed => {
                tracing::warn!(
                    pid = child.pid(),
                    exit_code = ?child.exit_code(),
                    "the UI process stopped answering; killing it"
                );
                if let Err(error) = child.kill() {
                    tracing::warn!(%error, "cannot kill the UI process");
                }
                exit.await
            }
        };
        match status {
            Ok(status) if status.success() => tracing::debug!(%status, "UI process exited"),
            Ok(status) => tracing::warn!(
                pid = child.pid(),
                code = status.code().map(|code| format!("{code:#x}")),
                "UI process exited with an error"
            ),
            Err(error) => tracing::warn!(%error, "lost track of the UI process"),
        }
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
    fn the_pipe_handle_follows_the_ui_flags() {
        assert_eq!(
            ui_args_with_pipe(true, true, 0x1a4),
            [
                "--ui",
                "--first-unlock",
                "--no-activate",
                "--ui-pipe",
                "420"
            ]
        );
    }

    #[test]
    fn the_first_unlock_flag_is_passed_only_when_set() {
        assert_eq!(ui_args(false, false), ["--ui"]);
        assert_eq!(
            ui_args_for(true, false, true),
            ["--ui", "--skip-security-issues", "--first-unlock"]
        );
        assert_eq!(ui_args(true, false), ["--ui", "--first-unlock"]);
        assert_eq!(ui_args(false, true), ["--ui", "--no-activate"]);
    }

    // These spawn Unix tools; the Windows launcher needs a real pipe and is covered in CI.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_started_child_is_tracked_until_it_exits() {
        let launcher = std::sync::Arc::new(Launcher::new(Some(PathBuf::from("/usr/bin/true"))));
        let (done, exited) = tokio::sync::oneshot::channel();
        let reaper = std::sync::Arc::clone(&launcher);
        launcher.ensure(false, false, false, move |ran| {
            reaper.exited();
            let _ = done.send(ran);
        });
        assert!(launcher.is_running());
        launcher.ensure(false, false, false, |_| {
            panic!("a second UI must not start")
        });
        let ran = tokio::time::timeout(Duration::from_secs(5), exited)
            .await
            .expect("exits")
            .expect("reaped");
        assert!(ran < Duration::from_secs(5));
        assert!(!launcher.is_running());
    }

    #[test]
    fn an_unanswered_command_kills_the_ui_unless_a_dialog_is_open() {
        assert_eq!(judge(3, 3, false), Hang::Answered);
        assert_eq!(
            judge(4, 3, false),
            Hang::Answered,
            "later ones answered too"
        );
        assert_eq!(judge(2, 3, false), Hang::Kill);
        assert_eq!(judge(2, 3, true), Hang::Wait);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_hung_child_is_killed_and_reaped() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("hang.sh");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n").expect("script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let launcher = std::sync::Arc::new(Launcher::new(Some(script)));
        let (done, exited) = tokio::sync::mpsc::unbounded_channel();
        // Exec'ing a file just written fails with ETXTBSY while another test thread forks.
        for _ in 0..20 {
            let reaper = std::sync::Arc::clone(&launcher);
            let done = done.clone();
            launcher.ensure(false, false, false, move |ran| {
                reaper.exited();
                let _ = done.send(ran);
            });
            if launcher.is_running() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(launcher.running_for().is_some());
        assert!(launcher.kill());
        assert!(!launcher.kill(), "one kill per child");
        let mut exited = exited;
        let ran = tokio::time::timeout(Duration::from_secs(5), exited.recv())
            .await
            .expect("killed well before the 30 s sleep ends")
            .expect("reaped");
        assert!(ran < Duration::from_secs(5));
        assert!(!launcher.is_running());
        assert!(!launcher.kill(), "nothing left to kill");
    }

    #[test]
    fn without_an_executable_nothing_starts() {
        let launcher = Launcher::new(None);
        launcher.ensure(false, false, false, |_| panic!("disabled"));
        assert!(!launcher.is_running());
    }
}
