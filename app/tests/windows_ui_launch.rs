//! The real start-up path on Windows, end to end: the daemon starts, a second launch asks it for a
//! window, the daemon spawns `vaultkeeper.exe --ui` through `spawn_hardened` (process and thread
//! SDDL, one-handle inherit list, creation mitigations) and the UI must complete the Hello
//! handshake over the inherited pipe. Nothing here is faked: the UI verifies that its parent is
//! the same executable, so the daemon has to be the real binary too.
//!
//! The daemon and the UI use the real per-user data and log directories and the single-instance
//! mutex, so the test runs only on CI (or with `VAULTKEEPER_UI_LAUNCH_TEST=1`), never next to a
//! daemon somebody is using.

#![cfg(windows)]
#![allow(clippy::print_stderr)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const EXE: &str = env!("CARGO_BIN_EXE_vaultkeeper");
const DAEMON_READY: &str = "vaultkeeper daemon running";
const UI_CONNECTED: &str = "connected to the daemon";
const DAEMON_WAIT: Duration = Duration::from_secs(30);
const UI_WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);

fn enabled() -> bool {
    std::env::var_os("CI").is_some()
        || std::env::var_os("VAULTKEEPER_UI_LAUNCH_TEST").is_some_and(|value| value == "1")
}

fn log_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is set in a user session");
    PathBuf::from(base).join("Vaultkeeper").join("logs")
}

/// A log file's size now, so that lines of earlier runs are not mistaken for this one's.
fn size(path: &Path) -> usize {
    fs::metadata(path).map_or(0, |meta| usize::try_from(meta.len()).unwrap_or(usize::MAX))
}

fn since(path: &Path, offset: usize) -> String {
    let bytes = fs::read(path).unwrap_or_default();
    String::from_utf8_lossy(bytes.get(offset..).unwrap_or_default()).into_owned()
}

struct Logs {
    daemon: (PathBuf, usize),
    ui: (PathBuf, usize),
    early: (PathBuf, usize),
}

impl Logs {
    fn new() -> Self {
        let dir = log_dir();
        let mark = |name: &str| {
            let path = dir.join(name);
            let offset = size(&path);
            (path, offset)
        };
        Self {
            daemon: mark("daemon.log"),
            ui: mark("ui.log"),
            early: mark("ui-early.log"),
        }
    }

    fn daemon(&self) -> String {
        since(&self.daemon.0, self.daemon.1)
    }

    fn ui(&self) -> String {
        since(&self.ui.0, self.ui.1)
    }

    fn early(&self) -> String {
        since(&self.early.0, self.early.1)
    }

    fn dump(&self) -> String {
        format!(
            "--- daemon.log ---\n{}\n--- ui.log ---\n{}\n--- ui-early.log ---\n{}\n",
            self.daemon(),
            self.ui(),
            self.early()
        )
    }
}

fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        thread::sleep(POLL);
    }
    done()
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let quit = Command::new(EXE)
            .arg("--quit")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if quit.is_err() {
            eprintln!("could not run --quit: {quit:?}");
        }
        if !wait_until(Duration::from_secs(10), || {
            self.0.try_wait().ok().flatten().is_some()
        }) {
            let _ = self.0.kill();
        }
    }
}

#[test]
fn the_daemon_starts_a_ui_that_completes_the_hello_handshake() {
    if !enabled() {
        eprintln!("skipped: set CI or VAULTKEEPER_UI_LAUNCH_TEST=1 to run it");
        return;
    }
    let logs = Logs::new();

    let child = Command::new(EXE)
        .args(["--tray", "--detached"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the daemon");
    let mut daemon = Daemon(child);

    let ready = wait_until(DAEMON_WAIT, || {
        daemon.0.try_wait().ok().flatten().is_some() || logs.daemon().contains(DAEMON_READY)
    });
    assert!(
        ready && daemon.0.try_wait().expect("poll the daemon").is_none(),
        "the daemon did not come up\n{}",
        logs.dump()
    );

    let second = Command::new(EXE)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run the second launch");
    assert!(second.success(), "the second launch failed: {second}");

    let connected = wait_until(UI_WAIT, || {
        logs.ui().contains(UI_CONNECTED) || logs.early().contains(UI_CONNECTED)
    });
    assert!(
        connected,
        "the UI process never completed the handshake with the daemon\n{}",
        logs.dump()
    );
    assert!(
        !logs.daemon().contains("stopped answering"),
        "the daemon killed the UI\n{}",
        logs.dump()
    );
}
