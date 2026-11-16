//! A trail the UI process leaves before (and beside) its real log. `ui.log` only exists once
//! `init_logging` got through hardening, argument parsing and the log directory, so a UI that dies
//! or hangs before that point would leave nothing. This writes plain lines with no checks of its
//! own, to `ui-early.log` in the log directory, or in the temp directory when that cannot be opened.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::PathBuf,
};

use super::log_file::log_dir;

const FILE_NAME: &str = "ui-early.log";
/// Past this the file starts over; every start adds a handful of lines.
const MAX_BYTES: u64 = 64 * 1024;

/// Appends one timestamped line. Never fails: it runs where nothing else can report a problem.
pub fn note(message: &str) {
    let line = format!(
        "{} pid={} {message}\n",
        chrono::Local::now().format("%H:%M:%S%.3f"),
        std::process::id()
    );
    for path in candidates() {
        if fs::metadata(&path).is_ok_and(|meta| meta.len() > MAX_BYTES) {
            let _ = fs::remove_file(&path);
        }
        let opened = OpenOptions::new().create(true).append(true).open(&path);
        if let Ok(mut file) = opened
            && file.write_all(line.as_bytes()).is_ok()
        {
            return;
        }
    }
}

/// Records the start of a process that is about to harden itself, and routes its panics here too.
pub fn start(args: &[String]) {
    note(&format!(
        "start exe={:?} args={args:?}",
        std::env::current_exe().ok()
    ));
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        note(&format!(
            "panic thread={:?} {info}\n{}",
            thread.name(),
            std::backtrace::Backtrace::force_capture()
        ));
        previous(info);
    }));
}

fn candidates() -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(2);
    if let Some(dir) = log_dir().filter(|dir| dir.is_dir()) {
        paths.push(dir.join(FILE_NAME));
    }
    paths.push(std::env::temp_dir().join(format!("vaultkeeper-{FILE_NAME}")));
    paths
}
