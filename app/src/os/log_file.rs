//! The log file of the daemon and the UI process, `~/Library/Logs/vaultkeeper/<process>.log` (on
//! Windows `%LOCALAPPDATA%\Vaultkeeper\logs`). Under the LaunchAgent, or detached from the
//! console, stderr goes nowhere, so without it an abort leaves no trace.
//!
//! Size-bounded: past [`LOG_CAP`] the file is renamed to `<process>.log.1` (replacing the older
//! one) and a new one starts, so each process keeps at most twice the cap on disk. The file gets
//! exactly what stderr gets; log calls are written to leave secret values out (tokens travel in
//! headers, never in logged URLs).

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

/// About 10 000 lines at the default `info` level.
pub const LOG_CAP: u64 = 1024 * 1024;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// `~/Library/Logs/vaultkeeper`, `%LOCALAPPDATA%\Vaultkeeper\logs` on Windows. Builds with the `vw-it` feature log into
/// `$VAULTKEEPER_TEST_DATA_DIR/logs` instead, so test runs leave the real logs alone.
#[must_use]
pub fn log_dir() -> Option<PathBuf> {
    #[cfg(feature = "vw-it")]
    if let Some(dir) = std::env::var_os("VAULTKEEPER_TEST_DATA_DIR") {
        return Some(PathBuf::from(dir).join("logs"));
    }
    #[cfg(windows)]
    {
        windows_log_dir(std::env::var_os("LOCALAPPDATA"))
    }
    #[cfg(target_os = "linux")]
    {
        vk_platform::desktop_file::state_home().map(|state| state.join("vaultkeeper/logs"))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let home = std::env::var_os("HOME").filter(|home| !home.is_empty())?;
        Some(PathBuf::from(home).join("Library/Logs/vaultkeeper"))
    }
}

/// Local, not roaming: logs have no business following the user to other machines.
#[cfg(any(windows, test))]
fn windows_log_dir(local_app_data: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let base = local_app_data.filter(|base| !base.is_empty())?;
    Some(PathBuf::from(base).join("Vaultkeeper").join("logs"))
}

/// A log file that rotates once it would grow past its cap.
pub struct BoundedLog {
    path: PathBuf,
    file: File,
    written: u64,
    cap: u64,
}

impl BoundedLog {
    /// Opens (or creates) `<dir>/<name>.log`, rotating first if it is already full.
    pub fn open(dir: &Path, name: &str, cap: u64) -> io::Result<Self> {
        create_log_dir(dir)?;
        let path = dir.join(format!("{name}.log"));
        let file = open_append(&path)?;
        let written = file.metadata()?.len();
        let mut log = Self {
            path,
            file,
            written,
            cap,
        };
        if log.written >= cap {
            log.rotate()?;
        }
        Ok(log)
    }

    fn rotate(&mut self) -> io::Result<()> {
        let mut old = self.path.clone().into_os_string();
        old.push(".1");
        fs::rename(&self.path, old)?;
        self.file = open_append(&self.path)?;
        self.written = 0;
        Ok(())
    }
}

#[cfg(unix)]
fn create_log_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir)
}

#[cfg(not(unix))]
fn create_log_dir(dir: &Path) -> io::Result<()> {
    vk_platform::fs::ensure_private_dir(dir)
}

#[cfg(unix)]
fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(FILE_MODE)
        .open(path)
}

#[cfg(not(unix))]
fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

impl Write for BoundedLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        if self.written > 0 && self.written.saturating_add(len) > self.cap {
            self.rotate()?;
        }
        let wrote = self.file.write(buf)?;
        self.written = self
            .written
            .saturating_add(u64::try_from(wrote).unwrap_or(u64::MAX));
        Ok(wrote)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn size(path: &Path) -> u64 {
        fs::metadata(path).expect("metadata").len()
    }

    #[test]
    fn the_windows_log_dir_is_under_local_app_data() {
        assert_eq!(
            windows_log_dir(Some(r"C:\Users\me\AppData\Local".into())),
            Some(PathBuf::from(r"C:\Users\me\AppData\Local").join("Vaultkeeper/logs"))
        );
        assert_eq!(windows_log_dir(None), None);
        assert_eq!(windows_log_dir(Some(String::new().into())), None);
    }

    #[test]
    fn rotates_before_passing_the_cap_and_keeps_one_old_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        let mut log = BoundedLog::open(&logs, "daemon", 100).expect("open");
        let line = [b'a'; 40];
        for _ in 0..2 {
            log.write_all(&line).expect("write");
        }
        assert_eq!(size(&logs.join("daemon.log")), 80);
        log.write_all(&[b'b'; 40]).expect("write");
        assert_eq!(
            size(&logs.join("daemon.log")),
            40,
            "a new file after rotation"
        );
        assert_eq!(
            fs::read(logs.join("daemon.log.1")).expect("old"),
            [b'a'; 80]
        );
        for _ in 0..3 {
            log.write_all(&[b'c'; 40]).expect("write");
        }
        assert_eq!(size(&logs.join("daemon.log")), 80);
        assert_eq!(
            fs::read(logs.join("daemon.log.1")).expect("old"),
            [[b'b'; 40], [b'c'; 40]].concat(),
            "only one old file is kept"
        );
        assert_eq!(fs::read_dir(&logs).expect("dir").count(), 2);
    }

    #[test]
    fn a_full_file_from_an_earlier_run_is_rotated_at_open_and_appended_to_otherwise() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("ui.log"), [b'x'; 30]).expect("seed");
        let mut log = BoundedLog::open(dir.path(), "ui", 100).expect("open");
        log.write_all(b"next").expect("write");
        assert_eq!(size(&dir.path().join("ui.log")), 34, "appended");
        drop(log);
        fs::write(dir.path().join("ui.log"), [b'x'; 100]).expect("full");
        let _log = BoundedLog::open(dir.path(), "ui", 100).expect("open");
        assert_eq!(size(&dir.path().join("ui.log")), 0);
        assert_eq!(size(&dir.path().join("ui.log.1")), 100);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_and_directory_are_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        let _log = BoundedLog::open(&logs, "daemon", LOG_CAP).expect("open");
        let mode = |path: &Path| fs::metadata(path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&logs), 0o700);
        assert_eq!(mode(&logs.join("daemon.log")), 0o600);
    }
}
