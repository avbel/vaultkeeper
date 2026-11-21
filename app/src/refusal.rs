//! A refused start, shown to someone who did not start Vaultkeeper from a terminal (linux-plan.md
//! 1c): the daemon writes the refusal to `last-refusal.txt`, posts a desktop notification and
//! starts `vaultkeeper --ui --refusal <file>`, a window that talks to no daemon and holds no
//! secrets. Without a display (the Wayland refusal) only the file and the notification remain.

use std::{
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use slint::ComponentHandle as _;

use crate::os::security_gate::SKIP_FLAG;

const RECORD: &str = "last-refusal.txt";
/// The record is ours, but the window still reads no more than a report can need.
const MAX_REPORT: u64 = 64 * 1024;

/// `$XDG_STATE_HOME/vaultkeeper/last-refusal.txt` on Linux; next to the data elsewhere, where no
/// start is refused today.
#[must_use]
pub fn record_path(data_dir: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    if let Some(state) = vk_platform::desktop_file::state_home() {
        return state.join("vaultkeeper").join(RECORD);
    }
    data_dir.join(RECORD)
}

/// Daemon side: records `text` and tells the user however this session allows.
pub fn present(data_dir: &Path, text: &str) {
    let path = record_path(data_dir);
    if let Err(error) = write_record(&path, text) {
        tracing::error!(%error, path = %path.display(), "cannot record the refusal");
        return;
    }
    tracing::info!(path = %path.display(), "refusal recorded");
    notify(text);
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            tracing::error!(%error, "cannot locate the binary for the refusal window");
            return;
        }
    };
    if let Err(error) = std::process::Command::new(exe)
        .args(["--ui", "--refusal"])
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .spawn()
    {
        tracing::error!(%error, "cannot open the refusal window");
    }
}

fn write_record(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(text.as_bytes())
}

/// The refused items of a refusal text: the lines between the heading and the ways out.
#[must_use]
pub fn refused_items(text: &str) -> String {
    text.lines()
        .skip_while(|line| !line.is_empty())
        .skip(1)
        .take_while(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Through `notify-send` until the D-Bus registry (3a) can call `org.freedesktop.Notifications`
/// itself; a session without it still has the window and the file.
fn notify(text: &str) {
    let posted = std::process::Command::new("notify-send")
        .args(["--app-name=Vaultkeeper", "--urgency=critical"])
        .arg("Vaultkeeper did not start")
        .arg(refused_items(text))
        .stdin(std::process::Stdio::null())
        .status();
    match posted {
        Ok(status) if status.success() => {}
        Ok(status) => tracing::warn!(%status, "notify-send failed"),
        Err(error) => tracing::debug!(%error, "no notify-send in this session"),
    }
}

/// `--ui --refusal <file>`: the window with "Quit" and "Start anyway (not recommended)".
pub fn run(path: &Path) -> anyhow::Result<()> {
    let mut report = String::new();
    std::fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(MAX_REPORT)
        .read_to_string(&mut report)
        .with_context(|| format!("read {}", path.display()))?;
    crate::run::select_backend(crate::run::Backend::Standalone)?;
    let window = crate::ui::RefusalWindow::new().context("create the refusal window")?;
    // The heading repeats the window title.
    let body = report
        .split_once("\n\n")
        .map_or(report.as_str(), |(_, rest)| rest);
    window.set_report(body.into());
    window.on_quit(quit);
    window.on_start_anyway(|| {
        start_anyway();
        quit();
    });
    window.run().context("show the refusal window")
}

fn quit() {
    if let Err(error) = slint::quit_event_loop() {
        tracing::error!(%error, "cannot close the refusal window");
    }
}

/// Starts the daemon once with the flag; the flag is never written to autostart.
fn start_anyway() {
    let started = std::env::current_exe().and_then(|exe| {
        std::process::Command::new(exe)
            .args(["--tray", SKIP_FLAG])
            .stdin(std::process::Stdio::null())
            .spawn()
    });
    if let Err(error) = started {
        tracing::error!(%error, "cannot start Vaultkeeper despite the refusal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_notification_lists_only_the_refused_items() {
        let text = "Vaultkeeper will not start: a required protection is missing.\n\n\
                    Kernel: SO_PEERPIDFD missing — boot a kernel 6.13 or newer\n\
                    Wayland session: no WAYLAND_DISPLAY — log in to a Wayland session\n\n\
                    Start anyway once with `vaultkeeper --skip-security-issues`.\n";
        assert_eq!(
            refused_items(text),
            "Kernel: SO_PEERPIDFD missing — boot a kernel 6.13 or newer\n\
             Wayland session: no WAYLAND_DISPLAY — log in to a Wayland session"
        );
    }

    #[test]
    fn the_record_is_private_and_replaced_on_each_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state/vaultkeeper").join(RECORD);
        write_record(&path, "first").expect("write");
        write_record(&path, "second").expect("rewrite");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
