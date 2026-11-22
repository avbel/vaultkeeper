//! Starting the daemon when the extension finds none running. The browser starts this host, so a
//! plain child would stay in the browser's process group and, on Linux, its cgroup: stopped with
//! the browser, and classified as unbound by the daemon check.

use std::{
    io,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

const TRAY_ARG: &str = "--tray";

#[cfg_attr(
    not(target_os = "linux"),
    allow(clippy::unused_async, reason = "only the Linux scope move waits")
)]
pub(super) async fn start_daemon() -> io::Result<()> {
    let exe = std::env::current_exe()?;
    let mut command = launcher(&exe);
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Out of the browser's process group, so a signal to that group does not reach it.
        .process_group(0)
        .spawn()?;
    #[cfg(target_os = "linux")]
    move_to_own_scope(child.id()).await;
    reap(child);
    Ok(())
}

#[cfg(target_os = "macos")]
fn launcher(exe: &Path) -> Command {
    if let Some(bundle) = bundle_path(exe) {
        let mut command = Command::new("/usr/bin/open");
        command
            .arg("-g")
            .arg("-a")
            .arg(bundle)
            .args(["--args", TRAY_ARG]);
        return command;
    }
    let mut command = Command::new(exe);
    command.arg(TRAY_ARG);
    command
}

/// The browser's environment is the session's, which the daemon needs (display, bus, agent
/// sockets), except for the launch credentials the browser was started with.
#[cfg(target_os = "linux")]
fn launcher(exe: &Path) -> Command {
    let mut command = Command::new(exe);
    command.arg(TRAY_ARG);
    for name in BROWSER_LAUNCH_VARS {
        command.env_remove(name);
    }
    command
}

#[cfg(target_os = "linux")]
const BROWSER_LAUNCH_VARS: [&str; 2] = ["XDG_ACTIVATION_TOKEN", "DESKTOP_STARTUP_ID"];

#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "only macOS launches through the app bundle")
)]
fn bundle_path(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle.extension().is_some_and(|ext| ext == "app"))
    .then(|| bundle.to_path_buf())
}

/// The daemon outlives this host; `open` and a daemon that finds another instance exit at once
/// and must not linger as zombies while the host runs.
fn reap(mut child: Child) {
    let spawned = std::thread::Builder::new()
        .name("daemon-reaper".to_owned())
        .spawn(move || {
            if let Err(error) = child.wait() {
                tracing::debug!(%error, "cannot wait for the started daemon");
            }
        });
    if let Err(error) = spawned {
        tracing::debug!(%error, "cannot start the reaper thread");
    }
}

/// Moves the daemon into a scope of its own, as a desktop launcher does, so it leaves the
/// browser's cgroup and its stop. A scope, not a service: a service would be stopped, with every
/// process in it, when the daemon exits to hand over to an upgraded one it started itself.
#[cfg(target_os = "linux")]
async fn move_to_own_scope(pid: u32) {
    use crate::daemon::relaunch::START_TIMEOUT;
    match tokio::time::timeout(START_TIMEOUT, start_scope(pid)).await {
        Ok(Ok(unit)) => tracing::info!(unit, "the started daemon runs in its own scope"),
        Ok(Err(error)) => {
            tracing::warn!(error, "the started daemon stays in the browser's cgroup");
        }
        Err(_) => tracing::warn!("the systemd user manager did not answer in time"),
    }
}

/// `StartTransientUnit` with the daemon's pid, what `systemd-run --user --scope` sends.
#[cfg(target_os = "linux")]
async fn start_scope(pid: u32) -> Result<String, String> {
    use zbus::Variant;

    use crate::daemon::relaunch::{MANAGER, MANAGER_PATH, session};

    let unit = scope_name(pid);
    let properties: Vec<(&str, Variant<'_>)> = vec![
        (
            "Description",
            Variant::from("Vaultkeeper (started for the browser extension)"),
        ),
        ("PIDs", Variant::from(vec![pid])),
        // Without it a failed scope stays listed until the session ends.
        ("CollectMode", Variant::from("inactive-or-failed")),
    ];
    let auxiliary: Vec<(&str, Vec<(&str, Variant<'_>)>)> = Vec::new();
    session()
        .await?
        .call_method(
            Some(MANAGER),
            MANAGER_PATH,
            Some("org.freedesktop.systemd1.Manager"),
            "StartTransientUnit",
            &(unit.as_str(), "fail", properties, auxiliary),
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(unit)
}

/// The daemon check accepts a scope whose name carries the app id.
#[cfg(target_os = "linux")]
fn scope_name(pid: u32) -> String {
    format!("app-{}-{pid}.scope", vk_platform::desktop_file::APP_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_macos_app_bundle_is_found() {
        assert_eq!(
            bundle_path(Path::new(
                "/Applications/Vaultkeeper.app/Contents/MacOS/vaultkeeper"
            )),
            Some(PathBuf::from("/Applications/Vaultkeeper.app"))
        );
        assert_eq!(bundle_path(Path::new("/usr/bin/vaultkeeper")), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_scope_is_named_like_a_desktop_launch_of_the_app() {
        assert_eq!(
            scope_name(4242),
            "app-io.github.avbel.Vaultkeeper-4242.scope"
        );
    }
}
