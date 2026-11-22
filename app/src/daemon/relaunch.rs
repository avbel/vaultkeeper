//! Starting the daemon again after an upgrade (Linux). A process this one spawns inherits its
//! Landlock rules for good: the new daemon would add its own on top, could not execute the
//! upgraded binary at all (the rule names the old file), and could not run what a daemon does
//! before it sandboxes itself. So a sandboxed daemon asks the systemd user manager to start the
//! new one, which then begins outside any sandbox like a first start. Without that manager the
//! upgrade watch does not let the daemon quit at all ([`Route::Manual`]).

use std::{ffi::OsString, path::Path, time::Duration};

use zbus::Variant;

use crate::os::self_protection::{self, Sandbox};

const START_TIMEOUT: Duration = Duration::from_secs(5);

/// The variables the new daemon gets. Any process of this user can read a unit's environment
/// (`systemctl --user show -p Environment`), which it cannot do with the daemon's own
/// (non-dumpable), so nothing else the daemon happened to inherit from a shell goes in: only
/// what Vaultkeeper and the display and font stacks under it read, none of it secret.
const CARRIED: [&str; 14] = [
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "HOME",
    "LANG",
    "LANGUAGE",
    "LOGNAME",
    "PATH",
    "RUST_LOG",
    "TZ",
    "USER",
    // Debug builds only: lets a test attach a tracer.
    "VK_ALLOW_TRACER",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XCURSOR_THEME",
];
/// `VAULTKEEPER_*` are this app's switches (the sandbox request, test data directories),
/// `XDG_*` the session's directories and desktop name, `LC_*` the locale.
const CARRIED_PREFIXES: [&str; 3] = ["VAULTKEEPER_", "XDG_", "LC_"];
/// The token belongs to the launch that started the old daemon: stale, and a compositor
/// credential. The cookie is ConsoleKit's per-session secret on the systems that still set it.
const NEVER_CARRIED: [&str; 2] = ["XDG_ACTIVATION_TOKEN", "XDG_SESSION_COOKIE"];

/// How an upgraded daemon gets started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// No sandbox: a child of this process starts as free as this one did.
    Spawn,
    Systemd,
    /// Sandboxed with no manager to ask: a child would be refused the new binary after this
    /// daemon has already shut down, so the daemon stays and the user restarts it.
    Manual,
}

#[must_use]
pub const fn route(sandboxed: bool, manager_reachable: bool) -> Route {
    match (sandboxed, manager_reachable) {
        (false, _) => Route::Spawn,
        (true, true) => Route::Systemd,
        (true, false) => Route::Manual,
    }
}

/// Whether the systemd user manager answers on the session bus.
pub async fn manager_reachable() -> bool {
    let ping = async {
        let connection = session().await?;
        connection
            .call_method(
                Some(MANAGER),
                MANAGER_PATH,
                Some("org.freedesktop.DBus.Peer"),
                "Ping",
                &(),
            )
            .await
            .map_err(|error| error.to_string())
    };
    match tokio::time::timeout(START_TIMEOUT, ping).await {
        Ok(Ok(_)) => true,
        Ok(Err(error)) => {
            tracing::debug!(error, "no systemd user manager");
            false
        }
        Err(_) => false,
    }
}

const MANAGER: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";

async fn session() -> Result<zbus::Connection, String> {
    zbus::connection::Builder::session()
        .method_timeout(START_TIMEOUT)
        .build()
        .await
        .map_err(|error| error.to_string())
}

/// Starts the upgraded binary, which waits for this process to exit before taking the instance
/// lock. A user unit's `Restart=` does not apply: this exit is a clean one.
pub fn start(runtime: &tokio::runtime::Runtime, exe: &Path) {
    let pid = std::process::id().to_string();
    if sandboxed() {
        let started = runtime.block_on(async {
            tokio::time::timeout(START_TIMEOUT, start_unit(exe, &pid))
                .await
                .map_err(|_| "the systemd user manager did not answer in time".to_owned())?
        });
        match started {
            Ok(unit) => {
                tracing::info!(exe = %exe.display(), unit, "systemd starts the upgraded Vaultkeeper");
                return;
            }
            // The watch saw the manager a moment ago; the spawn below is all that is left.
            Err(error) => tracing::warn!(
                error,
                "systemd did not start the upgraded Vaultkeeper; starting it from inside this sandbox"
            ),
        }
    }
    match std::process::Command::new(exe)
        .args(["--tray", "--wait-for", &pid])
        .spawn()
    {
        Ok(_) => tracing::info!(exe = %exe.display(), "started the upgraded Vaultkeeper"),
        Err(error) => tracing::error!(%error, "cannot start the upgraded Vaultkeeper"),
    }
}

pub fn sandboxed() -> bool {
    matches!(
        self_protection::sandbox(),
        Some(Sandbox::Applied { enforcement, .. })
            if enforcement != vk_platform::sandbox::Enforcement::None
    )
}

/// `StartTransientUnit`, what `systemd-run --user` sends.
async fn start_unit(exe: &Path, pid: &str) -> Result<String, String> {
    let exe = exe
        .to_str()
        .ok_or_else(|| "the install path is not UTF-8".to_owned())?;
    let unit = format!("vaultkeeper-restart-{pid}.service");
    let command = vec![(
        exe.to_owned(),
        vec![
            exe.to_owned(),
            "--tray".to_owned(),
            "--wait-for".to_owned(),
            pid.to_owned(),
        ],
        false,
    )];
    let properties: Vec<(&str, Variant<'_>)> = vec![
        (
            "Description",
            Variant::from("Vaultkeeper (restarted after an upgrade)"),
        ),
        ("ExecStart", Variant::from(command)),
        (
            "Environment",
            Variant::from(unit_environment(std::env::vars_os())),
        ),
        // Without it the finished unit stays listed until the session ends.
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

/// `NAME=value` for the carried variables. One assignment systemd refuses fails the whole
/// request, so a value with a control character is left out too.
fn unit_environment(vars: impl Iterator<Item = (OsString, OsString)>) -> Vec<String> {
    vars.filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(name, value)| {
            carried(name) && !value.chars().any(|c| c.is_control() && c != '\t')
        })
        .map(|(name, value)| format!("{name}={value}"))
        .collect()
}

fn carried(name: &str) -> bool {
    let listed = CARRIED.contains(&name)
        || CARRIED_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix));
    listed
        && !NEVER_CARRIED.contains(&name)
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_gets_only_the_variables_vaultkeeper_reads() {
        use std::os::unix::ffi::OsStringExt as _;
        let vars = [
            ("VAULTKEEPER_LANDLOCK", "1"),
            ("VAULTKEEPER_TEST_DATA_DIR", "/tmp/data dir"),
            ("WAYLAND_DISPLAY", "wayland-0"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("LC_TIME", "en_GB.UTF-8"),
            ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI"),
            ("GITHUB_TOKEN", "ghp_secret"),
            ("SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh"),
            ("XDG_ACTIVATION_TOKEN", "gnome-shell/token"),
            ("XDG_SESSION_COOKIE", "0123abcd-1.2"),
            ("DESKTOP_STARTUP_ID", "stale"),
            ("INVOCATION_ID", "0123"),
            ("NOTIFY_SOCKET", "/run/user/1000/systemd/notify"),
            ("XDG_BAD%NAME", "x"),
            ("LANG", "a\nb"),
        ]
        .into_iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .chain([(OsString::from("PATH"), OsString::from_vec(vec![0xff]))]);
        assert_eq!(
            unit_environment(vars),
            [
                "VAULTKEEPER_LANDLOCK=1",
                "VAULTKEEPER_TEST_DATA_DIR=/tmp/data dir",
                "WAYLAND_DISPLAY=wayland-0",
                "XDG_RUNTIME_DIR=/run/user/1000",
                "LC_TIME=en_GB.UTF-8",
            ]
        );
    }

    #[test]
    fn a_sandboxed_daemon_without_a_manager_must_not_quit_for_the_upgrade() {
        assert_eq!(route(false, false), Route::Spawn);
        assert_eq!(route(false, true), Route::Spawn);
        assert_eq!(route(true, true), Route::Systemd);
        assert_eq!(route(true, false), Route::Manual);
    }
}
