//! Whether the desktop services the Linux chains lean on own their well-known D-Bus names
//! (linux-plan.md 1b): the portal, the notification daemon and the tray watcher on the session
//! bus, logind on the system bus. Asked once through `NameHasOwner` and cached; a missing bus is
//! `Unavailable` with the reason, never a panic. vk-linux has no D-Bus client, so this lives here.

use std::{
    sync::{OnceLock, mpsc},
    thread,
    time::Duration,
};

use zbus::{Connection, connection::Builder};

use crate::security::Probe;

pub const PORTAL: &str = "org.freedesktop.portal.Desktop";
pub const NOTIFICATIONS: &str = "org.freedesktop.Notifications";
pub const TRAY_WATCHER: &str = "org.kde.StatusNotifierWatcher";
pub const LOGIND: &str = "org.freedesktop.login1";
pub const SCREENSAVER_KDE: &str = "org.freedesktop.ScreenSaver";
pub const SCREENSAVER_GNOME: &str = "org.gnome.ScreenSaver";

const TIMEOUT: Duration = Duration::from_secs(2);
/// The whole run, covering a connection handshake that `method_timeout` does not bound.
const OVERALL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopNames {
    pub portal: Probe,
    pub notifications: Probe,
    pub tray_watcher: Probe,
    pub logind: Probe,
    /// Either lock-signal source power/linux.rs listens to on the session bus (KDE or GNOME).
    pub screensaver: Probe,
}

/// The probes, run on the first call only.
#[must_use]
pub fn desktop_names() -> &'static DesktopNames {
    static CACHE: OnceLock<DesktopNames> = OnceLock::new();
    CACHE.get_or_init(run)
}

fn run() -> DesktopNames {
    let (tx, rx) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("dbus-name-probes".to_owned())
        .spawn(move || {
            let _ = tx.send(zbus::block_on(ask()));
        });
    match spawned {
        Ok(_) => rx
            .recv_timeout(OVERALL)
            .unwrap_or_else(|_| all_unavailable("the D-Bus name probes timed out")),
        Err(error) => all_unavailable(&format!("cannot start the D-Bus name probes: {error}")),
    }
}

fn all_unavailable(why: &str) -> DesktopNames {
    let probe = Probe::Unavailable(why.to_owned());
    DesktopNames {
        portal: probe.clone(),
        notifications: probe.clone(),
        tray_watcher: probe.clone(),
        logind: probe.clone(),
        screensaver: probe,
    }
}

async fn ask() -> DesktopNames {
    let session = connect(Builder::session(), "session").await;
    let system = connect(Builder::system(), "system").await;
    let (portal, notifications, tray_watcher) = (
        owner(&session, PORTAL).await,
        owner(&session, NOTIFICATIONS).await,
        owner(&session, TRAY_WATCHER).await,
    );
    DesktopNames {
        portal,
        notifications,
        tray_watcher,
        logind: owner(&system, LOGIND).await,
        screensaver: screensaver(&session).await,
    }
}

async fn screensaver(session: &Result<Connection, String>) -> Probe {
    let kde = owner(session, SCREENSAVER_KDE).await;
    if kde == Probe::Available {
        return kde;
    }
    let gnome = owner(session, SCREENSAVER_GNOME).await;
    if gnome == Probe::Available {
        return gnome;
    }
    kde
}

async fn connect(builder: Builder<'_>, bus: &str) -> Result<Connection, String> {
    builder
        .method_timeout(TIMEOUT)
        .build()
        .await
        .map_err(|error| format!("no {bus} bus: {error}"))
}

async fn owner(connection: &Result<Connection, String>, name: &'static str) -> Probe {
    let asked = match connection {
        Ok(connection) => name_has_owner(connection, name).await,
        Err(why) => Err(why.clone()),
    };
    to_probe(name, asked)
}

async fn name_has_owner(connection: &Connection, name: &'static str) -> Result<bool, String> {
    let reply = connection
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "NameHasOwner",
            &(name,),
        )
        .await
        .map_err(|error| error.to_string())?;
    reply
        .body()
        .deserialize::<bool>()
        .map_err(|error| error.to_string())
}

fn to_probe(name: &str, asked: Result<bool, String>) -> Probe {
    match asked {
        Ok(true) => Probe::Available,
        Ok(false) => Probe::Unavailable(format!("nothing owns {name}")),
        Err(why) => Probe::Unavailable(format!("{name}: {why}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_without_an_owner_is_unavailable_with_its_name() {
        assert_eq!(to_probe(PORTAL, Ok(true)), Probe::Available);
        assert_eq!(
            to_probe(PORTAL, Ok(false)),
            Probe::Unavailable("nothing owns org.freedesktop.portal.Desktop".to_owned())
        );
        assert!(matches!(
            to_probe(LOGIND, Err("no system bus".to_owned())),
            Probe::Unavailable(why) if why.contains("no system bus")
        ));
    }

    #[test]
    fn the_probes_never_panic_and_are_cached() {
        let first = desktop_names();
        assert!(std::ptr::eq(first, desktop_names()));
        for probe in [
            &first.portal,
            &first.notifications,
            &first.tray_watcher,
            &first.logind,
        ] {
            tracing::info!(?probe, "desktop name probe");
        }
    }
}
