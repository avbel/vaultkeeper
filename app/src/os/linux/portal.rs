//! Host-app registration with `xdg-desktop-portal`.
//!
//! A non-sandboxed process has no app id the portal can trust, so permission stores and dialog
//! titles fall back to "unknown". The host Registry binds the id to this process once, and the
//! binding is lost whenever the portal restarts.
//!
//! Non-dumpable processes (linux-plan.md 1d): xdg-desktop-portal 1.22 identifies a caller the
//! first time a D-Bus connection talks to it by opening `/proc/<pid>/root` (the Flatpak check),
//! and a non-dumpable process denies that to same-user peers. The answer is cached per unique
//! name until that name leaves the bus (`xdp_app_info_registry_ensure_for_invocation_sync`), so:
//! - Register has to run while still dumpable: daemon and UI call
//!   [`super::open::register_before_hardening`] before `harden_after_handshake`.
//! - Every portal call must go over ashpd's shared session connection, the one registered here:
//!   ashpd's default proxies, never `with_connection` or a fresh `Connection::session()`. A
//!   connection first seen after hardening gets "Portal operation not allowed", not just the
//!   "unknown app" treatment.
//! - After a portal restart the cache is empty and nothing gets through until Vaultkeeper
//!   restarts; see [`watch`] for why dumpable is not toggled to register again.

use std::sync::atomic::{AtomicBool, Ordering};

use ashpd::{AppID, desktop::settings::Settings, register_host_app, zbus};
use futures_util::StreamExt as _;
use tokio::sync::OnceCell;
use vk_platform::desktop_file::APP_ID;

const PORTAL_BUS_NAME: &str = "org.freedesktop.portal.Desktop";

static REGISTERED: OnceCell<()> = OnceCell::const_new();
static WATCHER_STARTED: AtomicBool = AtomicBool::new(false);

/// Registers [`APP_ID`] once per process; every portal caller awaits this first. A failure is
/// logged and not retried here, since the portal may simply be absent; the watcher handles a
/// portal that appears or restarts later.
pub async fn ensure_registered() {
    REGISTERED
        .get_or_init(|| async {
            identify().await;
            if !WATCHER_STARTED.swap(true, Ordering::AcqRel) {
                tokio::spawn(watch_portal_restarts());
            }
        })
        .await;
}

/// A refused Register leaves nothing in the portal's cache (only the registered entry is stored),
/// so while still dumpable one ordinary call caches this connection as an anonymous host app:
/// portal calls then work, only without the app id.
async fn identify() {
    if register().await || vk_linux::probes::dumpable() != Ok(true) {
        return;
    }
    let read = async { Settings::new().await?.color_scheme().await };
    if let Err(error) = read.await {
        tracing::debug!(%error, "the portal did not answer the fallback identification either");
    }
}

async fn register() -> bool {
    let app_id = match AppID::try_from(APP_ID) {
        Ok(app_id) => app_id,
        Err(error) => {
            tracing::warn!(%error, "portal app id is not a valid application id");
            return false;
        }
    };
    match register_host_app(app_id).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, "portal host registration failed");
            false
        }
    }
}

async fn watch_portal_restarts() {
    if let Err(error) = watch().await {
        tracing::warn!(%error, "watching the portal for restarts failed");
    }
}

/// A new portal instance cannot be registered with once this process is non-dumpable. Making it
/// dumpable again for the call was rejected: any same-user program can kill the portal, so the
/// window would open on an attacker's demand, and a tracer attached inside it stays attached after
/// dumpable is cleared again, which defeats the C3 memory-read chain (linux-ideas.md §11).
async fn watch() -> zbus::Result<()> {
    // Bus-daemon signals only; this connection never talks to the portal itself.
    let connection = zbus::Connection::session().await?;
    let dbus = zbus::fdo::DBusProxy::new(&connection).await?;
    let mut changes = dbus
        .receive_name_owner_changed_with_args(&[(0, PORTAL_BUS_NAME)])
        .await?;
    while let Some(change) = changes.next().await {
        let has_owner = change.args().is_ok_and(|args| args.new_owner().is_some());
        if !has_owner {
            continue;
        }
        if vk_linux::probes::dumpable() == Ok(false) {
            tracing::warn!(
                "the desktop portal restarted; it refuses Vaultkeeper's portal calls (shortcuts, \
                 auto-type, links, theme) until Vaultkeeper restarts"
            );
        } else {
            identify().await;
        }
    }
    Ok(())
}
