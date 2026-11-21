//! Host-app registration with `xdg-desktop-portal`.
//!
//! A non-sandboxed process has no app id the portal can trust, so permission stores and dialog
//! titles fall back to "unknown". The host Registry binds the id to this process once, and the
//! binding is lost whenever the portal restarts.

use std::sync::atomic::{AtomicBool, Ordering};

use ashpd::{AppID, register_host_app, zbus};
use futures_util::StreamExt as _;
use tokio::sync::OnceCell;
use vk_platform::desktop_file::APP_ID;

const PORTAL_BUS_NAME: &str = "org.freedesktop.portal.Desktop";

static REGISTERED: OnceCell<()> = OnceCell::const_new();
static WATCHER_STARTED: AtomicBool = AtomicBool::new(false);

/// Registers [`APP_ID`] once per process; every portal caller awaits this first. A failure is
/// logged and not retried here, since the portal may simply be absent; the watcher registers
/// again when one appears.
pub async fn ensure_registered() {
    REGISTERED
        .get_or_init(|| async {
            register().await;
            if !WATCHER_STARTED.swap(true, Ordering::AcqRel) {
                tokio::spawn(watch_portal_restarts());
            }
        })
        .await;
}

async fn register() {
    let app_id = match AppID::try_from(APP_ID) {
        Ok(app_id) => app_id,
        Err(error) => {
            tracing::warn!(%error, "portal app id is not a valid application id");
            return;
        }
    };
    if let Err(error) = register_host_app(app_id).await {
        tracing::warn!(%error, "portal host registration failed");
    }
}

async fn watch_portal_restarts() {
    if let Err(error) = watch().await {
        tracing::warn!(%error, "watching the portal for restarts failed");
    }
}

async fn watch() -> zbus::Result<()> {
    let connection = zbus::Connection::session().await?;
    let dbus = zbus::fdo::DBusProxy::new(&connection).await?;
    let mut changes = dbus
        .receive_name_owner_changed_with_args(&[(0, PORTAL_BUS_NAME)])
        .await?;
    while let Some(change) = changes.next().await {
        let has_owner = change.args().is_ok_and(|args| args.new_owner().is_some());
        if has_owner {
            register().await;
        }
    }
    Ok(())
}
