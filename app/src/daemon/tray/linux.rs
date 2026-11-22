//! The tray on Linux: a StatusNotifierItem through ksni. Slint's own Linux tray hard-codes the id
//! `slint-tray` and only sends pixmaps, so the daemon drives the protocol itself and the Slint
//! `TrayIcon` stays for macOS and Windows.

use std::{future::Future, sync::Arc, time::Duration};

use ashpd::desktop::settings::{ColorScheme, Settings};
use futures_util::StreamExt as _;
use ksni::{
    Handle as ItemHandle, Icon, MenuItem, OfflineReason, Tray, TrayMethods as _,
    menu::{StandardItem, SubMenu},
};
use vk_platform::desktop_file::{APP_ID, data_home};

use super::{
    Snapshot,
    icon::{self, PIXMAP_SIZES},
    menu::{self, Entry, MenuState},
};
use crate::{
    daemon::{Daemon, routing::TrayAction},
    os::{
        linux::portal,
        security_gate::{Distro, detect_distro, set_tray_report, tray_chain},
        taskbar,
        tray_way::{bar_is_dark, session_desktop},
    },
    settings::TrayIconChoice,
};

const WATCHER_NAME: &str = "org.kde.StatusNotifierWatcher";
/// A session bus or portal that does not answer must not hold up the daemon's start.
const BUS_TIMEOUT: Duration = Duration::from_secs(5);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(8);

/// Keeps the item registered while the shell lives; dropping it unregisters.
pub struct Handle {
    item: Option<ItemHandle<Item>>,
    theme: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(theme) = &self.theme {
            theme.abort();
        }
        if let Some(item) = &self.item {
            drop(item.shutdown());
        }
    }
}

impl Handle {
    const fn none() -> Self {
        Self {
            item: None,
            theme: None,
        }
    }
}

struct Item {
    daemon: Arc<Daemon>,
    distro: Distro,
    desktop: String,
    menu: MenuState,
    choice: TrayIconChoice,
    system_dark: Option<bool>,
    icon_installed: bool,
    pixmaps: Vec<Icon>,
}

impl Item {
    fn new(daemon: &Arc<Daemon>, distro: Distro, system_dark: Option<bool>) -> Self {
        let icon_installed = icon::icon_paths(data_home().as_deref())
            .iter()
            .any(|path| path.exists());
        let mut item = Self {
            daemon: Arc::clone(daemon),
            distro,
            desktop: session_desktop(),
            menu: MenuState::default(),
            choice: daemon.settings().tray_icon,
            system_dark,
            icon_installed,
            pixmaps: Vec::new(),
        };
        item.pixmaps = item.render();
        item
    }

    fn render(&self) -> Vec<Icon> {
        let glyph = glyph_for(self.choice, self.system_dark, self.distro, &self.desktop);
        PIXMAP_SIZES
            .iter()
            .filter_map(|&px| {
                let pixels = taskbar::rasterise_rgba(glyph, px)?;
                Some(Icon {
                    width: i32::try_from(pixels.width()).ok()?,
                    height: i32::try_from(pixels.height()).ok()?,
                    data: icon::argb32(pixels.as_bytes()),
                })
            })
            .collect()
    }

    fn restyle(&mut self, choice: TrayIconChoice, system_dark: Option<bool>) {
        if (choice, system_dark) != (self.choice, self.system_dark) {
            self.choice = choice;
            self.system_dark = system_dark;
            self.pixmaps = self.render();
        }
    }
}

/// Omarchy's bar is transparent over the wallpaper and draws dark icons whatever the colour
/// scheme says, so a scheme-driven white glyph disappears there. Sway and plain Hyprland bars are
/// dark whatever the scheme says, so Auto must not follow a light scheme to a black glyph.
fn glyph_for(
    choice: TrayIconChoice,
    system_dark: Option<bool>,
    distro: Distro,
    desktop: &str,
) -> taskbar::Glyph {
    let bar_dark = if choice != TrayIconChoice::Auto {
        system_dark
    } else if distro == Distro::Omarchy {
        Some(false)
    } else if bar_is_dark(desktop) {
        Some(true)
    } else {
        system_dark
    };
    taskbar::Glyph::choose(choice, bar_dark)
}

fn dispatch(daemon: &Arc<Daemon>, action: TrayAction) {
    let daemon = Arc::clone(daemon);
    if let Err(error) = slint::invoke_from_event_loop(move || super::run(&daemon, action)) {
        tracing::error!(%error, ?action, "cannot reach the event loop for a tray action");
    }
}

fn convert(entries: Vec<Entry>) -> Vec<MenuItem<Item>> {
    entries
        .into_iter()
        .map(|entry| match entry {
            Entry::Item {
                label,
                enabled,
                action,
            } => StandardItem {
                label: menu::escape_label(&label),
                enabled,
                activate: Box::new(move |item: &mut Item| dispatch(&item.daemon, action)),
                ..StandardItem::default()
            }
            .into(),
            Entry::Note(text) => StandardItem {
                label: menu::escape_label(&text),
                enabled: false,
                ..StandardItem::default()
            }
            .into(),
            Entry::Submenu { label, items } => SubMenu {
                label: menu::escape_label(&label),
                submenu: convert(items),
                ..SubMenu::default()
            }
            .into(),
            Entry::Separator => MenuItem::Separator,
        })
        .collect()
}

impl Tray for Item {
    fn id(&self) -> String {
        APP_ID.to_owned()
    }

    fn title(&self) -> String {
        "Vaultkeeper".to_owned()
    }

    fn icon_name(&self) -> String {
        icon::icon_name(self.choice, self.icon_installed)
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        self.pixmaps.clone()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        dispatch(&self.daemon, TrayAction::QuickSearch);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        convert(menu::build(&self.menu))
    }

    fn watcher_online(&self) {
        publish(&Ok(()), self.distro);
    }

    fn watcher_offline(&self, reason: OfflineReason) -> bool {
        publish(&Err(format!("{WATCHER_NAME}: {reason:?}")), self.distro);
        true
    }
}

fn publish(watcher: &Result<(), String>, distro: Distro) {
    let report = tray_chain(watcher, distro, &session_desktop()).evaluate();
    if let (Some(fix), Err(why)) = (&report.fix, watcher) {
        tracing::warn!(%why, %fix, "no tray host");
    } else {
        tracing::info!(status = report.status.label(), "tray host");
    }
    set_tray_report(report);
}

async fn within<T>(future: impl Future<Output = T>) -> Result<T, String> {
    tokio::time::timeout(BUS_TIMEOUT, future)
        .await
        .map_err(|_| format!("no answer within {} s", BUS_TIMEOUT.as_secs()))
}

async fn watcher_present() -> Result<(), String> {
    let connection = ashpd::zbus::Connection::session()
        .await
        .map_err(|error| format!("session bus: {error}"))?;
    let bus = ashpd::zbus::fdo::DBusProxy::new(&connection)
        .await
        .map_err(|error| format!("session bus: {error}"))?;
    let name =
        ashpd::zbus::names::BusName::try_from(WATCHER_NAME).map_err(|error| error.to_string())?;
    match bus.name_has_owner(name).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!("{WATCHER_NAME} has no owner")),
        Err(error) => Err(format!("session bus: {error}")),
    }
}

const fn is_dark(scheme: ColorScheme) -> Option<bool> {
    match scheme {
        ColorScheme::PreferDark => Some(true),
        ColorScheme::PreferLight => Some(false),
        ColorScheme::NoPreference => None,
    }
}

async fn system_dark() -> Option<bool> {
    portal::ensure_registered().await;
    let settings = Settings::new().await.ok()?;
    settings.color_scheme().await.ok().and_then(is_dark)
}

async fn follow_color_scheme(item: ItemHandle<Item>) {
    portal::ensure_registered().await;
    let Ok(settings) = Settings::new().await else {
        return;
    };
    let Ok(changes) = settings.receive_color_scheme_changed().await else {
        return;
    };
    let mut changes = std::pin::pin!(changes);
    while let Some(scheme) = changes.next().await {
        let dark = is_dark(scheme);
        let kept = item
            .update(|item| {
                let choice = item.choice;
                item.restyle(choice, dark);
            })
            .await;
        if kept.is_none() {
            break;
        }
    }
}

/// A missing host is not an error: the item registers when one appears, and without one the
/// hotkey and the launcher entry still work (C13, "no tray").
pub fn install(daemon: &Arc<Daemon>) -> anyhow::Result<Handle> {
    let runtime = daemon.runtime().clone();
    let distro = detect_distro();
    let started = runtime.block_on(tokio::time::timeout(
        INSTALL_TIMEOUT,
        start_item(daemon, distro),
    ));
    let item = match started {
        Ok(Ok(item)) => item,
        Ok(Err(why)) => return Ok(tray_less(&why, distro)),
        Err(_) => {
            return Ok(tray_less(
                &format!("no answer within {} s", INSTALL_TIMEOUT.as_secs()),
                distro,
            ));
        }
    };
    let theme = runtime.spawn(follow_color_scheme(item.clone()));
    follow(daemon, &item)?;
    Ok(Handle {
        item: Some(item),
        theme: Some(theme),
    })
}

/// The three bus conversations run on the main thread before the event loop, so they share one
/// bound instead of each adding its own.
async fn start_item(daemon: &Arc<Daemon>, distro: Distro) -> Result<ItemHandle<Item>, String> {
    let watcher = within(watcher_present()).await.and_then(|probe| probe);
    publish(&watcher, distro);
    let dark = within(system_dark()).await.ok().flatten();
    let item = Item::new(daemon, distro, dark);
    // Without this a panel that starts after the daemon (Waybar at login) would be an error.
    within(item.assume_sni_available(true).spawn())
        .await?
        .map_err(|error| error.to_string())
}

fn tray_less(why: &str, distro: Distro) -> Handle {
    publish(&Err(why.to_owned()), distro);
    Handle::none()
}

fn follow(daemon: &Arc<Daemon>, item: &ItemHandle<Item>) -> anyhow::Result<()> {
    let item = item.clone();
    let watched = Arc::clone(daemon);
    let mut shown: Option<(MenuState, TrayIconChoice)> = None;
    super::follow_changes(daemon, move || {
        let state = menu_state(super::snapshot(&watched));
        let choice = watched.settings().tray_icon;
        if shown.as_ref() != Some(&(state.clone(), choice)) {
            shown = Some((state.clone(), choice));
            let item = item.clone();
            let spawned = slint::spawn_local(async move {
                item.update(|item| {
                    item.menu = state;
                    let dark = item.system_dark;
                    item.restyle(choice, dark);
                })
                .await;
            });
            if let Err(error) = spawned {
                tracing::warn!(%error, "cannot update the tray");
            }
        }
        !item.is_closed()
    })
}

fn menu_state(snapshot: Snapshot) -> MenuState {
    MenuState {
        locked: snapshot.locked,
        logged_in: snapshot.logged_in,
        accounts: snapshot.accounts,
        syncing: snapshot.syncing,
        sync_label: snapshot.sync_label,
        update_label: snapshot.update_label,
        update_enabled: snapshot.update_enabled,
        restart_to_update: snapshot.restart_to_update,
        restart_by_hand: snapshot.restart_by_hand,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_is_black_on_omarchy_even_with_a_dark_scheme() {
        assert_eq!(
            glyph_for(
                TrayIconChoice::Auto,
                Some(true),
                Distro::Omarchy,
                "Hyprland"
            ),
            taskbar::Glyph::Black
        );
    }

    #[test]
    fn auto_follows_the_scheme_elsewhere() {
        assert_eq!(
            glyph_for(
                TrayIconChoice::Auto,
                Some(true),
                Distro::Ubuntu,
                "ubuntu:GNOME"
            ),
            taskbar::Glyph::White
        );
        assert_eq!(
            glyph_for(TrayIconChoice::Auto, None, Distro::Fedora, "GNOME"),
            taskbar::Glyph::Neutral
        );
    }

    #[test]
    fn auto_is_white_on_the_always_dark_bars_of_sway_and_plain_hyprland() {
        for (distro, desktop) in [
            (Distro::Ubuntu, "sway"),
            (Distro::OtherArch, "Hyprland"),
            (Distro::Fedora, "sway"),
        ] {
            for scheme in [Some(false), Some(true), None] {
                assert_eq!(
                    glyph_for(TrayIconChoice::Auto, scheme, distro, desktop),
                    taskbar::Glyph::White,
                    "{desktop} {scheme:?}"
                );
            }
        }
    }

    #[test]
    fn an_explicit_black_stays_black_on_sway() {
        assert_eq!(
            glyph_for(TrayIconChoice::Black, Some(true), Distro::Ubuntu, "sway"),
            taskbar::Glyph::Black
        );
    }

    #[test]
    fn an_explicit_choice_wins_on_omarchy() {
        assert_eq!(
            glyph_for(
                TrayIconChoice::White,
                Some(false),
                Distro::Omarchy,
                "Hyprland"
            ),
            taskbar::Glyph::White
        );
    }
}
