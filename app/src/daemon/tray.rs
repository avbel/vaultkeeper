//! The daemon's only UI: the `TrayIcon` component (no window, nothing rendered). Its menu items
//! are routed like every other trigger, and it follows the vault and settings through watches on
//! the Slint event loop.

#[cfg(not(target_os = "linux"))]
use std::time::{Duration, Instant};
use std::{
    cell::{Cell, RefCell},
    sync::Arc,
};

use slint::language::ColorScheme;
#[cfg(not(target_os = "linux"))]
use slint::{ModelRc, SharedString, VecModel};
use vk_vault::{VaultService, model::SessionState};

use super::{
    Daemon,
    routing::{self, Effect, TrayAction},
};
use crate::{
    os::taskbar::{self, Glyph},
    settings::TrayIconChoice,
    ui::TrayIcon,
    viewmodel::{host, local_time, tray_sync_label},
};

#[cfg(any(target_os = "linux", test))]
mod icon;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", test))]
mod menu;

/// What the daemon's shell keeps alive: Slint's status item, or the StatusNotifierItem service
/// on Linux (whose id Slint hard-codes to `slint-tray`).
#[cfg(not(target_os = "linux"))]
pub(crate) type Handle = TrayIcon;
#[cfg(target_os = "linux")]
pub(crate) use linux::{Handle, install};

#[cfg(not(target_os = "linux"))]
const ATTACH_RETRY: Duration = Duration::from_millis(250);

#[cfg(not(target_os = "linux"))]
pub fn install(daemon: &Arc<Daemon>) -> anyhow::Result<TrayIcon> {
    let tray = TrayIcon::new()?;
    let on = |action: TrayAction| {
        let daemon = Arc::clone(daemon);
        move || run(&daemon, action)
    };
    tray.on_quick_search(on(TrayAction::QuickSearch));
    tray.on_open_vault(on(TrayAction::OpenVault));
    tray.on_generator(on(TrayAction::Generator));
    tray.on_settings(on(TrayAction::Settings));
    tray.on_lock_toggle(on(TrayAction::LockToggle));
    tray.on_sync_now(on(TrayAction::SyncNow));
    tray.on_update(on(TrayAction::Update));
    tray.on_quit(on(TrayAction::Quit));
    let switch = Arc::clone(daemon);
    tray.on_switch_account(move |index| run(&switch, TrayAction::SwitchAccount(index)));
    let clicks = DoubleClick::default();
    let open = Arc::clone(daemon);
    tray.on_icon_clicked(move || {
        if clicks.click(Instant::now(), taskbar::double_click_time()) {
            run(&open, TrayAction::OpenVault);
        }
    });
    refresh(&tray, daemon);
    tray.show()?;
    follow_menu_bar(&tray, daemon);
    follow_taskbar(&tray);
    let weak = tray.as_weak();
    let watched = Arc::clone(daemon);
    follow_changes(daemon, move || {
        weak.upgrade()
            .map(|tray| refresh(&tray, &watched))
            .is_some()
    })?;
    Ok(tray)
}

/// Pairs single clicks into double-clicks. A completed pair is consumed, so a third quick click
/// starts a new pair instead of opening the vault twice.
#[cfg(not(target_os = "linux"))]
#[derive(Default)]
struct DoubleClick {
    pending: Cell<Option<Instant>>,
}

#[cfg(not(target_os = "linux"))]
impl DoubleClick {
    fn click(&self, now: Instant, window: Duration) -> bool {
        let paired = self
            .pending
            .get()
            .is_some_and(|first| now.saturating_duration_since(first) <= window);
        self.pending.set(if paired { None } else { Some(now) });
        paired
    }
}

fn run(daemon: &Arc<Daemon>, action: TrayAction) {
    let vault = daemon.vault();
    let effects = routing::tray(action, &vault.state(), &vault.accounts(), || {
        daemon.typing_target()
    });
    for effect in effects {
        if effect == Effect::Quit {
            if let Err(error) = slint::quit_event_loop() {
                tracing::error!(%error, "cannot quit the event loop");
            }
        } else {
            daemon.apply(effect);
        }
    }
}

/// What the menu shows, read from the daemon. Both the Slint and the Linux menu are built from
/// this, so the labels cannot drift apart.
struct Snapshot {
    locked: bool,
    logged_in: bool,
    accounts: Vec<String>,
    syncing: bool,
    sync_label: String,
    update_label: String,
    update_enabled: bool,
    #[cfg(target_os = "linux")]
    restart_to_update: bool,
}

fn snapshot(daemon: &Daemon) -> Snapshot {
    let vault = daemon.vault();
    let state = vault.state();
    let accounts = vault
        .accounts()
        .iter()
        .map(|account| {
            let mark = if account.active { "✓ " } else { "" };
            format!("{mark}{} @ {}", account.email, host(&account.server))
        })
        .collect();
    let sync = daemon.tray_sync();
    let last_sync = vault.last_sync();
    let sync_label = tray_sync_label(
        last_sync.map(local_time),
        chrono::Local::now().naive_local(),
        sync.failure(vault.active_account_id().as_deref(), last_sync),
    );
    let update = daemon
        .subscribe_update()
        .map(|status| status.borrow().clone());
    Snapshot {
        locked: !matches!(state, SessionState::Unlocked { .. }),
        logged_in: !matches!(state, SessionState::LoggedOut),
        accounts,
        syncing: sync.running,
        sync_label,
        update_label: update
            .as_ref()
            .map(super::update::Status::tray_label)
            .unwrap_or_default(),
        update_enabled: update.is_none_or(|status| status.tray_enabled()),
        #[cfg(target_os = "linux")]
        restart_to_update: daemon.upgraded().is_some(),
    }
}

#[cfg(not(target_os = "linux"))]
fn refresh(tray: &TrayIcon, daemon: &Daemon) {
    let snapshot = snapshot(daemon);
    tray.set_locked(snapshot.locked);
    tray.set_logged_in(snapshot.logged_in);
    let labels: Vec<SharedString> = snapshot.accounts.into_iter().map(Into::into).collect();
    tray.set_accounts(ModelRc::new(VecModel::from(labels)));
    tray.set_syncing(snapshot.syncing);
    tray.set_sync_label(snapshot.sync_label.into());
    tray.set_update_label(snapshot.update_label.into());
    tray.set_update_enabled(snapshot.update_enabled);
    refresh_scheme(tray, daemon);
}

/// The bar's appearance follows the wallpaper; `follow_menu_bar` calls this when it changes.
/// Before the status item has a window the system appearance is the best guess. The Settings
/// choice overrides both; the icon is the opposite shade of the bar it must read on,
/// so "White" is the scheme of a dark bar. `Blue` ignores the bar entirely. Windows has no
/// template images, so there the glyph is rasterised for the taskbar's theme and pixel size.
#[cfg(not(target_os = "linux"))]
fn refresh_scheme(tray: &TrayIcon, daemon: &Daemon) {
    apply_choice(tray, daemon.settings().tray_icon);
}

/// Also used by the `--mock` tray in the UI process, which has no `Daemon` to read the setting
/// from.
pub(crate) fn apply_choice(tray: &TrayIcon, choice: TrayIconChoice) {
    CHOICE.set(choice);
    let dark = match choice {
        TrayIconChoice::Blue => None,
        TrayIconChoice::White => Some(true),
        TrayIconChoice::Black => Some(false),
        TrayIconChoice::Auto if cfg!(windows) => taskbar::taskbar_dark(),
        TrayIconChoice::Auto => {
            crate::os::appkit::menu_bar_dark().or_else(crate::os::appkit::system_dark)
        }
    };
    tray.set_blue_icon(choice == TrayIconChoice::Blue);
    tray.set_menu_bar_scheme(match dark {
        Some(true) => ColorScheme::Dark,
        Some(false) => ColorScheme::Light,
        None => ColorScheme::Unknown,
    });
    render_icon(tray, Glyph::choose(choice, dark));
}

/// Skips the work while neither the glyph nor the pixel size changed, because `refresh` runs on
/// every vault and sync event.
fn render_icon(tray: &TrayIcon, glyph: Glyph) {
    let Some(px) = taskbar::icon_pixel_size() else {
        return;
    };
    if RENDERED.get() == Some((glyph, px)) {
        return;
    }
    let Some(image) = taskbar::rasterise(glyph, px) else {
        tracing::warn!(?glyph, px, "cannot rasterise the tray icon");
        return;
    };
    tray.set_rendered_icon(image);
    tray.set_use_rendered_icon(true);
    RENDERED.set(Some((glyph, px)));
}

/// The taskbar theme changes on a registry watcher thread; the refresh itself runs on the event
/// loop.
pub(crate) fn follow_taskbar(tray: &TrayIcon) {
    let weak = tray.as_weak();
    let watch = taskbar::watch_taskbar_theme(move || {
        if let Err(error) = weak.upgrade_in_event_loop(|tray| apply_choice(&tray, CHOICE.get())) {
            tracing::debug!(%error, "tray gone before a taskbar theme change");
        }
    });
    TASKBAR_WATCH.with_borrow_mut(|slot| *slot = watch);
}

/// Slint creates the status item on its first event-loop turn, so the window to observe does not
/// exist yet right after `show()`; a short retry timer bridges that gap and stops once attached.
#[cfg(not(target_os = "linux"))]
fn follow_menu_bar(tray: &TrayIcon, daemon: &Arc<Daemon>) {
    let weak = tray.as_weak();
    let daemon = Arc::clone(daemon);
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, ATTACH_RETRY, move || {
        let Some(tray) = weak.upgrade() else {
            return;
        };
        let on_change = {
            let weak = tray.as_weak();
            let daemon = Arc::clone(&daemon);
            move || {
                if let Some(tray) = weak.upgrade() {
                    refresh_scheme(&tray, &daemon);
                }
            }
        };
        if let Some(watch) = crate::os::appkit::watch_menu_bar(on_change) {
            MENU_BAR_WATCH.with_borrow_mut(|slot| *slot = Some(watch));
            SCHEME_TIMER.with_borrow(|timer| timer.iter().for_each(slint::Timer::stop));
            refresh_scheme(&tray, &daemon);
        }
    });
    SCHEME_TIMER.with_borrow_mut(|slot| *slot = Some(timer));
}

thread_local! {
    /// The last applied setting, for the taskbar watcher, which has no settings to read.
    static CHOICE: Cell<TrayIconChoice> = const { Cell::new(TrayIconChoice::Auto) };
    static RENDERED: Cell<Option<(Glyph, u32)>> = const { Cell::new(None) };
    static TASKBAR_WATCH: RefCell<Option<taskbar::ThemeWatch>> = const { RefCell::new(None) };
    #[cfg(not(target_os = "linux"))]
    static SCHEME_TIMER: RefCell<Option<slint::Timer>> = const { RefCell::new(None) };
    #[cfg(not(target_os = "linux"))]
    static MENU_BAR_WATCH: RefCell<Option<crate::os::appkit::MenuBarWatch>> =
        const { RefCell::new(None) };
}

/// Runs `refresh` on the event loop whenever the vault, settings, sync or update state changes,
/// until it returns `false` (the tray is gone).
fn follow_changes(
    daemon: &Arc<Daemon>,
    mut refresh: impl FnMut() -> bool + 'static,
) -> anyhow::Result<()> {
    let mut changes = daemon.vault().changes();
    let mut settings = daemon.subscribe_settings();
    let mut sync = daemon.subscribe_tray_sync();
    let mut update = daemon.subscribe_update();
    let mut upgraded = daemon.subscribe_upgraded();
    slint::spawn_local(async move {
        loop {
            tokio::select! {
                biased;
                vault = changes.changed() => if vault.is_err() { break },
                prefs = settings.changed() => if prefs.is_err() { break },
                status = sync.changed() => if status.is_err() { break },
                state = upgraded.changed() => if state.is_err() { break },
                status = async {
                    match update.as_mut() {
                        Some(update) => update.changed().await,
                        None => std::future::pending().await,
                    }
                } => if status.is_err() { break },
            }
            if !refresh() {
                break;
            }
        }
    })?;
    Ok(())
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_millis(500);

    #[test]
    fn two_quick_clicks_make_a_double_click() {
        let clicks = DoubleClick::default();
        let start = Instant::now();
        assert!(!clicks.click(start, WINDOW));
        assert!(clicks.click(start + Duration::from_millis(200), WINDOW));
    }

    #[test]
    fn slow_clicks_stay_single() {
        let clicks = DoubleClick::default();
        let start = Instant::now();
        assert!(!clicks.click(start, WINDOW));
        assert!(!clicks.click(start + Duration::from_millis(600), WINDOW));
        assert!(clicks.click(start + Duration::from_millis(700), WINDOW));
    }

    #[test]
    fn a_third_quick_click_starts_a_new_pair() {
        let clicks = DoubleClick::default();
        let start = Instant::now();
        assert!(!clicks.click(start, WINDOW));
        assert!(clicks.click(start + Duration::from_millis(100), WINDOW));
        assert!(!clicks.click(start + Duration::from_millis(200), WINDOW));
    }
}
