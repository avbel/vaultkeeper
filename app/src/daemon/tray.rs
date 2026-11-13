//! The daemon's only UI: the `TrayIcon` component (no window, nothing rendered). Its menu items
//! are routed like every other trigger, and it follows the vault and settings through watches on
//! the Slint event loop.

use std::{cell::RefCell, sync::Arc, time::Duration};

use slint::{ModelRc, SharedString, VecModel, language::ColorScheme};
use vk_vault::{VaultService, model::SessionState};

use super::{
    Daemon,
    routing::{self, Effect, TrayAction},
};
use crate::{
    settings::ThemeChoice,
    ui::TrayIcon,
    viewmodel::{host, local_time, tray_sync_label},
};

const ATTACH_RETRY: Duration = Duration::from_millis(250);

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
    refresh(&tray, daemon);
    tray.show()?;
    follow_menu_bar(&tray, daemon);
    watch(&tray, daemon)?;
    Ok(tray)
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

fn refresh(tray: &TrayIcon, daemon: &Daemon) {
    let vault = daemon.vault();
    let state = vault.state();
    tray.set_locked(!matches!(state, SessionState::Unlocked { .. }));
    tray.set_logged_in(!matches!(state, SessionState::LoggedOut));
    let labels: Vec<SharedString> = vault
        .accounts()
        .iter()
        .map(|account| {
            let mark = if account.active { "✓ " } else { "" };
            format!("{mark}{} @ {}", account.email, host(&account.server)).into()
        })
        .collect();
    tray.set_accounts(ModelRc::new(VecModel::from(labels)));
    let sync = daemon.tray_sync();
    let last_sync = vault.last_sync();
    tray.set_syncing(sync.running);
    tray.set_sync_label(
        tray_sync_label(
            last_sync.map(local_time),
            chrono::Local::now().naive_local(),
            sync.failure(vault.active_account_id().as_deref(), last_sync),
        )
        .into(),
    );
    let update = daemon
        .subscribe_update()
        .map(|status| status.borrow().clone());
    tray.set_update_label(
        update
            .as_ref()
            .map(super::update::Status::tray_label)
            .unwrap_or_default()
            .into(),
    );
    tray.set_update_enabled(update.is_none_or(|status| status.tray_enabled()));
    refresh_scheme(tray, daemon);
}

/// The bar's appearance follows the wallpaper; `follow_menu_bar` calls this when it changes.
/// Before the status item has a window the system appearance is the best guess. The Settings
/// choice overrides both; the icon is the opposite shade of the bar it must read on,
/// so "White" is the scheme of a dark bar.
fn refresh_scheme(tray: &TrayIcon, daemon: &Daemon) {
    let dark = match daemon.settings().tray_icon {
        ThemeChoice::Light => Some(true),
        ThemeChoice::Dark => Some(false),
        ThemeChoice::System => {
            crate::os::appkit::menu_bar_dark().or_else(crate::os::appkit::system_dark)
        }
    };
    tray.set_menu_bar_scheme(match dark {
        Some(true) => ColorScheme::Dark,
        Some(false) => ColorScheme::Light,
        None => ColorScheme::Unknown,
    });
}

/// Slint creates the status item on its first event-loop turn, so the window to observe does not
/// exist yet right after `show()`; a short retry timer bridges that gap and stops once attached.
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
    static SCHEME_TIMER: RefCell<Option<slint::Timer>> = const { RefCell::new(None) };
    static MENU_BAR_WATCH: RefCell<Option<crate::os::appkit::MenuBarWatch>> =
        const { RefCell::new(None) };
}

fn watch(tray: &TrayIcon, daemon: &Arc<Daemon>) -> anyhow::Result<()> {
    let mut changes = daemon.vault().changes();
    let mut settings = daemon.subscribe_settings();
    let mut sync = daemon.subscribe_tray_sync();
    let mut update = daemon.subscribe_update();
    let weak = tray.as_weak();
    let daemon = Arc::clone(daemon);
    slint::spawn_local(async move {
        loop {
            tokio::select! {
                biased;
                vault = changes.changed() => if vault.is_err() { break },
                prefs = settings.changed() => if prefs.is_err() { break },
                status = sync.changed() => if status.is_err() { break },
                status = async {
                    match update.as_mut() {
                        Some(update) => update.changed().await,
                        None => std::future::pending().await,
                    }
                } => if status.is_err() { break },
            }
            match weak.upgrade() {
                Some(tray) => refresh(&tray, &daemon),
                None => break,
            }
        }
    })?;
    Ok(())
}
