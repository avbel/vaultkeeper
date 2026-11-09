//! The daemon's only UI: the `TrayIcon` component (no window, nothing rendered). Its menu items
//! are routed like every other trigger, and it follows the vault and settings through watches on
//! the Slint event loop.

use std::sync::Arc;

use bwl_vault::{VaultService, model::SessionState};
use slint::{ModelRc, SharedString, VecModel, language::ColorScheme};

use super::{
    Daemon,
    routing::{self, Effect, TrayAction},
};
use crate::{
    ui::TrayIcon,
    viewmodel::{host, local_time, tray_sync_label},
};

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
    tray.on_quit(on(TrayAction::Quit));
    let switch = Arc::clone(daemon);
    tray.on_switch_account(move |index| run(&switch, TrayAction::SwitchAccount(index)));
    refresh(&tray, daemon);
    tray.show()?;
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
            sync.failure(last_sync),
        )
        .into(),
    );
    // Re-read on every refresh: a system appearance switch shows on the next vault or settings
    // change (a sync runs at least every 30 minutes).
    tray.set_menu_bar_scheme(match crate::os::appkit::system_dark() {
        Some(true) => ColorScheme::Dark,
        Some(false) => ColorScheme::Light,
        None => ColorScheme::Unknown,
    });
}

fn watch(tray: &TrayIcon, daemon: &Arc<Daemon>) -> anyhow::Result<()> {
    let mut changes = daemon.vault().changes();
    let mut settings = daemon.subscribe_settings();
    let mut sync = daemon.subscribe_tray_sync();
    let weak = tray.as_weak();
    let daemon = Arc::clone(daemon);
    slint::spawn_local(async move {
        loop {
            tokio::select! {
                biased;
                vault = changes.changed() => if vault.is_err() { break },
                prefs = settings.changed() => if prefs.is_err() { break },
                status = sync.changed() => if status.is_err() { break },
            }
            match weak.upgrade() {
                Some(tray) => refresh(&tray, &daemon),
                None => break,
            }
        }
    })?;
    Ok(())
}
