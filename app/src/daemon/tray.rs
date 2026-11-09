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
use crate::{ui::TrayIcon, viewmodel::host};

pub fn install(daemon: &Arc<Daemon>) -> anyhow::Result<TrayIcon> {
    let tray = TrayIcon::new()?;
    let on = |action: TrayAction| {
        let daemon = Arc::clone(daemon);
        move || run(&daemon, action)
    };
    tray.on_quick_search(on(TrayAction::QuickSearch));
    tray.on_open_vault(on(TrayAction::OpenVault));
    tray.on_generator(on(TrayAction::Generator));
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
    let settings = daemon.settings();
    tray.set_quick_hotkey(hotkey_hint(&settings, &settings.hotkey).into());
    tray.set_generator_hotkey(hotkey_hint(&settings, &settings.generator_hotkey).into());
    // Re-read on every refresh: a system appearance switch shows on the next vault or settings
    // change (a sync runs at least every 30 minutes).
    tray.set_menu_bar_scheme(match crate::os::appkit::system_dark() {
        Some(true) => ColorScheme::Dark,
        Some(false) => ColorScheme::Light,
        None => ColorScheme::Unknown,
    });
}

/// The hotkey suffix of a tray item; empty (no suffix) with "Show keyboard shortcuts" off.
fn hotkey_hint(settings: &crate::settings::Settings, accelerator: &str) -> String {
    if settings.show_shortcuts {
        crate::settings::hotkey_symbols(accelerator)
    } else {
        String::new()
    }
}

fn watch(tray: &TrayIcon, daemon: &Arc<Daemon>) -> anyhow::Result<()> {
    let mut changes = daemon.vault().changes();
    let mut settings = daemon.subscribe_settings();
    let weak = tray.as_weak();
    let daemon = Arc::clone(daemon);
    slint::spawn_local(async move {
        loop {
            tokio::select! {
                biased;
                vault = changes.changed() => if vault.is_err() { break },
                prefs = settings.changed() => if prefs.is_err() { break },
            }
            match weak.upgrade() {
                Some(tray) => refresh(&tray, &daemon),
                None => break,
            }
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Settings;

    #[test]
    fn tray_items_show_their_hotkeys_only_while_shortcuts_are_shown() {
        let shown = Settings {
            hotkey: "Cmd+Shift+Space".to_owned(),
            generator_hotkey: "Cmd+Alt+G".to_owned(),
            ..Settings::default()
        };
        assert_eq!(hotkey_hint(&shown, &shown.hotkey), "⇧⌘Space");
        assert_eq!(hotkey_hint(&shown, &shown.generator_hotkey), "⌥⌘G");
        assert_eq!(hotkey_hint(&shown, ""), "", "no Generator hotkey set");
        let hidden = Settings {
            show_shortcuts: false,
            ..shown
        };
        assert_eq!(hotkey_hint(&hidden, &hidden.hotkey), "");
        assert_eq!(hotkey_hint(&hidden, &hidden.generator_hotkey), "");
    }
}
