//! Tray icon (Slint `SystemTrayIcon`) and its menu.

use bwl_vault::{VaultService, model::SessionState};
use slint::{ModelRc, SharedString, VecModel};

use super::{App, handler};
use crate::{ui::TrayIcon, viewmodel::host};

impl<S: VaultService> App<S> {
    /// Creates the tray icon; it lives as long as the app. Not used in headless tests.
    pub fn install_tray(&self) {
        let tray = match TrayIcon::new() {
            Ok(tray) => tray,
            Err(error) => {
                tracing::error!(%error, "cannot create the tray icon");
                return;
            }
        };
        tray.on_quick_search(handler!(self, |app| app.toggle_quick_panel()));
        tray.on_open_vault(handler!(self, |app| app.open_vault()));
        tray.on_generator(handler!(self, |app| app.open_generator_window()));
        tray.on_lock_toggle(handler!(self, |app| app.tray_lock_toggle()));
        tray.on_sync_now(handler!(self, |app| app.sync_now()));
        tray.on_switch_account(handler!(self, |app, index| app.switch_account_at(index)));
        tray.on_theme_selected(handler!(self, |app, index| {
            if let Some(theme) = crate::settings::ThemeChoice::from_index(index) {
                app.set_theme(theme);
            }
        }));
        tray.set_theme_index(self.settings.borrow().theme.index());
        tray.on_quit(handler!(self, |app| app.quit()));
        if let Err(error) = tray.show() {
            tracing::error!(%error, "cannot show the tray icon");
        }
        *self.tray.borrow_mut() = Some(tray);
        self.update_tray(&self.vault.state());
    }

    pub fn tray_lock_toggle(&self) {
        match self.vault.state() {
            SessionState::Unlocked { .. } => self.lock(),
            SessionState::Locked { .. } | SessionState::LoggedOut => self.open_vault(),
        }
    }

    pub(super) fn update_tray(&self, state: &SessionState) {
        if let Some(tray) = self.tray.borrow().as_ref() {
            tray.set_locked(!matches!(state, SessionState::Unlocked { .. }));
            tray.set_logged_in(!matches!(state, SessionState::LoggedOut));
        }
        self.refresh_accounts_menu();
    }

    /// Account lists of the tray submenu, the Manager switcher and the lock screen.
    pub(super) fn refresh_accounts_menu(&self) {
        let accounts = self.vault.accounts();
        if let Some(tray) = self.tray.borrow().as_ref() {
            let labels: Vec<SharedString> = accounts
                .iter()
                .map(|account| {
                    let mark = if account.active { "✓ " } else { "" };
                    format!("{mark}{} @ {}", account.email, host(&account.server)).into()
                })
                .collect();
            tray.set_accounts(ModelRc::new(VecModel::from(labels)));
        }
        if let Some(manager) = self.manager.borrow().as_ref() {
            let state = self.vault.state();
            manager.window.set_accounts(ModelRc::new(VecModel::from(
                crate::viewmodel::account_rows(&accounts, &state),
            )));
            if let Some(active) = accounts.iter().find(|account| account.active) {
                manager
                    .window
                    .set_account_email(active.email.as_ref().into());
                manager.window.set_account_host(host(&active.server).into());
                manager
                    .window
                    .set_account_initial(crate::viewmodel::initial(&active.email).into());
                manager
                    .window
                    .set_account_color(crate::viewmodel::avatar_color(&active.email));
            }
        }
    }
}
