//! Settings window: each control writes the setting, persists it and applies its side effect.

use std::sync::Arc;

use slint::{CloseRequestResponse, ComponentHandle, ModelRc, SharedString, VecModel};
use vk_vault::VaultService;

use super::{App, handler, hide, retire, show};
use crate::{
    settings::{
        CLIPBOARD_OPTIONS, LOCK_OPTIONS, Settings, SshApproval, TextScale, ThemeChoice, option_at,
        option_index,
    },
    ui::SettingsWindow,
    viewmodel::host,
};

fn cli_path_setup() -> String {
    std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::to_str)
        .map_or_else(String::new, |directory| {
            format!(
                "export PATH='{}':\"$PATH\"",
                directory.replace('\'', "'\\''")
            )
        })
}

impl<S: VaultService> App<S> {
    pub fn open_settings(&self) {
        let existing = self
            .settings_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong);
        if let Some(window) = existing {
            show(&window, "settings");
            return;
        }
        let window = match SettingsWindow::new() {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot create the settings window");
                return;
            }
        };
        self.apply_theme(&window);
        self.fill_settings(&window);
        self.bind_settings(&window);
        show(&window, "settings");
        *self.settings_window.borrow_mut() = Some(window);
    }

    pub(super) fn close_settings(&self) {
        let window = self.settings_window.borrow_mut().take();
        if let Some(window) = window {
            self.end_recording(&window);
            hide(&window);
            retire(window);
            self.window_closed();
        }
    }

    fn fill_settings(&self, window: &SettingsWindow) {
        let settings = self.settings.borrow().clone();
        let account = self
            .vault
            .accounts()
            .into_iter()
            .find(|account| account.active);
        window.set_server(
            account
                .as_ref()
                .map_or_else(String::new, |account| host(&account.server))
                .into(),
        );
        window.set_theme_index(settings.theme.index());
        window.set_tray_icon_index(settings.tray_icon.index());
        window.set_scale_index(settings.text_scale.index());
        let lock_labels: Vec<SharedString> = LOCK_OPTIONS
            .iter()
            .map(|option| option.label().into())
            .collect();
        window.set_lock_options(ModelRc::new(VecModel::from(lock_labels)));
        window.set_lock_index(option_index(&LOCK_OPTIONS, &settings.lock_timeout));
        window.set_lock_on_sleep(settings.lock_on_sleep);
        let clip_labels: Vec<SharedString> = CLIPBOARD_OPTIONS
            .iter()
            .map(|option| option.label().into())
            .collect();
        window.set_clipboard_options(ModelRc::new(VecModel::from(clip_labels)));
        window.set_clipboard_index(option_index(&CLIPBOARD_OPTIONS, &settings.clipboard_clear));
        window.set_start_at_login(settings.start_at_login);
        window.set_auto_update(settings.auto_update);
        window.set_ask_unlock_on_start(settings.ask_unlock_on_start);
        window.set_require_master_password(settings.require_master_password_on_start);
        let biometrics = &self.hooks.biometrics;
        window.set_touch_id_available(biometrics.is_available());
        window.set_touch_id_enrolled(
            account
                .as_ref()
                .is_some_and(|account| biometrics.is_enrolled(&account.id)),
        );
        window.set_unlocked(matches!(
            self.vault.state(),
            vk_vault::model::SessionState::Unlocked { .. }
        ));
        window.set_ssh_agent(settings.ssh_agent);
        window.set_cli_access(settings.cli_access);
        window.set_cli_path_setup(cli_path_setup().into());
        let socket = self.hooks.ssh_agent.socket_path();
        window.set_ssh_config(ssh_config_lines(&socket).into());
        window.set_ssh_socket(socket.into());
        window.set_ssh_approval_index(i32::from(
            settings.ssh_approval == SshApproval::RememberUntilLock,
        ));
        window.set_ssh_touch_id(settings.ssh_touch_id);
        window.set_touch_id_right_away(settings.touch_id_right_away);
        window.set_show_site_icons(settings.show_site_icons);
        super::settings_hotkeys::show_hotkeys(window, &settings);
        self.fill_browser_settings(window, &settings);
    }

    fn bind_ssh_settings(&self, window: &SettingsWindow) {
        window.on_ssh_agent_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.ssh_agent = enabled);
            app.report(app.hooks.ssh_agent.set_enabled(enabled));
            app.refresh_status();
        }));
        window.on_copy_ssh_config(handler!(self, false, |app| {
            let lines =
                zeroize::Zeroizing::new(ssh_config_lines(&app.hooks.ssh_agent.socket_path()));
            app.copy_text("SSH config lines", &lines)
        }));
        window.on_copy_socket(handler!(self, false, |app| {
            let path = zeroize::Zeroizing::new(app.hooks.ssh_agent.socket_path());
            app.copy_text("socket path", &path)
        }));
        window.on_ssh_approval_selected(handler!(self, |app, index| {
            let approval = if index == 1 {
                SshApproval::RememberUntilLock
            } else {
                SshApproval::Always
            };
            app.update_settings(|settings| settings.ssh_approval = approval);
        }));
        window.on_ssh_touch_id_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.ssh_touch_id = enabled);
        }));
    }

    fn bind_settings(&self, window: &SettingsWindow) {
        window.window().on_close_requested(handler!(
            self,
            CloseRequestResponse::HideWindow,
            |app| {
                app.close_settings();
                CloseRequestResponse::HideWindow
            }
        ));
        window.on_theme_selected(handler!(self, |app, index| {
            if let Some(theme) = ThemeChoice::from_index(index) {
                app.set_theme(theme);
            }
        }));
        window.on_tray_icon_selected(handler!(self, |app, index| {
            if let Some(choice) = ThemeChoice::from_index(index) {
                app.update_settings(|settings| settings.tray_icon = choice);
            }
        }));
        window.on_scale_selected(handler!(self, |app, index| {
            if let Some(scale) = TextScale::from_index(index) {
                app.update_settings(|settings| settings.text_scale = scale);
                app.apply_theme_everywhere();
                // Icons are decoded at the row size, which follows the text size.
                app.forget_site_icons();
                app.schedule_site_icons();
            }
        }));
        window.on_lock_selected(handler!(self, |app, index| {
            if let Some(timeout) = option_at(&LOCK_OPTIONS, index) {
                app.update_settings(|settings| settings.lock_timeout = timeout);
            }
        }));
        window.on_lock_on_sleep_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.lock_on_sleep = enabled);
        }));
        window.on_clipboard_selected(handler!(self, |app, index| {
            if let Some(clear) = option_at(&CLIPBOARD_OPTIONS, index) {
                app.update_settings(|settings| settings.clipboard_clear = clear);
            }
        }));
        window.on_start_at_login_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.start_at_login = enabled);
            app.report(app.hooks.autostart.set_enabled(enabled));
        }));
        window.on_auto_update_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.auto_update = enabled);
        }));
        window.on_ask_unlock_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.ask_unlock_on_start = enabled);
        }));
        window.on_require_master_password_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.require_master_password_on_start = enabled);
        }));
        window.on_touch_id_enroll(handler!(self, |app| app.enroll_touch_id()));
        window.on_touch_id_remove(handler!(self, |app| app.remove_touch_id()));
        self.bind_ssh_settings(window);
        window.on_cli_access_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.cli_access = enabled);
        }));
        window.on_copy_cli_path_setup(handler!(self, false, |app| {
            let command = zeroize::Zeroizing::new(cli_path_setup());
            app.copy_text("CLI setup command", &command)
        }));
        window.on_touch_id_right_away_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.touch_id_right_away = enabled);
        }));
        window.on_site_icons_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.show_site_icons = enabled);
            app.apply_theme_everywhere();
            app.site_icons_changed();
        }));
        self.bind_hotkeys(window);
        self.bind_browser_settings(window);
    }

    /// Re-reads the store after the daemon changed it and applies what is visible.
    pub(super) fn reload_settings(&self) {
        let fresh = self.hooks.settings.load();
        *self.settings.borrow_mut() = fresh;
        self.apply_theme_everywhere();
        self.site_icons_changed();
        let window = self
            .settings_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong);
        if let Some(window) = window {
            self.fill_settings(&window);
        }
    }

    pub(super) fn update_settings(&self, change: impl FnOnce(&mut Settings)) {
        let updated = {
            let mut settings = self.settings.borrow_mut();
            change(&mut settings);
            settings.clone()
        };
        self.report(self.hooks.settings.save(&updated));
    }

    pub(super) fn report(&self, result: crate::hooks::HookResult<()>) {
        let text: SharedString = result
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default()
            .into();
        if let Some(window) = self.settings_window.borrow().as_ref() {
            window.set_error_text(text);
        }
    }

    fn enroll_touch_id(&self) {
        let account = self
            .vault
            .accounts()
            .into_iter()
            .find(|account| account.active);
        let unlocked = matches!(
            self.vault.state(),
            vk_vault::model::SessionState::Unlocked { .. }
        );
        let (Some(account), true) = (account, unlocked) else {
            self.report(Err(crate::hooks::HookError::Failed(
                "Unlock the vault to enrol Touch ID".to_owned(),
            )));
            return;
        };
        let biometrics = Arc::clone(&self.hooks.biometrics);
        self.exec.spawn_blocking(
            move || biometrics.enroll(&account.id),
            handler!(self, |app, result| app.touch_id_changed(result)),
        );
    }

    fn remove_touch_id(&self) {
        let Some(account) = self
            .vault
            .accounts()
            .into_iter()
            .find(|account| account.active)
        else {
            return;
        };
        let result = self.hooks.biometrics.unenroll(&account.id);
        self.touch_id_changed(result);
    }

    fn touch_id_changed(&self, result: crate::hooks::HookResult<()>) {
        let window = self
            .settings_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong);
        if let Some(window) = window {
            self.fill_settings(&window);
        }
        if let Err(error) = &result {
            tracing::warn!(%error, "Touch ID change failed");
        }
        self.report(result);
        self.refresh_lock_window();
    }
}

/// `~/.ssh/config` lines that send every host's key requests to the agent. The path is quoted
/// because "Application Support" has a space; ssh expands a leading `~` inside the quotes.
fn ssh_config_lines(socket: &str) -> String {
    format!("Host *\n    IdentityAgent \"{socket}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_config_lines_quote_the_socket_path() {
        assert_eq!(
            ssh_config_lines("/Users/me/Library/Application Support/vaultkeeper/ssh-agent.sock"),
            "Host *\n    IdentityAgent \"/Users/me/Library/Application Support/vaultkeeper/ssh-agent.sock\""
        );
    }
}
