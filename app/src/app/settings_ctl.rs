//! Settings window: each control writes the setting, persists it and applies its side effect.

use std::sync::Arc;

use slint::{CloseRequestResponse, ComponentHandle, ModelRc, SharedString, VecModel};
use vk_vault::VaultService;

use super::{App, handler, hide, retire, show};
use crate::{
    settings::{
        CLIPBOARD_OPTIONS, LOCK_OPTIONS, Settings, SshApproval, TextScale, ThemeChoice,
        TrayIconChoice, option_at, option_index,
    },
    ui::SettingsWindow,
    viewmodel::host,
};

/// The tray icon is a menu bar icon on macOS and a taskbar icon on Windows.
#[must_use]
pub fn tray_icon_label() -> &'static str {
    if cfg!(windows) {
        "Tray icon"
    } else {
        "Menu bar icon"
    }
}

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
            self.fill_biometric(&window);
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
        window.set_tray_icon_label(tray_icon_label().into());
        window.set_capture_exclusion_available(cfg!(windows));
        window.set_hide_from_capture(settings.hide_from_capture);
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
        window.set_updates_managed_note(updates_managed_note().into());
        window.set_ask_unlock_on_start(settings.ask_unlock_on_start);
        window.set_require_master_password(settings.require_master_password_on_start);
        self.fill_biometric(window);
        window.set_unlocked(matches!(
            self.vault.state(),
            vk_vault::model::SessionState::Unlocked { .. }
        ));
        window.set_ssh_agent(settings.ssh_agent);
        window.set_ssh_notice(self.ssh_notice.borrow().as_str().into());
        window.set_cli_access(settings.cli_access);
        window.set_cli_path_setup(cli_path_setup().into());
        let socket = self.hooks.ssh_agent.socket_path();
        window.set_ssh_hint(ssh_hint().into());
        window.set_ssh_config(ssh_config_lines(&socket).into());
        window.set_ssh_socket(socket.into());
        window.set_ssh_approval_index(i32::from(
            settings.ssh_approval == SshApproval::RememberUntilLock,
        ));
        window.set_ssh_biometric(settings.ssh_touch_id);
        window.set_biometric_right_away(settings.touch_id_right_away);
        window.set_show_site_icons(settings.show_site_icons);
        super::settings_hotkeys::show_hotkeys(window, &settings, self.hotkey_issues.get());
        self.fill_browser_settings(window, &settings);
    }

    /// Availability can change between openings (Hello is off over RDP and on a locked session),
    /// so it is read again each time the window is shown.
    fn fill_biometric(&self, window: &SettingsWindow) {
        let biometrics = &self.hooks.biometrics;
        let account = self
            .vault
            .accounts()
            .into_iter()
            .find(|account| account.active);
        window.set_hide_missing_biometric(cfg!(windows));
        window.set_biometric_available(biometrics.is_available());
        window.set_biometric_enrolled(
            account
                .as_ref()
                .is_some_and(|account| biometrics.is_enrolled(&account.id)),
        );
    }

    fn bind_ssh_settings(&self, window: &SettingsWindow) {
        window.on_ssh_agent_toggled(handler!(self, |app, enabled| {
            app.ssh_notice.take();
            if let Some(window) = app.settings_window() {
                window.set_ssh_notice(SharedString::new());
            }
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
        window.on_ssh_biometric_toggled(handler!(self, |app, enabled| {
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
            if let Some(choice) = TrayIconChoice::from_index(index) {
                app.update_settings(|settings| settings.tray_icon = choice);
                app.refresh_tray_icon();
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
        window.on_hide_from_capture_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.hide_from_capture = enabled);
            crate::os::ui_window::set_capture_exclusion(enabled);
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
        window.on_biometric_enroll(handler!(self, |app| app.enroll_touch_id()));
        window.on_biometric_remove(handler!(self, |app| app.remove_touch_id()));
        self.bind_ssh_settings(window);
        window.on_cli_access_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.cli_access = enabled);
        }));
        window.on_copy_cli_path_setup(handler!(self, false, |app| {
            let command = zeroize::Zeroizing::new(cli_path_setup());
            app.copy_text("CLI setup command", &command)
        }));
        window.on_biometric_right_away_toggled(handler!(self, |app, enabled| {
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
            self.report(Err(crate::hooks::HookError::Failed(format!(
                "Unlock the vault to enrol {}",
                crate::os::BIOMETRIC_LABEL
            ))));
            return;
        };
        let biometrics = Arc::clone(&self.hooks.biometrics);
        let parent = self
            .settings_window
            .borrow()
            .as_ref()
            .and_then(|window| crate::os::ui_window::window_handle(window.window()));
        self.exec.spawn_blocking(
            move || biometrics.enroll(&account.id, parent),
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

/// Shown instead of the config lines on Windows, where `ssh.exe` finds the agent by its pipe name.
const WINDOWS_SSH_HINT: &str = "Windows OpenSSH (ssh.exe) uses this pipe by itself; stop and disable the \"OpenSSH Authentication Agent\" service first. Git for Windows needs core.sshCommand = C:/Windows/System32/OpenSSH/ssh.exe, and WSL needs a relay such as npiperelay.";

fn ssh_hint() -> &'static str {
    if cfg!(windows) { WINDOWS_SSH_HINT } else { "" }
}

/// `~/.ssh/config` lines that send every host's key requests to the agent. The path is quoted
/// because "Application Support" has a space; ssh expands a leading `~` inside the quotes.
fn ssh_config_lines(socket: &str) -> String {
    format!("Host *\n    IdentityAgent \"{socket}\"")
}

/// "Managed by Homebrew — run brew upgrade vaultkeeper" for a package-manager install, else empty.
fn updates_managed_note() -> String {
    let kind = vk_platform::install_kind::detect();
    match (kind.manager(), kind.upgrade_command()) {
        (Some(manager), Some(command)) => format!("Managed by {manager} — run {command}"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_hint_names_the_pipe_workarounds() {
        assert!(WINDOWS_SSH_HINT.contains("C:/Windows/System32/OpenSSH/ssh.exe"));
        assert!(WINDOWS_SSH_HINT.contains("npiperelay"));
    }

    #[test]
    fn ssh_config_lines_quote_the_socket_path() {
        assert_eq!(
            ssh_config_lines("/Users/me/Library/Application Support/vaultkeeper/ssh-agent.sock"),
            "Host *\n    IdentityAgent \"/Users/me/Library/Application Support/vaultkeeper/ssh-agent.sock\""
        );
    }
}
