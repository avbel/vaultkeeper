//! Settings window: each control writes the setting, persists it and applies its side effect.

use std::sync::Arc;

use bwl_vault::VaultService;
use slint::{CloseRequestResponse, ComponentHandle, ModelRc, SharedString, VecModel};

use super::{App, handler, hide, retire, show};
use crate::{
    settings::{
        CLIPBOARD_OPTIONS, LOCK_OPTIONS, Settings, SshApproval, TextScale, ThemeChoice, option_at,
        option_index,
    },
    ui::SettingsWindow,
    viewmodel::host,
};

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
        if let Some(window) = self.settings_window.borrow_mut().take() {
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
        window.set_scale_index(settings.text_scale.index());
        let lock_labels: Vec<SharedString> = LOCK_OPTIONS
            .iter()
            .map(|option| option.label().into())
            .collect();
        window.set_lock_options(ModelRc::new(VecModel::from(lock_labels)));
        window.set_lock_index(option_index(&LOCK_OPTIONS, &settings.lock_timeout));
        let clip_labels: Vec<SharedString> = CLIPBOARD_OPTIONS
            .iter()
            .map(|option| option.label().into())
            .collect();
        window.set_clipboard_options(ModelRc::new(VecModel::from(clip_labels)));
        window.set_clipboard_index(option_index(&CLIPBOARD_OPTIONS, &settings.clipboard_clear));
        window.set_start_at_login(settings.start_at_login);
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
            bwl_vault::model::SessionState::Unlocked { .. }
        ));
        window.set_ssh_agent(settings.ssh_agent);
        window.set_ssh_socket(self.hooks.ssh_agent.socket_path().into());
        window.set_ssh_approval_index(i32::from(
            settings.ssh_approval == SshApproval::RememberUntilLock,
        ));
        window.set_ssh_touch_id(settings.ssh_touch_id);
        window.set_hotkey(settings.hotkey.as_str().into());
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
        window.on_scale_selected(handler!(self, |app, index| {
            if let Some(scale) = TextScale::from_index(index) {
                app.update_settings(|settings| settings.text_scale = scale);
                app.apply_theme_everywhere();
            }
        }));
        window.on_lock_selected(handler!(self, |app, index| {
            if let Some(timeout) = option_at(&LOCK_OPTIONS, index) {
                app.update_settings(|settings| settings.lock_timeout = timeout);
            }
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
        window.on_ask_unlock_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.ask_unlock_on_start = enabled);
        }));
        window.on_require_master_password_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.require_master_password_on_start = enabled);
        }));
        window.on_touch_id_enroll(handler!(self, |app| app.enroll_touch_id()));
        window.on_touch_id_remove(handler!(self, |app| app.remove_touch_id()));
        window.on_ssh_agent_toggled(handler!(self, |app, enabled| {
            app.update_settings(|settings| settings.ssh_agent = enabled);
            app.report(app.hooks.ssh_agent.set_enabled(enabled));
            app.refresh_status();
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
        window.on_hotkey_accepted(handler!(self, |app, accelerator| {
            let accelerator = accelerator.trim().to_owned();
            // Checked before saving: the daemon registers whatever the file says.
            match app.hooks.hotkey.register(&accelerator) {
                Ok(()) => app.update_settings(|settings| settings.hotkey.clone_from(&accelerator)),
                Err(error) => app.report(Err(error)),
            }
        }));
    }

    /// Re-reads the store after the daemon changed it and applies what is visible.
    pub(super) fn reload_settings(&self) {
        let fresh = self.hooks.settings.load();
        *self.settings.borrow_mut() = fresh;
        self.apply_theme_everywhere();
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

    fn report(&self, result: crate::hooks::HookResult<()>) {
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
            bwl_vault::model::SessionState::Unlocked { .. }
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
