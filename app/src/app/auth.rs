//! Lock screen, login (with 2FA and new-device steps) and account switching.

use std::sync::Arc;

use bwl_vault::{
    TwoFactorProvider, VaultService,
    model::{AccountView, LoginRequest, LoginStep, SessionState, TwoFactorAnswer},
};
use slint::{CloseRequestResponse, ComponentHandle, ModelRc, SharedString, VecModel};
use url::Url;
use zeroize::Zeroizing;

use super::{App, handler, hide, retire, show};
use crate::{
    server_url,
    ui::{LockWindow, LoginWindow},
    viewmodel::{self, LoginError, account_rows, host, initial},
};

pub(super) struct LoginState {
    pub(super) window: LoginWindow,
    /// Kept between the credential step and the 2FA / device steps.
    pending: Option<(Url, String, Zeroizing<String>)>,
    providers: Vec<TwoFactorProvider>,
    /// Account to return to on Cancel (adding a further account).
    previous: Option<Arc<str>>,
}

const fn provider_label(provider: TwoFactorProvider) -> Option<&'static str> {
    match provider {
        TwoFactorProvider::Authenticator => Some("Authenticator"),
        TwoFactorProvider::Email => Some("Email"),
        TwoFactorProvider::RecoveryCode => Some("Recovery code"),
        _ => None,
    }
}

impl<S: VaultService> App<S> {
    fn active_account(&self) -> Option<AccountView> {
        self.vault
            .accounts()
            .into_iter()
            .find(|account| account.active)
    }

    pub(super) fn open_lock_window(&self) {
        if self.lock_window.borrow().is_none() {
            let window = match LockWindow::new() {
                Ok(window) => window,
                Err(error) => {
                    tracing::error!(%error, "cannot create the lock window");
                    return;
                }
            };
            self.apply_theme(&window);
            self.bind_lock(&window);
            *self.lock_window.borrow_mut() = Some(window);
        }
        self.refresh_lock_window();
        let window = self
            .lock_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong);
        if let Some(window) = window {
            show(&window, "lock");
        }
    }

    pub(super) fn refresh_lock_window(&self) {
        let Some(window) = self
            .lock_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong)
        else {
            return;
        };
        let state = self.vault.state();
        let accounts = self.vault.accounts();
        if let SessionState::Locked { server, email } = &state {
            window.set_server(host(server).into());
            window.set_email(email.as_str().into());
            window.set_initial(initial(email).into());
        }
        window.set_touch_id_available(self.touch_id_enrolled());
        if let SessionState::Locked { email, .. } = &state {
            window.set_avatar_color(viewmodel::avatar_color(email));
        }
        window.set_accounts(ModelRc::new(VecModel::from(account_rows(
            &accounts, &state,
        ))));
    }

    fn bind_lock(&self, window: &LockWindow) {
        window.window().on_close_requested(handler!(
            self,
            CloseRequestResponse::HideWindow,
            |app| {
                app.close_lock_window();
                CloseRequestResponse::HideWindow
            }
        ));
        window.on_unlock(handler!(self, |app, password| app
            .unlock(Zeroizing::new(password.to_string()))));
        window.on_unlock_touch_id(handler!(self, |app| app.unlock_touch_id()));
        window.on_logout_confirmed(handler!(self, |app| app.logout()));
        window.on_open_settings(handler!(self, |app| app.open_settings()));
        window.on_switch_account(handler!(self, |app, index| app.switch_account_at(index)));
        window.on_add_account(handler!(self, |app| app.add_account()));
    }

    pub(super) fn close_lock_window(&self) {
        if let Some(window) = self.lock_window.borrow_mut().take() {
            hide(&window);
            retire(window);
            self.window_closed();
        }
    }

    fn set_lock_busy(&self, busy: bool) {
        if let Some(window) = self.lock_window.borrow().as_ref() {
            window.set_busy(busy);
        }
        if let Some(quick) = self.quick.borrow().as_ref() {
            quick.window.set_unlock_busy(busy);
        }
    }

    /// "Ask to unlock on start": the lock screen opens and Touch ID is offered once right away,
    /// unless the master password is required on app start. Success leaves the app in the tray.
    pub(super) fn ask_unlock_on_start(&self) {
        if matches!(self.vault.state(), SessionState::LoggedOut) {
            self.show_login_for_state();
            return;
        }
        self.target.set(super::Target::None);
        self.open_lock_window();
        let password_required = self.settings.borrow().require_master_password_on_start;
        if self.touch_id_enrolled() && !password_required {
            self.unlock_touch_id();
        }
    }

    pub(super) fn touch_id_enrolled(&self) -> bool {
        self.hooks.biometrics.is_available()
            && self
                .active_account()
                .is_some_and(|account| self.hooks.biometrics.is_enrolled(&account.id))
    }

    fn show_unlock_error(&self, text: &str, attempts: i32) {
        if let Some(window) = self.lock_window.borrow().as_ref() {
            window.set_error_text(text.into());
            window.set_failed_attempts(attempts);
            window.set_password(SharedString::new());
        }
        if let Some(quick) = self.quick.borrow().as_ref() {
            quick.window.set_unlock_error(text.into());
            quick.window.set_password(SharedString::new());
        }
    }

    pub(super) fn unlock(&self, password: Zeroizing<String>) {
        if password.is_empty() {
            return;
        }
        self.set_lock_busy(true);
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.unlock_with_password(password).await },
            handler!(self, |app, result| app.unlocked(result)),
        );
    }

    fn unlocked(&self, result: bwl_vault::Result<()>) {
        self.set_lock_busy(false);
        if let Err(error) = result {
            let attempts = self.failed_unlocks.get() + 1;
            self.failed_unlocks.set(attempts);
            let text = match error {
                bwl_vault::Error::InvalidPassword => {
                    format!(
                        "Wrong master password (attempt {attempts}) · check Caps Lock and try again"
                    )
                }
                other => viewmodel::error_text(&other),
            };
            self.show_unlock_error(&text, attempts);
            return;
        }
        self.on_vault_changed();
    }

    pub(super) fn unlock_touch_id(&self) {
        let Some(account) = self.active_account() else {
            return;
        };
        self.set_lock_busy(true);
        let biometrics = Arc::clone(&self.hooks.biometrics);
        self.exec.spawn_blocking(
            move || biometrics.unlock(&account.id, "unlock your vault"),
            handler!(self, |app, result| app.touch_id_unlocked(result)),
        );
    }

    fn touch_id_unlocked(&self, result: crate::hooks::HookResult<Zeroizing<Vec<u8>>>) {
        let result = result.map_err(|error| error.to_string()).and_then(|key| {
            self.vault
                .unlock_with_user_key(key)
                .map_err(|error| viewmodel::error_text(&error))
        });
        self.set_lock_busy(false);
        match result {
            Ok(()) => self.on_vault_changed(),
            Err(text) => {
                let attempts = self.failed_unlocks.get();
                self.show_unlock_error(
                    &format!("Touch ID failed: {text} · use your master password"),
                    attempts,
                );
            }
        }
    }

    pub(super) fn logout(&self) {
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.logout().await },
            handler!(self, |app, result| {
                if let Err(error) = result {
                    app.toast(&viewmodel::error_text(&error), true);
                }
                app.on_vault_changed();
            }),
        );
    }

    pub(super) fn switch_account_at(&self, index: i32) {
        let Some(account) = usize::try_from(index)
            .ok()
            .and_then(|index| self.vault.accounts().into_iter().nth(index))
        else {
            return;
        };
        self.switch_account(&account.id);
    }

    pub fn switch_account(&self, account_id: &str) {
        let already_active = self
            .active_account()
            .is_some_and(|account| account.id.as_ref() == account_id);
        if already_active {
            return;
        }
        if let Err(error) = self.vault.switch_account(account_id) {
            self.toast(&viewmodel::error_text(&error), true);
            return;
        }
        self.on_vault_changed();
    }

    /// "Add account": the login screen opens prefilled with the current server, with Cancel.
    pub(super) fn add_account(&self) {
        let previous = self.active_account();
        self.vault.begin_add_account();
        *self.phase.borrow_mut() = super::Phase::of(&SessionState::LoggedOut);
        self.clear_account_ui();
        self.close_lock_window();
        let server = previous
            .as_ref()
            .map(|account| server_url::display(&account.server));
        self.open_login(server.as_deref(), previous.map(|account| account.id));
        self.update_tray(&SessionState::LoggedOut);
    }

    /// Login for `LoggedOut`: prefilled from a logged-out active account, cancellable when
    /// another logged-in account exists.
    pub(super) fn show_login_for_state(&self) {
        if self.login.borrow().is_some() {
            return;
        }
        self.close_lock_window();
        let accounts = self.vault.accounts();
        let prefill = accounts
            .iter()
            .find(|account| account.active)
            .map(|account| server_url::display(&account.server));
        let previous = accounts
            .iter()
            .find(|account| account.logged_in && !account.active)
            .map(|account| Arc::clone(&account.id));
        self.open_login(prefill.as_deref(), previous);
    }

    fn open_login(&self, server: Option<&str>, previous: Option<Arc<str>>) {
        self.close_login();
        let window = match LoginWindow::new() {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot create the login window");
                return;
            }
        };
        self.apply_theme(&window);
        let mut servers: Vec<String> = self
            .vault
            .accounts()
            .iter()
            .map(|account| server_url::display(&account.server))
            .collect();
        servers.sort();
        servers.dedup();
        let suggestions: Vec<SharedString> = servers.into_iter().map(SharedString::from).collect();
        window.set_server_suggestions(ModelRc::new(VecModel::from(suggestions)));
        if let Some(server) = server {
            window.set_server(server.into());
            validate_server(&window, server);
        }
        window.set_can_cancel(previous.is_some());
        self.bind_login(&window);
        show(&window, "login");
        *self.login.borrow_mut() = Some(LoginState {
            window,
            pending: None,
            providers: Vec::new(),
            previous,
        });
    }

    pub(super) fn close_login(&self) {
        if let Some(login) = self.login.borrow_mut().take() {
            hide(&login.window);
            retire(login);
            self.window_closed();
        }
    }

    fn bind_login(&self, window: &LoginWindow) {
        window.window().on_close_requested(handler!(
            self,
            CloseRequestResponse::HideWindow,
            |app| {
                app.close_login();
                CloseRequestResponse::HideWindow
            }
        ));
        let weak = window.as_weak();
        window.on_server_edited(move |text| {
            if let Some(window) = weak.upgrade() {
                validate_server(&window, &text);
            }
        });
        window.on_submit_credentials(handler!(self, |app| app.submit_credentials()));
        window.on_submit_two_factor(handler!(self, |app| app.submit_second_step(true)));
        window.on_submit_new_device(handler!(self, |app| app.submit_second_step(false)));
        window.on_send_email_code(handler!(self, |app| app.send_email_code()));
        window.on_provider_selected(handler!(self, |app, _index| app.update_provider_hint()));
        window.on_back(handler!(self, |app| {
            if let Some(login) = app.login.borrow_mut().as_mut() {
                login.pending = None;
                login.window.set_step(0);
                login.window.set_error_text(SharedString::new());
            }
        }));
        window.on_cancel(handler!(self, |app| app.cancel_login()));
    }

    fn submit_credentials(&self) {
        let Some(window) = self.login_window() else {
            return;
        };
        let server = match server_url::normalize(&window.get_server()) {
            Ok(server) => server.url,
            Err(error) => {
                window.set_server_error(error.to_string().into());
                return;
            }
        };
        let email = window.get_email().trim().to_owned();
        let password = Zeroizing::new(window.get_password().to_string());
        if email.is_empty() || password.is_empty() {
            window.set_error_text("Enter your email and master password".into());
            return;
        }
        window.set_password(SharedString::new());
        if let Some(login) = self.login.borrow_mut().as_mut() {
            login.pending = Some((server, email, password));
        }
        self.run_login(None, None);
    }

    fn submit_second_step(&self, two_factor: bool) {
        let Some(window) = self.login_window() else {
            return;
        };
        let code = window.get_code().trim().to_owned();
        if code.is_empty() {
            window.set_error_text("Enter the code".into());
            return;
        }
        if two_factor {
            let provider = self.login.borrow().as_ref().and_then(|login| {
                usize::try_from(window.get_provider_index())
                    .ok()
                    .and_then(|index| login.providers.get(index).copied())
            });
            let Some(provider) = provider else {
                return;
            };
            let answer = TwoFactorAnswer {
                provider,
                code,
                remember: window.get_remember(),
            };
            self.run_login(Some(answer), None);
        } else {
            self.run_login(None, Some(code));
        }
    }

    fn run_login(&self, two_factor: Option<TwoFactorAnswer>, new_device_otp: Option<String>) {
        let request = self.login.borrow().as_ref().and_then(|login| {
            login
                .pending
                .as_ref()
                .map(|(server, email, password)| LoginRequest {
                    server: server.clone(),
                    email: email.clone(),
                    password: password.clone(),
                })
        });
        let Some(request) = request else {
            return;
        };
        if let Some(window) = self.login_window() {
            window.set_busy(true);
            window.set_error_text(SharedString::new());
            window.set_server_error(SharedString::new());
        }
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.login(request, two_factor, new_device_otp).await },
            handler!(self, |app, result| app.login_result(result)),
        );
    }

    fn login_result(&self, result: bwl_vault::Result<LoginStep>) {
        let Some(window) = self.login_window() else {
            return;
        };
        window.set_busy(false);
        match result {
            Ok(LoginStep::Done) => {
                if let Some(login) = self.login.borrow_mut().as_mut() {
                    login.pending = None;
                }
                self.target.set(super::Target::Manager);
                self.on_vault_changed();
            }
            Ok(LoginStep::TwoFactorRequired(providers)) => self.show_two_factor(&window, providers),
            Ok(LoginStep::NewDeviceOtpRequired) => {
                window.set_code(SharedString::new());
                window.set_step(2);
            }
            Err(error) => {
                match viewmodel::login_error(&error) {
                    LoginError::Server(text) => window.set_server_error(text.into()),
                    LoginError::General(text) => window.set_error_text(text.into()),
                }
                if !matches!(error, bwl_vault::Error::Api(_)) || window.get_step() == 0 {
                    window.set_step(0);
                    if let Some(login) = self.login.borrow_mut().as_mut() {
                        login.pending = None;
                    }
                }
            }
        }
    }

    fn show_two_factor(&self, window: &LoginWindow, providers: Vec<TwoFactorProvider>) {
        let supported: Vec<TwoFactorProvider> = providers
            .into_iter()
            .filter(|provider| provider_label(*provider).is_some())
            .collect();
        if supported.is_empty() {
            window.set_error_text(
                "This account needs a two-step method bw-lite does not support yet".into(),
            );
            window.set_step(0);
            return;
        }
        let labels: Vec<SharedString> = supported
            .iter()
            .filter_map(|provider| provider_label(*provider))
            .map(SharedString::from)
            .collect();
        window.set_providers(ModelRc::new(VecModel::from(labels)));
        window.set_provider_index(0);
        window.set_code(SharedString::new());
        window.set_step(1);
        if let Some(login) = self.login.borrow_mut().as_mut() {
            login.providers = supported;
        }
        self.update_provider_hint();
    }

    fn update_provider_hint(&self) {
        let guard = self.login.borrow();
        let Some(login) = guard.as_ref() else {
            return;
        };
        let email = usize::try_from(login.window.get_provider_index())
            .ok()
            .and_then(|index| login.providers.get(index))
            .is_some_and(|provider| *provider == TwoFactorProvider::Email);
        login.window.set_email_provider_selected(email);
    }

    fn send_email_code(&self) {
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.send_email_code().await },
            handler!(self, |app, result| {
                if let (Err(error), Some(window)) = (result, app.login_window()) {
                    window.set_error_text(viewmodel::error_text(&error).into());
                }
            }),
        );
    }

    fn cancel_login(&self) {
        let previous = self
            .login
            .borrow()
            .as_ref()
            .and_then(|login| login.previous.clone());
        let Some(previous) = previous else {
            return;
        };
        self.close_login();
        if let Err(error) = self.vault.switch_account(&previous) {
            tracing::warn!(%error, "cannot return to the previous account");
        }
        self.target.set(super::Target::Manager);
        self.on_vault_changed();
    }
}

/// Inline validation while typing; returns the normalized URL when valid.
fn validate_server(window: &LoginWindow, text: &str) -> Option<Url> {
    match server_url::normalize(text) {
        Ok(server) => {
            window.set_server_error(SharedString::new());
            window.set_server_warning(server.warning.unwrap_or_default().into());
            Some(server.url)
        }
        Err(server_url::ServerUrlError::Empty) => {
            window.set_server_error(SharedString::new());
            window.set_server_warning(SharedString::new());
            None
        }
        Err(error) => {
            window.set_server_error(error.to_string().into());
            None
        }
    }
}
