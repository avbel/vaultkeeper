//! The security-key provider of the login window's two-step page (WebAuthn, provider 7).
//!
//! A challenge answers one login attempt only: Vaultwarden replaces it whenever it issues a new
//! one and deletes it once checked. So the key starts at once on a fresh challenge, and every
//! retry first logs in again without an answer to get a new one.

use slint::SharedString;
use vk_vault::{TwoFactorProvider, VaultService, model::TwoFactorAnswer};
use vk_webauthn::RequestOptions;
use zeroize::Zeroizing;

use super::{App, handler};
use crate::hooks::{HookError, KeyCeremony, KeyEvent};

pub(super) const KEY_LABEL: &str = "Security key";

/// The security-key part of the login state.
#[derive(Default)]
pub(super) struct KeyLogin {
    /// The current round's challenge (Vaultwarden's options as JSON text).
    pub(super) challenge: Option<String>,
    running: Option<Box<dyn KeyCeremony>>,
    /// Numbers the requests so the events of a cancelled one are dropped.
    round: u64,
    /// The next challenge comes from a retry and starts the key at once.
    start_on_next_challenge: bool,
}

impl KeyLogin {
    /// Whether `challenge` is usable; a provider without one is not offered.
    pub(super) fn accepts(challenge: Option<&str>) -> bool {
        challenge.is_some_and(|challenge| parse(challenge).is_some())
    }

    pub(super) fn cancel(&mut self) {
        self.round += 1;
        if let Some(running) = self.running.take() {
            running.cancel();
        }
    }
}

fn parse(challenge: &str) -> Option<RequestOptions> {
    serde_json::from_str(challenge)
        .ok()
        .and_then(|value| RequestOptions::from_json(&value).ok())
}

impl<S: VaultService> App<S> {
    pub(super) fn key_selected(&self) -> bool {
        self.login.borrow().as_ref().is_some_and(|login| {
            usize::try_from(login.window.get_provider_index())
                .ok()
                .and_then(|index| login.providers.get(index))
                .is_some_and(|provider| *provider == TwoFactorProvider::WebAuthn)
        })
    }

    /// A 2FA round arrived with `challenge`. `first` is the round right after the password.
    pub(super) fn key_challenge_received(&self, challenge: Option<String>, first: bool) {
        let start = {
            let mut guard = self.login.borrow_mut();
            let Some(login) = guard.as_mut() else {
                return;
            };
            login.key.cancel();
            login.key.challenge = challenge;
            let start = first || login.key.start_on_next_challenge;
            login.key.start_on_next_challenge = false;
            start
        };
        self.reset_key_prompt();
        if start && self.key_selected() {
            self.start_key();
        }
    }

    /// The selected provider changed: a key request only runs while the key is selected.
    pub(super) fn key_provider_changed(&self) {
        let selected = self.key_selected();
        if let Some(window) = self.login_window() {
            window.set_key_selected(selected);
        }
        if !selected {
            self.cancel_key();
        }
    }

    pub(super) fn cancel_key(&self) {
        if let Some(login) = self.login.borrow_mut().as_mut() {
            login.key.cancel();
        }
        self.reset_key_prompt();
    }

    /// "Use security key": a fresh challenge, then the key.
    pub(super) fn retry_key(&self) {
        if let Some(login) = self.login.borrow_mut().as_mut() {
            login.key.cancel();
            login.key.start_on_next_challenge = true;
        }
        self.run_login(None, None);
    }

    pub(super) fn submit_key_pin(&self) {
        let Some(window) = self.login_window() else {
            return;
        };
        let pin = Zeroizing::new(window.get_key_pin().to_string());
        window.set_key_pin(SharedString::new());
        if pin.is_empty() {
            window.set_error_text("Enter the security key's PIN".into());
            return;
        }
        window.set_error_text(SharedString::new());
        window.set_key_pin_needed(false);
        window.set_key_status("Checking the PIN…".into());
        if let Some(running) = self
            .login
            .borrow()
            .as_ref()
            .and_then(|login| login.key.running.as_ref())
        {
            running.enter_pin(pin);
        }
    }

    fn start_key(&self) {
        let Some(window) = self.login_window() else {
            return;
        };
        let request = self.login.borrow().as_ref().and_then(|login| {
            let options = parse(login.key.challenge.as_deref()?)?;
            let (server, ..) = login.pending.as_ref()?;
            Some((options, vk_webauthn::origin_of(server)))
        });
        let Some((options, origin)) = request else {
            window.set_error_text("The server sent no usable security key challenge".into());
            return;
        };
        let (events, receiver) = tokio::sync::mpsc::unbounded_channel();
        let round = {
            let mut guard = self.login.borrow_mut();
            let Some(login) = guard.as_mut() else {
                return;
            };
            login.key.cancel();
            login.key.round
        };
        window.set_error_text(SharedString::new());
        window.set_key_waiting(true);
        window.set_key_status("Plug in your security key and touch it".into());
        match self.hooks.security_keys.sign(options, origin, events) {
            Ok(running) => {
                if let Some(login) = self.login.borrow_mut().as_mut() {
                    login.key.running = Some(running);
                }
            }
            Err(error) => {
                self.reset_key_prompt();
                window.set_error_text(key_error_text(&error).into());
                return;
            }
        }
        self.exec.stream(
            receiver,
            handler!(self, |app, event| app.key_event(round, event)),
        );
    }

    fn key_event(&self, round: u64, event: KeyEvent) {
        let current = self
            .login
            .borrow()
            .as_ref()
            .is_some_and(|login| login.key.round == round);
        let Some(window) = self.login_window().filter(|_| current) else {
            return;
        };
        match event {
            KeyEvent::Touch => {
                window.set_key_pin_needed(false);
                window.set_key_status("Touch your security key".into());
            }
            KeyEvent::ChooseKey => {
                window.set_key_status("Several keys are plugged in: touch the one to use".into());
            }
            KeyEvent::Pin {
                wrong,
                attempts_left,
            } => {
                let status = match (wrong, attempts_left) {
                    (false, _) => "Enter your security key's PIN".to_owned(),
                    (true, Some(left)) => format!("Wrong PIN, {left} attempts left"),
                    (true, None) => "Wrong PIN, try again".to_owned(),
                };
                window.set_key_status(status.into());
                window.set_key_pin_needed(true);
            }
            KeyEvent::Done(result) => {
                if let Some(login) = self.login.borrow_mut().as_mut() {
                    login.key.running = None;
                    login.key.challenge = None;
                }
                self.reset_key_prompt();
                match result {
                    Ok(assertion) => {
                        let answer = TwoFactorAnswer {
                            provider: TwoFactorProvider::WebAuthn,
                            code: assertion.to_two_factor_token(),
                            remember: window.get_remember(),
                        };
                        self.run_login(Some(answer), None);
                    }
                    Err(HookError::Cancelled) => {}
                    Err(error) => window.set_error_text(key_error_text(&error).into()),
                }
            }
        }
    }

    fn reset_key_prompt(&self) {
        if let Some(window) = self.login_window() {
            window.set_key_waiting(false);
            window.set_key_pin_needed(false);
            window.set_key_pin(SharedString::new());
            window.set_key_status(SharedString::new());
        }
    }
}

fn key_error_text(error: &HookError) -> String {
    match error {
        HookError::Unavailable(_) => "Security keys cannot be used on this Mac".to_owned(),
        HookError::Cancelled => String::new(),
        HookError::Failed(text) => text.clone(),
    }
}
