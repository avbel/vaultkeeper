//! Commands the daemon sends to the UI process, and the "last window closed" signal that drives
//! the UI process's linger timer.

use vk_vault::{VaultService, model::SessionState};

use super::{App, BrowserPromptRequest, SshApprovalRequest, Target};
use crate::hooks::TypingTarget;

/// What the daemon can ask the UI process to show.
#[derive(Debug)]
pub enum UiCommand {
    ShowManager,
    /// `target` is where auto-type goes: the app that was in front when the user asked, as the
    /// daemon saw it.
    ShowQuickPanel {
        target: Option<TypingTarget>,
    },
    /// The global hotkey: open the Quick Panel, or close it when open.
    ToggleQuickPanel {
        target: Option<TypingTarget>,
    },
    ShowSshApproval(SshApprovalRequest),
    ShowBrowserPrompt(BrowserPromptRequest),
    ShowUnlock,
    ShowLogin,
    ShowSettings,
    ShowGenerator,
    /// The lock screen, Touch ID offered once; the unlock opens nothing else ("Ask to unlock on
    /// start", SSH requests before the first unlock).
    UnlockInTray,
    /// Opens the Manager on the first item matching `query` (unlocked only).
    ShowItem {
        query: String,
    },
    /// The vault changed in the daemon (sync, lock timeout, sleep).
    VaultChanged,
    /// The daemon rewrote the settings (theme from the tray menu).
    ReloadSettings,
    /// The server became unreachable (`true`) or reachable again.
    OfflineChanged(bool),
    /// The tray's "Sync now" ended, with the error text when it failed.
    SyncFinished(Option<String>),
    /// A daemon-side message; shown now when a window is open, otherwise with the next one.
    Toast {
        text: String,
        error: bool,
    },
}

impl<S: VaultService> App<S> {
    pub fn handle(&self, command: UiCommand) {
        // Any other window request drops the target, so a panel opened later from inside
        // vaultkeeper (⌘K) never types into an app that was in front long ago. An open panel keeps
        // its own copy.
        // The hotkey on an open panel closes it and hands the front back; activating first
        // would only flash vaultkeeper forward.
        let closes_panel =
            matches!(command, UiCommand::ToggleQuickPanel { .. }) && self.quick.borrow().is_some();
        if command.shows_a_window() && !closes_panel {
            self.typing_target
                .replace(command.typing_target().and_then(not_vaultkeeper));
            self.hooks.dock.activate();
        }
        match command {
            UiCommand::ShowManager => self.open_vault(),
            UiCommand::ShowQuickPanel { .. } => {
                if self.quick.borrow().is_none() {
                    self.toggle_quick_panel();
                }
            }
            UiCommand::ToggleQuickPanel { .. } => self.toggle_quick_panel(),
            UiCommand::ShowSshApproval(request) => self.request_ssh_approval(request),
            UiCommand::ShowBrowserPrompt(request) => self.request_browser_prompt(request),
            UiCommand::ShowUnlock => match self.vault.state() {
                SessionState::Locked { .. } => {
                    self.target.set(Target::Manager);
                    self.request_unlock(super::unlock::UnlockView::LockWindow);
                }
                SessionState::LoggedOut => self.show_login_for_state(),
                SessionState::Unlocked { .. } => self.open_manager(),
            },
            UiCommand::ShowLogin => self.show_login_for_state(),
            UiCommand::ShowSettings => self.open_settings(),
            UiCommand::ShowGenerator => self.open_generator_window(),
            UiCommand::UnlockInTray => {
                if matches!(self.vault.state(), SessionState::Locked { .. }) {
                    self.ask_unlock_on_start();
                }
            }
            UiCommand::ShowItem { query } => self.show_item(&query),
            UiCommand::VaultChanged => self.on_vault_changed(),
            UiCommand::ReloadSettings => self.reload_settings(),
            UiCommand::OfflineChanged(offline) => self.offline_changed(offline),
            UiCommand::SyncFinished(error) => self.sync_finished(error.as_deref()),
            UiCommand::Toast { text, error } => self.daemon_toast(text, error),
        }
    }

    /// Only an open Manager shows it; the tray menu carries the result otherwise.
    pub(super) fn sync_finished(&self, error: Option<&str>) {
        if self.manager.borrow().is_none() {
            return;
        }
        match error {
            None => self.toast(super::SYNCED_TOAST, false),
            Some(error) => self.toast(&format!("Sync failed: {error}"), true),
        }
        self.refresh_status();
    }

    fn daemon_toast(&self, text: String, error: bool) {
        if self.manager.borrow().is_some() || self.quick.borrow().is_some() {
            self.toast(&text, error);
        } else {
            self.pending_notice.replace(Some(text));
        }
    }

    fn offline_changed(&self, offline: bool) {
        if offline {
            self.toast(super::OFFLINE_TOAST, false);
        }
        self.refresh_status();
    }

    fn show_item(&self, query: &str) {
        let first = self
            .vault
            .search(query, &vk_vault::model::Filter::default())
            .ok()
            .and_then(|items| items.first().map(|item| item.id.clone()));
        match first {
            Some(id) => self.reveal_in_manager(&id),
            None => self.open_vault(),
        }
    }

    /// Called once each time the number of open windows drops to zero.
    pub fn set_on_last_window_closed(&self, callback: impl Fn() + 'static) {
        *self.on_last_window_closed.borrow_mut() = Some(Box::new(callback));
    }

    #[must_use]
    pub fn open_window_count(&self) -> usize {
        [
            self.manager.borrow().is_some(),
            self.quick.borrow().is_some(),
            self.lock_window.borrow().is_some(),
            self.login.borrow().is_some(),
            self.settings_window.borrow().is_some(),
            self.generator_window.borrow().is_some(),
            self.ssh_prompt.borrow().is_some(),
            self.browser_pair_prompt.borrow().is_some(),
            self.browser_save_prompt.borrow().is_some(),
            self.browser_picker.borrow().is_some(),
            // Counted like a window, so the process does not linger out under the system prompt.
            self.right_away_pending(),
            self.autotyping.get(),
        ]
        .into_iter()
        .filter(|open| *open)
        .count()
    }

    /// Every `close_*` calls this after dropping its window. The count is checked on the next
    /// event-loop turn, because flows such as unlock close one window just before opening the next.
    pub(super) fn window_closed(&self) {
        let weak = std::rc::Weak::clone(&self.me);
        slint::Timer::single_shot(std::time::Duration::ZERO, move || {
            let Some(app) = weak.upgrade() else {
                return;
            };
            if app.open_window_count() != 0 {
                return;
            }
            app.hooks.dock.hide();
            if let Some(callback) = app.on_last_window_closed.borrow().as_ref() {
                callback();
            }
        });
    }
}

/// Typing into vaultkeeper itself would type the password into its own search field.
fn not_vaultkeeper(target: TypingTarget) -> Option<TypingTarget> {
    let own = i32::try_from(std::process::id()).ok();
    (target.pid > 0 && Some(target.pid) != own).then_some(target)
}

impl UiCommand {
    fn typing_target(&self) -> Option<TypingTarget> {
        match self {
            Self::ShowQuickPanel { target } | Self::ToggleQuickPanel { target } => target.clone(),
            _ => None,
        }
    }

    /// Commands that put a window in front of the user, so the app must come forward first.
    const fn shows_a_window(&self) -> bool {
        !matches!(
            self,
            Self::VaultChanged
                | Self::ReloadSettings
                | Self::OfflineChanged(_)
                | Self::SyncFinished(_)
                | Self::Toast { .. }
                | Self::ShowBrowserPrompt(BrowserPromptRequest {
                    prompt: vk_ipc::BrowserPrompt::Save { .. }
                        | vk_ipc::BrowserPrompt::AddAddress { .. }
                        | vk_ipc::BrowserPrompt::Passkey { .. },
                    ..
                })
        )
    }
}

#[cfg(test)]
mod browser_tests {
    use super::*;
    use tokio::sync::oneshot;
    use vk_ipc::BrowserPrompt;

    #[test]
    fn save_prompts_do_not_request_activation() {
        let (reply, _receiver) = oneshot::channel();
        let command = UiCommand::ShowBrowserPrompt(BrowserPromptRequest {
            prompt: BrowserPrompt::Save {
                browser: "Firefox".into(),
                host: "example.com".into(),
                username: "user".into(),
                update_of: None,
                choices: vec![],
                return_to: None,
            },
            reply,
        });
        assert!(!command.shows_a_window());
    }
}
