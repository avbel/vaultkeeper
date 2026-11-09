//! Commands the daemon sends to the UI process, and the "last window closed" signal that drives
//! the UI process's linger timer.

use bwl_vault::{VaultService, model::SessionState};

use super::{App, SshApprovalRequest, Target};

/// What the daemon can ask the UI process to show.
#[derive(Debug)]
pub enum UiCommand {
    ShowManager,
    ShowQuickPanel,
    /// The global hotkey: open the Quick Panel, or close it when open.
    ToggleQuickPanel,
    ShowSshApproval(SshApprovalRequest),
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
}

impl<S: VaultService> App<S> {
    pub fn handle(&self, command: UiCommand) {
        if command.shows_a_window() {
            self.hooks.dock.activate();
        }
        match command {
            UiCommand::ShowManager => self.open_vault(),
            UiCommand::ShowQuickPanel => {
                if self.quick.borrow().is_none() {
                    self.toggle_quick_panel();
                }
            }
            UiCommand::ToggleQuickPanel => self.toggle_quick_panel(),
            UiCommand::ShowSshApproval(request) => self.request_ssh_approval(request),
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
            .search(query, &bwl_vault::model::Filter::default())
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
            // Counted like a window, so the process does not linger out under the system prompt.
            self.right_away_pending(),
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
            if app.open_window_count() == 0
                && let Some(callback) = app.on_last_window_closed.borrow().as_ref()
            {
                callback();
            }
        });
    }
}

impl UiCommand {
    /// Commands that put a window in front of the user, so the app must come forward first.
    const fn shows_a_window(&self) -> bool {
        !matches!(
            self,
            Self::VaultChanged | Self::ReloadSettings | Self::OfflineChanged(_)
        )
    }
}
