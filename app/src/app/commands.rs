//! Commands the daemon sends to the UI process, and the "last window closed" signal that drives
//! the UI process's linger timer.

use bwl_vault::{VaultService, model::SessionState};

use super::{App, SshApprovalRequest, Target};

/// What the daemon can ask the UI process to show.
#[derive(Debug)]
pub enum UiCommand {
    ShowManager,
    ShowQuickPanel,
    ShowSshApproval(SshApprovalRequest),
    ShowUnlock,
    ShowLogin,
    /// Opens the Manager on the first item matching `query` (unlocked only).
    ShowItem {
        query: String,
    },
    /// The vault changed in the daemon (sync, lock timeout, sleep).
    VaultChanged,
}

impl<S: VaultService> App<S> {
    pub fn handle(&self, command: UiCommand) {
        match command {
            UiCommand::ShowManager => self.open_vault(),
            UiCommand::ShowQuickPanel => {
                if self.quick.borrow().is_none() {
                    self.toggle_quick_panel();
                }
            }
            UiCommand::ShowSshApproval(request) => self.request_ssh_approval(request),
            UiCommand::ShowUnlock => match self.vault.state() {
                SessionState::Locked { .. } => {
                    self.target.set(Target::Manager);
                    self.open_lock_window();
                }
                SessionState::LoggedOut => self.show_login_for_state(),
                SessionState::Unlocked { .. } => self.open_manager(),
            },
            UiCommand::ShowLogin => self.show_login_for_state(),
            UiCommand::ShowItem { query } => self.show_item(&query),
            UiCommand::VaultChanged => self.on_vault_changed(),
        }
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
