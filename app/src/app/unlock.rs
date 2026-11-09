//! "Unlock with Touch ID right away": a request that needs the vault (Manager, Quick Panel, the
//! tray's Unlock, an SSH request, "Ask to unlock on start") starts the Touch ID prompt before any
//! lock window. Only a cancel or failure shows the window the request would have shown, and while
//! that window stays open no request prompts again: after a "no" the user decides.

use bwl_vault::VaultService;

use super::App;
use crate::hooks::{HookError, HookResult};

/// The window a locked request shows: the lock window, or the Quick Panel with its inline
/// password field for the hotkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnlockView {
    LockWindow,
    QuickPanel,
}

impl<S: VaultService> App<S> {
    /// Every user request that needs a locked vault unlocked ends here, with `target` already set.
    pub(super) fn request_unlock(&self, view: UnlockView) {
        if self.right_away.get().is_some() {
            // The prompt on screen answers this request too; a failure shows the latest view.
            self.right_away.set(Some(view));
            return;
        }
        if self.right_away_declined.get() || !self.touch_id_right_away() {
            self.show_unlock_view(view);
            return;
        }
        self.right_away.set(Some(view));
        if !self.unlock_touch_id() {
            self.right_away.set(None);
            self.show_unlock_view(view);
        }
    }

    /// Enrolled and allowed now ("Require master password on app start" keeps the first unlock
    /// for the password), and switched on.
    pub(super) fn touch_id_right_away(&self) -> bool {
        self.settings.borrow().touch_id_right_away && self.touch_id_enrolled()
    }

    /// A right-away prompt is on screen (with no window, or the lock window a lock left open).
    pub(super) fn right_away_pending(&self) -> bool {
        self.right_away.get().is_some()
    }

    /// The lock view a declined attempt opened is gone, or the vault unlocked: the next request
    /// may prompt again.
    pub(super) fn forget_declined_touch_id(&self) {
        self.right_away_declined.set(false);
    }

    fn show_unlock_view(&self, view: UnlockView) {
        match view {
            UnlockView::LockWindow => self.open_lock_window(),
            UnlockView::QuickPanel => self.open_quick_panel(),
        }
    }

    /// Ends a right-away attempt; `false` when the attempt was a plain one (lock window button,
    /// Return on an empty field), which the caller reports as before.
    pub(super) fn finish_right_away(&self, result: &HookResult<()>) -> bool {
        let Some(view) = self.right_away.take() else {
            return false;
        };
        match result {
            Ok(()) => {
                // The system prompt had the focus; the window the request opens needs it back.
                self.hooks.dock.activate();
                self.on_vault_changed();
                // No window may open (an unlock for SSH or at start); the linger timer of the UI
                // process must still start again.
                self.window_closed();
            }
            Err(error) => {
                tracing::info!(%error, "Touch ID right away did not unlock");
                if !matches!(
                    self.vault.state(),
                    bwl_vault::model::SessionState::Locked { .. }
                ) {
                    self.on_vault_changed();
                    self.window_closed();
                    return true;
                }
                self.right_away_declined.set(true);
                self.show_unlock_view(view);
                // A cancel is the user's own choice; the window says nothing about it.
                if !matches!(error, HookError::Cancelled) {
                    self.show_touch_id_error(error);
                }
            }
        }
        true
    }
}
