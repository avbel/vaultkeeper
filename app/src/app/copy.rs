//! One-click copy: reveal on demand, hand to the clipboard hook, show footer feedback.

use slint::SharedString;
use vk_vault::{
    VaultService,
    model::{CopyField, ItemKind, ItemSummary},
};
use zeroize::Zeroizing;

use slint::ComponentHandle;

use super::App;
use crate::viewmodel::{self, copy_label, status_line};

impl<S: VaultService> App<S> {
    /// Returns whether the value reached the clipboard (the button then shows ✓).
    pub(super) fn copy_item_field(&self, item: &ItemSummary, field: CopyField) -> bool {
        if super::reprompt::is_secret(field) && !self.reprompt_cleared(item) {
            self.request_reprompt(item, super::reprompt::Pending::Copy(field));
            return false;
        }
        match self.vault.reveal(&item.id, field) {
            Ok(value) => self.copy_text(copy_label(field), &value),
            Err(error) => {
                self.toast(&viewmodel::error_text(&error), true);
                false
            }
        }
    }

    pub(super) fn copy_text(&self, label: &str, value: &Zeroizing<String>) -> bool {
        if value.is_empty() {
            self.toast("Nothing to copy", true);
            return false;
        }
        let clear_after = self.settings.borrow().clipboard_clear.duration();
        if let Err(error) = self.hooks.clipboard.copy(value, clear_after) {
            self.toast(&format!("Copy failed: {error}"), true);
            return false;
        }
        let total = clear_after.map_or(0, |after| {
            i32::try_from(after.as_secs()).unwrap_or(i32::MAX)
        });
        let clears_at =
            self.hooks.clock.unix_now() + clear_after.map_or(0, |after| after.as_secs());
        self.clip
            .replace(Some((format!("Copied {label}").into(), clears_at, total)));
        self.restore_clip_status();
        true
    }

    /// Shows the last copy's countdown in the Manager footer, if it is still running.
    pub(super) fn restore_clip_status(&self) {
        let Some(manager) = self
            .manager
            .borrow()
            .as_ref()
            .map(|manager| manager.window.clone_strong())
        else {
            return;
        };
        let now = self.hooks.clock.unix_now();
        match self.clip.borrow().as_ref() {
            Some((label, _, 0)) => {
                manager.set_clip_label(label.clone());
                manager.set_clip_total(0);
                manager.set_clip_seconds(0);
            }
            Some((label, clears_at, total)) if *clears_at > now => {
                manager.set_clip_label(label.clone());
                manager.set_clip_total(*total);
                manager.set_clip_seconds(i32::try_from(clears_at - now).unwrap_or(0));
            }
            _ => {
                manager.set_clip_label(SharedString::new());
                manager.set_clip_seconds(0);
            }
        }
    }

    pub(super) fn refresh_status(&self) {
        let guard = self.manager.borrow();
        let Some(manager) = guard.as_ref() else {
            return;
        };
        let now = self.hooks.clock.unix_now();
        // The daemon's own syncs (timer, websocket, on unlock) count, not only the UI's.
        let synced = self
            .vault
            .last_sync()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|elapsed| elapsed.as_secs())
            .max(self.last_sync.get());
        let since = synced.map(|synced| now.saturating_sub(synced));
        let ssh_keys = self.settings.borrow().ssh_agent.then(|| {
            manager
                .counts
                .kinds
                .get(&ItemKind::SshKey)
                .copied()
                .unwrap_or(0)
        });
        let text = status_line(since, self.vault.is_offline(), manager.counts.all, ssh_keys);
        manager.window.set_status_text(text.into());
    }
}
