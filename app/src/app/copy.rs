//! One-click copy: reveal on demand, hand to the clipboard hook, show footer feedback.

use slint::SharedString;
use vk_vault::{
    VaultService,
    model::{CopyField, ItemKind, ItemSummary},
};
use zeroize::Zeroizing;

use slint::ComponentHandle;

use super::{App, handler};
use crate::{
    hooks::{CopyStart, HookError, HookResult},
    viewmodel::{self, copy_label, status_line},
};

const WAITING_FOR_PERMISSION: &str = "Waiting for clipboard permission: in the system dialog \
                                      switch on Allow Remote Interaction, then Share";
const WAITING_FOR_CLIPBOARD: &str = "Waiting for the clipboard…";

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
        // A second click while the dialog is open would queue a second copy behind it and
        // report twice.
        if let Some(waiting) = self.copy_waiting.get() {
            self.toast(waiting, false);
            return false;
        }
        let clear_after = self.settings.borrow().clipboard_clear.duration();
        match self.hooks.clipboard.begin_copy(value, clear_after) {
            CopyStart::Done(copied) => self.copy_finished(label, clear_after, copied),
            CopyStart::Waiting {
                outcome,
                permission_dialog,
            } => {
                tracing::info!(permission_dialog, "copy waits for the clipboard");
                let waiting = if permission_dialog {
                    WAITING_FOR_PERMISSION
                } else {
                    WAITING_FOR_CLIPBOARD
                };
                self.copy_waiting.set(Some(waiting));
                self.toast(waiting, false);
                let label = label.to_owned();
                self.exec.spawn_blocking(
                    move || {
                        outcome.recv().unwrap_or_else(|_| {
                            Err(HookError::Failed("the copy was abandoned".to_owned()))
                        })
                    },
                    handler!(self, |app, copied| {
                        app.copy_waiting.set(None);
                        if app.copy_finished(&label, clear_after, copied) {
                            tracing::info!("copy landed once the permission was given");
                            app.toast(&format!("Copied {label}"), false);
                        }
                    }),
                );
                false
            }
        }
    }

    /// The auto-clear countdown starts here, when the value is on the clipboard.
    fn copy_finished(
        &self,
        label: &str,
        clear_after: Option<std::time::Duration>,
        copied: HookResult<()>,
    ) -> bool {
        if let Err(error) = copied {
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
