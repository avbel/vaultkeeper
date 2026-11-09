//! Master password re-prompt for items marked "Ask for master password": their secret fields are
//! released only after `VaultService::verify_master_password` succeeds, until the next lock.

use std::sync::Arc;

use bwl_vault::{
    VaultService,
    model::{CopyField, ItemId, ItemSummary},
};
use slint::{ComponentHandle, SharedString};
use zeroize::Zeroizing;

use super::{App, handler};
use crate::{ui::ManagerWindow, viewmodel};

/// What to finish once the password is confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Pending {
    Copy(CopyField),
    CopyDetail(i32),
    Reveal(i32),
    /// The edit form shows every secret unmasked-on-demand and can untick the re-prompt.
    Edit,
}

#[must_use]
pub const fn is_secret(field: CopyField) -> bool {
    matches!(
        field,
        CopyField::Password
            | CopyField::Totp
            | CopyField::Notes
            | CopyField::CardNumber
            | CopyField::CardCode
            | CopyField::SshPrivateKey
            | CopyField::Custom(_)
    )
}

impl<S: VaultService> App<S> {
    pub(super) fn bind_reprompt(&self, window: &ManagerWindow) {
        window.on_reprompt_submit(handler!(self, |app, password| {
            app.verify_reprompt(Zeroizing::new(password.to_string()));
        }));
        window.on_reprompt_cancel(handler!(self, |app| app.cancel_reprompt()));
    }

    pub(super) fn reprompt_cleared(&self, item: &ItemSummary) -> bool {
        !item.reprompt || self.reprompt_verified.borrow().contains(&item.id)
    }

    /// Refuses a secret of a re-prompt item: the Manager asks for the password inline and then
    /// finishes `pending`; the Quick Panel points to the Manager.
    pub(super) fn request_reprompt(&self, item: &ItemSummary, pending: Pending) {
        let Some(window) = self
            .manager
            .borrow()
            .as_ref()
            .map(|manager| manager.window.clone_strong())
        else {
            self.toast("Open in Manager (⌘O) to confirm your master password", true);
            return;
        };
        let shown = self
            .manager
            .borrow()
            .as_ref()
            .and_then(|manager| manager.selected.clone())
            .is_some_and(|id| id == item.id);
        if !shown {
            self.reveal_in_manager(&item.id);
        }
        self.reprompt_pending
            .replace(Some((item.id.clone(), pending)));
        window.set_reprompt_error(SharedString::new());
        window.set_reprompt_visible(true);
    }

    fn cancel_reprompt(&self) {
        self.reprompt_pending.replace(None);
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_reprompt_visible(false);
        }
    }

    fn verify_reprompt(&self, password: Zeroizing<String>) {
        if password.is_empty() {
            return;
        }
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.verify_master_password(password).await },
            handler!(self, |app, result| app.reprompt_verified(result)),
        );
    }

    fn reprompt_verified(&self, result: bwl_vault::Result<bool>) {
        let window = self
            .manager
            .borrow()
            .as_ref()
            .map(|manager| manager.window.clone_strong());
        match result {
            Ok(true) => {
                if let Some(window) = &window {
                    window.set_reprompt_visible(false);
                }
                if let Some((id, pending)) = self.reprompt_pending.take() {
                    self.reprompt_verified.borrow_mut().insert(id.clone());
                    self.finish_pending(&id, pending);
                }
            }
            Ok(false) => {
                if let Some(window) = &window {
                    window.set_reprompt_error("Wrong master password · try again".into());
                }
            }
            Err(error) => {
                if let Some(window) = &window {
                    window.set_reprompt_error(viewmodel::error_text(&error).into());
                }
            }
        }
    }

    fn finish_pending(&self, id: &ItemId, pending: Pending) {
        match pending {
            Pending::Copy(field) => {
                let item = self.manager.borrow().as_ref().and_then(|manager| {
                    manager
                        .rows
                        .position(id)
                        .and_then(|row| manager.rows.item(row))
                });
                if let Some(item) = item {
                    self.copy_item_field(&item, field);
                }
            }
            Pending::CopyDetail(index) => {
                self.copy_detail_field(index);
            }
            Pending::Reveal(index) => self.toggle_reveal(index),
            Pending::Edit => self.start_edit(),
        }
        // Codes held back for this item until now.
        self.refresh_totp();
    }

    /// Lock, logout and switch forget every confirmation.
    pub(super) fn forget_reprompts(&self) {
        self.reprompt_verified.borrow_mut().clear();
        self.reprompt_pending.replace(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_fields_need_the_reprompt() {
        for field in [
            CopyField::Password,
            CopyField::Totp,
            CopyField::CardNumber,
            CopyField::CardCode,
            CopyField::SshPrivateKey,
            CopyField::Custom(0),
            CopyField::Notes,
        ] {
            assert!(is_secret(field), "{field:?}");
        }
        for field in [
            CopyField::Username,
            CopyField::Uri,
            CopyField::Email,
            CopyField::Phone,
            CopyField::SshPublicKey,
        ] {
            assert!(!is_secret(field), "{field:?}");
        }
    }
}
