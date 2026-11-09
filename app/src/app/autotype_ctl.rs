//! Quick Panel auto-type (⌘⇧↩ and the row button): types `<username> Tab <password>` of the
//! selected login into the app that was in front when the panel opened. Never via the clipboard.

use slint::ComponentHandle;
use vk_vault::{
    VaultService,
    model::{CopyField, ItemSummary, SessionState},
};
use zeroize::Zeroizing;

use super::{App, handler};
use crate::{
    autotype::{can_auto_type, login_strokes},
    hooks::{HookError, HookResult},
    viewmodel,
};

pub const ACCESSIBILITY_NEEDED: &str =
    "Allow Vaultkeeper in System Settings → Privacy & Security → Accessibility, then try again";
pub const NO_TARGET: &str = "No app to type into: open the Quick Panel from that app";
pub const NO_PASSWORD: &str = "This login has no password to type";
pub const LOCKED_WHILE_TYPING: &str = "Auto-type stopped: the vault locked";

impl<S: VaultService> App<S> {
    /// Returns whether the key was handled.
    pub(super) fn auto_type_row(&self, row: Option<i32>) -> bool {
        if !matches!(self.vault.state(), SessionState::Unlocked { .. }) {
            return false;
        }
        let Some(item) = self.quick_item(row).filter(can_auto_type) else {
            return false;
        };
        if !self.reprompt_cleared(&item) {
            self.panel_toast(super::reprompt::CONFIRM_IN_MANAGER);
            return true;
        }
        let Some(target) = self
            .quick
            .borrow()
            .as_ref()
            .and_then(|quick| quick.typing_target.clone())
        else {
            self.panel_toast(NO_TARGET);
            return true;
        };
        if !self.hooks.autotype.is_trusted(true) {
            self.show_notice(ACCESSIBILITY_NEEDED);
            return true;
        }
        let Some((username, password)) = self.login_secrets(&item) else {
            return true;
        };
        let strokes = login_strokes(&username, &password);
        drop((username, password));
        self.close_quick_panel();
        self.autotyping.set(true);
        self.hooks.autotype.start(
            target,
            strokes,
            Box::new(handler!(self, |app, result| app.auto_typed(&result))),
        );
        true
    }

    fn login_secrets(&self, item: &ItemSummary) -> Option<(Zeroizing<String>, Zeroizing<String>)> {
        // An empty field is reported as missing; for auto-type that is just nothing to type.
        let reveal = |field| match self.vault.reveal(&item.id, field) {
            Ok(value) => Some(value),
            Err(vk_vault::Error::NoSuchField) => Some(Zeroizing::new(String::new())),
            Err(error) => {
                self.panel_toast(&viewmodel::error_text(&error));
                None
            }
        };
        let password = reveal(CopyField::Password)?;
        if password.is_empty() {
            self.panel_toast(NO_PASSWORD);
            return None;
        }
        let username = reveal(CopyField::Username)?;
        Some((username, password))
    }

    fn auto_typed(&self, result: &HookResult<()>) {
        self.autotyping.set(false);
        if let Err(error) = result {
            tracing::warn!(%error, "auto-type did not finish");
            let text = match error {
                HookError::Cancelled => LOCKED_WHILE_TYPING.to_owned(),
                other => other.to_string(),
            };
            self.pending_notice.replace(Some(text));
            self.show_pending_notices();
        }
        self.window_closed();
    }

    /// Toasts `text` now and keeps it for the next window: the panel that shows it may close
    /// at once, e.g. when the system's permission dialog takes the focus. Seeing the toast out
    /// (it hides after a few seconds) drops it.
    fn show_notice(&self, text: &str) {
        self.pending_notice.replace(Some(text.to_owned()));
        self.panel_toast(text);
    }

    /// An error about the panel's auto-type, on the panel: `toast` prefers an open Manager,
    /// which may sit behind other apps, so the user pressing ⌘⇧↩ in the panel would see nothing.
    fn panel_toast(&self, text: &str) {
        let Some(window) = self
            .quick
            .borrow()
            .as_ref()
            .map(|quick| quick.window.clone_strong())
        else {
            self.toast(text, true);
            return;
        };
        tracing::warn!(text, "error toast");
        window.set_toast_text(text.into());
        window.set_toast_error(true);
        window.set_toast_shown(true);
    }

    /// The Quick Panel's toast closed on screen, so a notice it showed has been read.
    pub(super) fn notice_seen(&self) {
        self.pending_notice.replace(None);
    }
}
