//! Manager "Send" section: the list of Sends, their detail pane and the text Send form. Active
//! while the sidebar's Send entry is selected; the item list, detail and edit stay untouched.

use std::{rc::Rc, sync::Arc};

use slint::{Model, ModelRc, SharedString, VecModel};
use vk_vault::{
    VaultService,
    model::{SendDraft, SendKind, SendSummary},
};
use zeroize::Zeroizing;

use super::{App, handler};
use crate::{
    send_view::{self, DEFAULT_PRESET, SendForm},
    sidebar::SidebarKey,
    ui::{ManagerWindow, RowData, SendDetail},
    viewmodel,
};

const VIEW_MODE: i32 = 4;
const EDIT_MODE: i32 = 5;

pub(super) struct SendPane {
    pub(super) rows: Rc<VecModel<RowData>>,
    /// The listed Sends, in row order.
    pub(super) sends: Vec<SendSummary>,
    pub(super) selected: Option<Arc<str>>,
    /// The selected text Send, decrypted while the pane shows it.
    draft: Option<SendDraft>,
    revealed: bool,
    pub(super) edit: Option<SendEdit>,
}

pub(super) struct SendEdit {
    id: Option<Arc<str>>,
    base: Option<SendDraft>,
    /// The unix time behind each deletion choice.
    deletion_dates: Vec<i64>,
}

impl Default for SendPane {
    fn default() -> Self {
        Self {
            rows: Rc::new(VecModel::default()),
            sends: Vec::new(),
            selected: None,
            draft: None,
            revealed: false,
            edit: None,
        }
    }
}

impl SendPane {
    pub(super) fn strings(&self, window: &ManagerWindow) -> Vec<String> {
        let mut strings: Vec<String> = self
            .rows
            .iter()
            .flat_map(|row| [row.name.to_string(), row.subtitle.to_string()])
            .collect();
        if let Some(draft) = &self.draft {
            strings.extend([
                draft.name.clone(),
                draft.text.to_string(),
                draft.notes.to_string(),
            ]);
        }
        let detail = window.get_send_detail();
        strings.extend([detail.name.to_string(), detail.text.to_string()]);
        if self.edit.is_some() {
            strings.extend([
                window.get_send_name().to_string(),
                window.get_send_text().to_string(),
                window.get_send_password().to_string(),
                window.get_send_notes().to_string(),
            ]);
        }
        strings
    }
}

impl<S: VaultService> App<S> {
    pub(super) fn bind_manager_send(&self, window: &ManagerWindow) {
        window.on_send_copy_link(handler!(self, false, |app| app.copy_selected_send_link()));
        window.on_send_copy_text(handler!(self, false, |app| app.copy_send_text()));
        window.on_send_toggle_text(handler!(self, |app| app.toggle_send_text()));
        window.on_send_edit(handler!(self, |app| app.start_send_edit()));
        window.on_send_delete_confirmed(handler!(self, |app| app.delete_selected_send()));
        window.on_send_remove_password_confirmed(
            handler!(self, |app| app.remove_selected_send_password())
        );
        window.on_send_generate_password(handler!(self, |app| app.generate_send_password()));
        window.on_send_save(handler!(self, |app| app.save_send()));
        window.on_send_cancel(handler!(self, |app| app.cancel_send_edit()));
    }

    pub(super) fn in_send_mode(&self) -> bool {
        self.manager
            .borrow()
            .as_ref()
            .is_some_and(|manager| manager.sidebar_key == SidebarKey::Send)
    }

    pub(super) fn editing_send(&self) -> bool {
        self.manager
            .borrow()
            .as_ref()
            .is_some_and(|manager| manager.send.edit.is_some())
    }

    /// Swaps the list between items and Sends when the sidebar crosses into or out of Send.
    pub(super) fn set_send_mode(&self, on: bool) {
        let guard = self.manager.borrow();
        let Some(manager) = guard.as_ref() else {
            return;
        };
        if manager.window.get_send_mode() == on {
            return;
        }
        manager.window.set_send_mode(on);
        if on {
            manager
                .window
                .set_rows(ModelRc::from(Rc::clone(&manager.send.rows)));
        } else {
            manager
                .window
                .set_rows(ModelRc::from(Rc::clone(&manager.rows)));
        }
        drop(guard);
        if on {
            self.clear_detail();
        } else {
            self.clear_send_detail();
        }
    }

    /// Re-reads the Sends, filtered by the search field, and keeps the selection when it is
    /// still listed.
    pub(super) fn refresh_send_list(&self) {
        let sends = match self.vault.sends() {
            Ok(sends) => sends,
            Err(error) => {
                self.toast(&viewmodel::error_text(&error), true);
                return;
            }
        };
        let now = self.send_now();
        let still_selected = {
            let mut guard = self.manager.borrow_mut();
            let Some(manager) = guard.as_mut() else {
                return;
            };
            let query = manager.window.get_query().to_lowercase();
            let query = query.trim();
            let listed: Vec<SendSummary> = sends
                .into_iter()
                .filter(|send| query.is_empty() || send.name.to_lowercase().contains(query))
                .collect();
            manager.send.rows.set_vec(
                listed
                    .iter()
                    .map(|send| send_view::to_row(send, now))
                    .collect::<Vec<_>>(),
            );
            let row = manager
                .send
                .selected
                .as_ref()
                .and_then(|id| listed.iter().position(|send| send.id == *id));
            manager.send.sends = listed;
            manager.window.set_selected(row.map_or(-1, to_i32));
            let empty_kind = if query.is_empty() { 3 } else { 1 };
            manager.window.set_empty_kind(empty_kind);
            manager.window.set_loading(false);
            row.is_some()
        };
        if still_selected {
            self.reload_send_detail();
        } else {
            self.clear_send_detail();
        }
    }

    pub(super) fn select_send_row(&self, row: i32) {
        let id = {
            let guard = self.manager.borrow();
            let Some(manager) = guard.as_ref() else {
                return;
            };
            if manager.send.edit.is_some() {
                drop(guard);
                self.toast("Save or cancel the Send first", true);
                return;
            }
            let Some(send) = usize::try_from(row)
                .ok()
                .and_then(|row| manager.send.sends.get(row))
            else {
                return;
            };
            manager.window.set_selected(row);
            manager.window.invoke_scroll_to(row);
            Arc::clone(&send.id)
        };
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            if manager.send.selected.as_ref() != Some(&id) {
                manager.send.revealed = false;
                manager.window.set_send_confirm_delete(false);
                manager.window.set_send_confirm_remove_password(false);
            }
            manager.send.selected = Some(id);
        }
        self.reload_send_detail();
    }

    pub(super) fn move_send_selection(&self, delta: i32) -> bool {
        let next = {
            let guard = self.manager.borrow();
            let Some(manager) = guard.as_ref() else {
                return false;
            };
            let count = to_i32(manager.send.sends.len());
            if count == 0 {
                return true;
            }
            manager.window.set_keyboard_nav(true);
            (manager.window.get_selected() + delta).clamp(0, count - 1)
        };
        self.select_send_row(next);
        true
    }

    /// Decrypts the selected text Send (kept only while the pane shows it) and fills the pane.
    fn reload_send_detail(&self) {
        let summary = self.manager.borrow().as_ref().and_then(|manager| {
            let id = manager.send.selected.as_ref()?;
            manager
                .send
                .sends
                .iter()
                .find(|send| send.id == *id)
                .cloned()
        });
        let Some(summary) = summary else {
            self.clear_send_detail();
            return;
        };
        let draft = if summary.kind == SendKind::Text {
            match self.vault.send_draft(&summary.id) {
                Ok(draft) => Some(draft),
                Err(error) => {
                    self.toast(&viewmodel::error_text(&error), true);
                    None
                }
            }
        } else {
            None
        };
        let now = self.send_now();
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            let detail = send_view::detail(&summary, draft.as_ref(), manager.send.revealed, now);
            manager.send.draft = draft;
            manager.window.set_send_detail(detail);
            if manager.send.edit.is_none() {
                manager.window.set_detail_mode(VIEW_MODE);
            }
        }
    }

    pub(super) fn clear_send_detail(&self) {
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            manager.send.selected = None;
            manager.send.draft = None;
            manager.send.revealed = false;
            manager.window.set_send_detail(SendDetail::default());
            manager.window.set_send_confirm_delete(false);
            manager.window.set_send_confirm_remove_password(false);
            if manager.send.edit.is_none() && manager.window.get_detail_mode() == VIEW_MODE {
                manager.window.set_detail_mode(0);
            }
            if manager.window.get_send_mode() {
                manager.window.set_selected(-1);
            }
        }
    }

    fn selected_send(&self) -> Option<SendSummary> {
        self.manager.borrow().as_ref().and_then(|manager| {
            let id = manager.send.selected.as_ref()?;
            manager
                .send
                .sends
                .iter()
                .find(|send| send.id == *id)
                .cloned()
        })
    }

    pub(super) fn copy_send_link(&self, id: &str) -> bool {
        match self.vault.send_link(id) {
            Ok(link) => self.copy_text("Send link", &link),
            Err(error) => {
                self.toast(&viewmodel::error_text(&error), true);
                false
            }
        }
    }

    pub(super) fn copy_selected_send_link(&self) -> bool {
        match self.selected_send() {
            Some(send) => self.copy_send_link(&send.id),
            None => false,
        }
    }

    pub(super) fn copy_send_row(&self, row: i32, code: i32) -> bool {
        let id = self.manager.borrow().as_ref().and_then(|manager| {
            usize::try_from(row)
                .ok()
                .and_then(|row| manager.send.sends.get(row))
                .map(|send| Arc::clone(&send.id))
        });
        match id {
            Some(id) if code == send_view::LINK_CODE => self.copy_send_link(&id),
            _ => false,
        }
    }

    fn copy_send_text(&self) -> bool {
        let text = self
            .manager
            .borrow()
            .as_ref()
            .and_then(|manager| manager.send.draft.as_ref().map(|draft| draft.text.clone()));
        text.is_some_and(|text| self.copy_text("Send text", &text))
    }

    /// Re-renders from the draft already held, so revealing costs no second decrypt.
    fn toggle_send_text(&self) {
        let now = self.send_now();
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            manager.send.revealed = !manager.send.revealed;
            let summary = manager
                .send
                .selected
                .as_ref()
                .and_then(|id| manager.send.sends.iter().find(|send| send.id == *id));
            if let Some(summary) = summary {
                let detail = send_view::detail(
                    summary,
                    manager.send.draft.as_ref(),
                    manager.send.revealed,
                    now,
                );
                manager.window.set_send_detail(detail);
            }
        }
    }

    fn sends_online(&self) -> bool {
        if self.vault.is_offline() {
            self.toast("Sends can't be changed while offline", true);
            return false;
        }
        true
    }

    pub(super) fn start_send_edit(&self) {
        let (id, draft) = {
            let guard = self.manager.borrow();
            let Some(manager) = guard.as_ref() else {
                return;
            };
            let (Some(id), Some(draft)) = (&manager.send.selected, &manager.send.draft) else {
                drop(guard);
                if self.selected_send().is_some() {
                    self.toast("Only text Sends can be edited here", true);
                }
                return;
            };
            (Arc::clone(id), draft.clone())
        };
        if !self.sends_online() {
            return;
        }
        self.open_send_form(Some(id), Some(draft));
    }

    /// "+ New ▸ Send" and ⌘N in the Send section: shows the Send list, then an empty form.
    pub(super) fn new_send(&self) {
        if self.editing() {
            self.toast("Save or cancel the edit first", true);
            return;
        }
        if !self.sends_online() {
            return;
        }
        if !self.in_send_mode() && !self.select_sidebar_key(&SidebarKey::Send) {
            return;
        }
        if self.editing_send() {
            return;
        }
        self.open_send_form(None, None);
    }

    fn open_send_form(&self, id: Option<Arc<str>>, base: Option<SendDraft>) {
        let now = self.send_now();
        let (labels, dates) =
            send_view::deletion_options(base.as_ref().map(|base| base.deletion_date), now);
        let guard = self.manager.borrow();
        let Some(manager) = guard.as_ref() else {
            return;
        };
        let window = &manager.window;
        let blank = Zeroizing::new(String::new());
        let (name, text, notes) = base.as_ref().map_or(("", &blank, &blank), |base| {
            (base.name.as_str(), &base.text, &base.notes)
        });
        window.set_send_edit_title(
            if id.is_some() {
                "Edit Send"
            } else {
                "New Send"
            }
            .into(),
        );
        window.set_send_name(name.into());
        window.set_send_text(text.as_str().into());
        window.set_send_notes(notes.as_str().into());
        window.set_send_hidden(base.as_ref().is_some_and(|base| base.hidden));
        window.set_send_hide_email(base.as_ref().is_some_and(|base| base.hide_email));
        window.set_send_password(SharedString::new());
        window.set_send_has_password(base.as_ref().is_some_and(|base| base.has_password));
        window.set_send_max_views(
            base.as_ref()
                .and_then(|base| base.max_access_count)
                .map_or_else(SharedString::new, |max| max.to_string().into()),
        );
        let views_hint = manager
            .send
            .sends
            .iter()
            .find(|send| id.as_ref() == Some(&send.id))
            .map_or_else(String::new, |send| {
                format!("Opened {} so far", send_view::views(send))
            });
        window.set_send_views_hint(views_hint.into());
        window.set_send_deletion_options(ModelRc::new(VecModel::from(labels)));
        window.set_send_deletion_index(if base.is_some() {
            0
        } else {
            to_i32(DEFAULT_PRESET)
        });
        window.set_send_edit_error(SharedString::new());
        window.set_send_saving(false);
        window.set_detail_mode(EDIT_MODE);
        drop(guard);
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            manager.send.edit = Some(SendEdit {
                id,
                base,
                deletion_dates: dates,
            });
        }
    }

    pub(super) fn cancel_send_edit(&self) {
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            if manager.window.get_send_saving() {
                return;
            }
            manager.send.edit = None;
            clear_send_form(&manager.window);
            let mode = if manager.send.selected.is_some() {
                VIEW_MODE
            } else {
                0
            };
            manager.window.set_detail_mode(mode);
        }
    }

    fn generate_send_password(&self) {
        let options = self.generator.borrow().password_options();
        match self.hooks.generator.password(&options) {
            Ok(password) => {
                if let Some(manager) = self.manager.borrow().as_ref() {
                    manager.window.set_send_password(password.as_str().into());
                }
            }
            Err(error) => self.toast(&error.to_string(), true),
        }
    }

    fn save_send(&self) {
        let prepared = {
            let guard = self.manager.borrow();
            let Some(manager) = guard.as_ref() else {
                return;
            };
            let Some(edit) = &manager.send.edit else {
                return;
            };
            let window = &manager.window;
            if window.get_send_saving() {
                return;
            }
            let deletion_date = usize::try_from(window.get_send_deletion_index())
                .ok()
                .and_then(|index| edit.deletion_dates.get(index))
                .copied();
            let Some(deletion_date) = deletion_date else {
                return;
            };
            let form = SendForm {
                name: window.get_send_name().into(),
                text: Zeroizing::new(window.get_send_text().into()),
                hidden: window.get_send_hidden(),
                deletion_date,
                password: Zeroizing::new(window.get_send_password().into()),
                max_views: window.get_send_max_views().into(),
                hide_email: window.get_send_hide_email(),
                notes: Zeroizing::new(window.get_send_notes().into()),
            };
            send_view::build_draft(form, edit.base.as_ref()).map(|draft| (edit.id.clone(), draft))
        };
        let (id, draft) = match prepared {
            Ok(prepared) => prepared,
            Err(message) => {
                if let Some(manager) = self.manager.borrow().as_ref() {
                    manager.window.set_send_edit_error(message.into());
                }
                return;
            }
        };
        if !self.sends_online() {
            return;
        }
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_send_saving(true);
            manager.window.set_send_edit_error(SharedString::new());
        }
        let created = id.is_none();
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.save_send(id, draft).await },
            handler!(self, |app, result| app.send_saved(result, created)),
        );
    }

    fn send_saved(&self, result: vk_vault::Result<SendSummary>, created: bool) {
        // The Manager may have closed (or locked) and reopened meanwhile: the answer then has no
        // form to close, and must not put a Send pane into another list.
        let form_open = self
            .manager
            .borrow()
            .as_ref()
            .is_some_and(|manager| manager.send.edit.is_some());
        if !form_open {
            self.on_vault_changed();
            return;
        }
        let saved = match result {
            Ok(saved) => saved,
            Err(error) => {
                if let Some(manager) = self.manager.borrow().as_ref() {
                    manager.window.set_send_saving(false);
                    manager
                        .window
                        .set_send_edit_error(viewmodel::error_text(&error).into());
                }
                return;
            }
        };
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            manager.window.set_send_saving(false);
            manager.send.edit = None;
            manager.send.selected = Some(Arc::clone(&saved.id));
            manager.send.revealed = false;
            clear_send_form(&manager.window);
            manager.window.set_detail_mode(VIEW_MODE);
        }
        self.on_vault_changed();
        // A new Send exists to be shared: its link goes straight to the clipboard.
        if created && self.copy_send_link(&saved.id) {
            self.toast("Send created · link copied", false);
        }
    }

    fn delete_selected_send(&self) {
        let Some(send) = self.selected_send() else {
            return;
        };
        if !self.sends_online() {
            return;
        }
        self.set_send_busy(true);
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.delete_send(&send.id).await },
            handler!(self, |app, result| app.send_write_done(&result)),
        );
    }

    fn remove_selected_send_password(&self) {
        let Some(send) = self.selected_send() else {
            return;
        };
        if !self.sends_online() {
            return;
        }
        self.set_send_busy(true);
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.remove_send_password(&send.id).await },
            handler!(self, |app, result| app.send_write_done(&result)),
        );
    }

    fn set_send_busy(&self, busy: bool) {
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_send_busy(busy);
        }
    }

    fn send_write_done(&self, result: &vk_vault::Result<()>) {
        self.set_send_busy(false);
        if let Err(error) = result {
            self.toast(&viewmodel::error_text(error), true);
        }
        self.on_vault_changed();
    }

    /// Escape in the Send section: closes the form, else clears the search.
    pub(super) fn send_escape(&self) -> bool {
        if self.editing_send() {
            self.cancel_send_edit();
            return true;
        }
        let has_query = self
            .manager
            .borrow()
            .as_ref()
            .is_some_and(|manager| !manager.window.get_query().is_empty());
        if !has_query {
            return false;
        }
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_query(SharedString::new());
        }
        self.refresh_send_list();
        true
    }

    fn send_now(&self) -> i64 {
        i64::try_from(self.hooks.clock.unix_now()).unwrap_or(i64::MAX)
    }
}

/// The form's secrets leave the window as soon as it closes.
fn clear_send_form(window: &ManagerWindow) {
    window.set_send_name(SharedString::new());
    window.set_send_text(SharedString::new());
    window.set_send_password(SharedString::new());
    window.set_send_notes(SharedString::new());
    window.set_send_max_views(SharedString::new());
    window.set_send_edit_error(SharedString::new());
}

fn to_i32(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}
