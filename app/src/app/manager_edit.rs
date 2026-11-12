//! Manager edit form: start from the detail draft or an empty one, save through the vault.

use std::rc::Rc;

use slint::{Model, ModelRc, SharedString, VecModel};
use vk_vault::{
    VaultService,
    model::{CLI_ACCESS_FIELD, ItemData, ItemDraft, ItemId, ItemKind},
};

use super::{App, handler};
use crate::{
    edit_form,
    sidebar::SidebarKey,
    ui::{EditField, ManagerWindow},
    viewmodel::{NEW_KINDS, kind_label},
};

pub(super) struct Edit {
    pub(super) id: Option<ItemId>,
    /// The draft the form started from; fields not shown in the form are kept from it.
    base: ItemDraft,
    pub(super) fields: Rc<VecModel<EditField>>,
    /// The picked folder by id: the picker's index points into a list rebuilt in name order on
    /// every folder change.
    pub(super) folder_id: Option<std::sync::Arc<str>>,
}

fn folder_index(
    choices: &[Option<std::sync::Arc<str>>],
    folder_id: Option<&std::sync::Arc<str>>,
) -> i32 {
    choices
        .iter()
        .position(|choice| choice.as_ref() == folder_id)
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or(0)
}

impl<S: VaultService> App<S> {
    pub(super) fn bind_manager_edit(&self, window: &ManagerWindow) {
        window.on_new_item(handler!(self, |app, kind| app.new_item(kind)));
        window.on_edit_generate(handler!(self, |app, index| app.open_generator_for(index)));
        window.on_edit_field_edited(handler!(self, |app, index, text| {
            app.edit_field_edited(index, &text);
        }));
        window.on_edit_add_uri(handler!(self, |app| app.add_uri_field()));
        window.on_edit_add_custom(handler!(self, |app, kind| app.add_custom_field(kind)));
        window.on_edit_remove_custom(handler!(self, |app, index| app.remove_custom_field(index)));
        window.on_edit_save(handler!(self, |app| app.save_edit()));
        window.on_edit_cancel(handler!(self, |app| app.cancel_edit()));
        window.on_leave_save(handler!(self, |app| app.leave_save()));
        window.on_leave_discard(handler!(self, |app| app.leave_discard()));
        window.on_leave_cancel(handler!(self, |app| app.leave_cancel()));
        window.on_edit_folder_selected(handler!(self, |app, index| app.pick_edit_folder(index)));
    }

    /// Every way into the editor (button, ⌘E, double-click, Quick Panel ⌘E) ends here, so the
    /// re-prompt is asked here: the form reveals every secret and can untick the re-prompt.
    pub(super) fn start_edit(&self) {
        let editable = |detail: &&super::manager_detail::Detail| {
            detail.summary.editable && !detail.summary.deleted
        };
        let summary = self.manager.borrow().as_ref().and_then(|manager| {
            manager
                .detail
                .as_ref()
                .filter(editable)
                .map(|detail| detail.summary.clone())
        });
        let Some(summary) = summary else {
            return;
        };
        if !self.reprompt_cleared(&summary) {
            self.request_reprompt(&summary, super::reprompt::Pending::Edit);
            return;
        }
        let draft = self
            .manager
            .borrow()
            .as_ref()
            .and_then(|manager| manager.detail.as_ref().map(|detail| detail.draft.clone()));
        if let Some(draft) = draft {
            let title = format!("Edit {}", kind_label(summary.kind).to_lowercase());
            self.open_edit(Some(summary.id), draft, &title);
        }
    }

    /// `kind` indexes [`NEW_KINDS`]; the item starts in the folder selected in the sidebar.
    pub(super) fn new_item(&self, kind: i32) {
        let Some(kind) = usize::try_from(kind)
            .ok()
            .and_then(|index| NEW_KINDS.get(index))
            .copied()
        else {
            return;
        };
        let folder =
            self.manager
                .borrow()
                .as_ref()
                .and_then(|manager| match &manager.sidebar_key {
                    SidebarKey::Folder(id) => Some(std::sync::Arc::clone(id)),
                    _ => None,
                });
        let mut draft = match edit_form::new_draft(kind, folder) {
            Ok(draft) => draft,
            Err(error) => {
                self.toast(&error.to_string(), true);
                return;
            }
        };
        if kind == ItemKind::SshKey {
            match self.hooks.ssh_keys.generate() {
                Ok((private_key, public_key, fingerprint)) => {
                    draft.data = ItemData::SshKey {
                        private_key,
                        public_key,
                        fingerprint,
                    };
                }
                Err(error) => self.toast(&error.to_string(), true),
            }
        }
        self.open_edit(
            None,
            draft,
            &format!("New {}", kind_label(kind).to_lowercase()),
        );
    }

    fn open_edit(&self, id: Option<ItemId>, draft: ItemDraft, title: &str) {
        let mut guard = self.manager.borrow_mut();
        let Some(manager) = guard.as_mut() else {
            return;
        };
        let fields = Rc::new(VecModel::from(edit_form::edit_fields(&draft)));
        let folder_index = folder_index(&manager.folder_choices, draft.folder_id.as_ref());
        let window = &manager.window;
        window.set_edit_title(title.into());
        window.set_edit_fields(ModelRc::from(Rc::clone(&fields)));
        window.set_edit_error(SharedString::new());
        window.set_edit_favorite(draft.favorite);
        window.set_edit_reprompt(draft.reprompt);
        window.set_edit_allow_cli_access(draft.allows_cli_access());
        window.set_edit_folder_index(folder_index);
        window.set_can_add_uri(matches!(draft.data, ItemData::Login { .. }));
        window.set_saving(false);
        window.set_detail_mode(2);
        manager.edit = Some(Edit {
            id,
            folder_id: draft.folder_id.clone(),
            base: draft,
            fields,
        });
        drop(guard);
        self.update_ticker();
    }

    /// The detail pane was not reloaded while the form was open; re-read it so it shows any
    /// change that arrived meanwhile (and the version a conflicting save was refused against).
    pub(super) fn cancel_edit(&self) {
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            manager.edit = None;
            manager.switch_to = None;
            manager.window.set_confirm_leave(false);
            manager.window.set_edit_fields(ModelRc::default());
            manager
                .window
                .set_detail_mode(i32::from(manager.detail.is_some()));
        }
        self.reload_detail();
        self.update_ticker();
    }

    pub(super) fn ask_before_leaving_edit(&self, target: ItemId) {
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            manager.switch_to = Some(target);
            manager.window.set_confirm_leave(true);
        }
    }

    fn take_switch_target(&self) -> Option<ItemId> {
        let mut guard = self.manager.borrow_mut();
        let manager = guard.as_mut()?;
        manager.window.set_confirm_leave(false);
        manager.switch_to.take()
    }

    fn leave_cancel(&self) {
        self.take_switch_target();
    }

    fn leave_discard(&self) {
        let target = self.take_switch_target();
        self.cancel_edit();
        if let Some(target) = target {
            self.select_item_row(&target);
        }
    }

    fn leave_save(&self) {
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_confirm_leave(false);
        }
        self.save_edit();
    }

    fn pick_edit_folder(&self, index: i32) {
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            let choice = usize::try_from(index)
                .ok()
                .and_then(|index| manager.folder_choices.get(index).cloned());
            if let (Some(edit), Some(folder_id)) = (manager.edit.as_mut(), choice) {
                edit.folder_id = folder_id;
            }
        }
    }

    /// After the folder list was rebuilt: point the picker at the stored folder again.
    pub(super) fn resync_edit_folder(&self) {
        if let Some(manager) = self.manager.borrow().as_ref()
            && let Some(edit) = manager.edit.as_ref()
        {
            manager.window.set_edit_folder_index(folder_index(
                &manager.folder_choices,
                edit.folder_id.as_ref(),
            ));
        }
    }

    /// A pasted private key in another format becomes OpenSSH with its public key and
    /// fingerprint. An unchanged key is left alone: re-encoding OpenSSH picks a new random
    /// check value, so every save would rewrite the item.
    fn normalize_ssh_key(&self, draft: ItemDraft) -> Result<ItemDraft, String> {
        let ItemData::SshKey { private_key, .. } = &draft.data else {
            return Ok(draft);
        };
        let unchanged = self
            .manager
            .borrow()
            .as_ref()
            .and_then(|manager| manager.edit.as_ref())
            .is_some_and(|edit| {
                matches!(&edit.base.data, ItemData::SshKey { private_key: base, .. } if base == private_key)
            });
        if unchanged || private_key.trim().is_empty() {
            return Ok(draft);
        }
        match self.hooks.ssh_keys.import(private_key) {
            Ok(Some((private_key, public_key, fingerprint))) => Ok(ItemDraft {
                data: ItemData::SshKey {
                    private_key,
                    public_key,
                    fingerprint,
                },
                ..draft
            }),
            Ok(None) => Ok(draft),
            Err(error) => Err(error.to_string()),
        }
    }

    /// The form's current values applied to its base draft.
    fn edited_draft(&self) -> Option<(Option<ItemId>, Result<ItemDraft, edit_form::EditError>)> {
        let guard = self.manager.borrow();
        let manager = guard.as_ref()?;
        let edit = manager.edit.as_ref()?;
        let window = &manager.window;
        let values: Vec<EditField> = edit.fields.iter().collect();
        let folder_id = edit.folder_id.clone();
        let missing_custom_name = values
            .iter()
            .any(|row| row.custom && row.custom_name.trim().is_empty());
        let draft = edit_form::apply(
            edit.base.clone(),
            values
                .iter()
                .map(|field| (field.key.as_str(), field.value.as_str())),
        )
        .and_then(|draft| {
            if missing_custom_name {
                Err(edit_form::EditError::CustomNameRequired)
            } else if matches!(draft.data, ItemData::Login { .. })
                && values
                    .iter()
                    .any(|row| row.custom && row.custom_name == CLI_ACCESS_FIELD)
            {
                Err(edit_form::EditError::ReservedCustomName)
            } else {
                Ok(draft)
            }
        })
        .map(|mut draft| {
            let mut fields: Vec<_> = values
                .iter()
                .filter(|row| row.custom)
                .map(|row| {
                    let old = row
                        .key
                        .strip_prefix("custom:")
                        .and_then(|n| n.parse::<usize>().ok())
                        .and_then(|i| edit.base.fields.get(i));
                    vk_vault::model::CustomField {
                        name: row.custom_name.to_string(),
                        value: zeroize::Zeroizing::new(row.value.to_string()),
                        hidden: row.custom_type == 1,
                        field_type: u8::try_from(row.custom_type).unwrap_or(0),
                        source_index: old.and_then(|field| field.source_index),
                        withheld: old.is_some_and(|field| field.withheld),
                    }
                })
                .collect();
            if matches!(draft.data, ItemData::Login { .. }) {
                fields.extend(
                    draft
                        .fields
                        .into_iter()
                        .filter(|field| field.name == CLI_ACCESS_FIELD),
                );
            }
            draft.fields = fields;
            draft.set_allow_cli_access(window.get_edit_allow_cli_access());
            ItemDraft {
                favorite: window.get_edit_favorite(),
                reprompt: window.get_edit_reprompt(),
                folder_id,
                ..draft
            }
        });
        Some((edit.id.clone(), draft))
    }

    fn save_edit(&self) {
        let Some((id, draft)) = self.edited_draft() else {
            return;
        };
        let draft = match draft
            .map_err(|error| error.to_string())
            .and_then(|draft| self.normalize_ssh_key(draft))
        {
            Ok(draft) => draft,
            Err(error) => {
                if let Some(manager) = self.manager.borrow().as_ref() {
                    manager.window.set_edit_error(error.into());
                }
                return;
            }
        };
        if self.vault.is_offline() {
            if let Some(manager) = self.manager.borrow().as_ref() {
                manager
                    .window
                    .set_edit_error("You're offline: saving needs the server".into());
            }
            return;
        }
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_saving(true);
        }
        self.save_item(id, draft, Self::edit_saved);
    }

    fn edit_saved(&self, result: &vk_vault::Result<ItemId>) {
        let mut guard = self.manager.borrow_mut();
        let Some(manager) = guard.as_mut() else {
            return;
        };
        manager.window.set_saving(false);
        let mut switch_to = None;
        match result {
            Ok(id) => {
                manager.edit = None;
                manager.selected = Some(id.clone());
                switch_to = manager.switch_to.take();
                manager.window.set_edit_fields(ModelRc::default());
                // `on_vault_changed` runs next and reloads the detail in view mode.
                manager.window.set_detail_mode(1);
            }
            // The form stays open with the user's values so nothing typed is lost; saving it
            // again is refused the same way, and Cancel shows the version from elsewhere.
            Err(vk_vault::Error::Conflict) => {
                manager.switch_to = None;
                manager.window.set_edit_error(
                    format!(
                        "{} · Cancel to load the latest version",
                        vk_vault::CONFLICT_MESSAGE
                    )
                    .into(),
                );
            }
            Err(error) => {
                manager.switch_to = None;
                manager
                    .window
                    .set_edit_error(crate::viewmodel::error_text(error).into());
            }
        }
        drop(guard);
        if let Some(target) = switch_to {
            self.select_item_row(&target);
        }
    }

    fn select_item_row(&self, id: &ItemId) {
        let row = self
            .manager
            .borrow()
            .as_ref()
            .and_then(|manager| manager.rows.position(id));
        if let Some(row) = row {
            self.select_row(i32::try_from(row).unwrap_or(i32::MAX));
        }
    }

    /// Editing an SSH private key refreshes its public key and fingerprint as soon as the text
    /// is a key the tool can read; while it isn't (half pasted, wrong passphrase-less format)
    /// they keep their last values. The private key text itself stays as typed until save.
    fn edit_field_edited(&self, index: i32, text: &str) {
        let is_private_key = {
            let guard = self.manager.borrow();
            guard
                .as_ref()
                .and_then(|manager| manager.edit.as_ref())
                .and_then(|edit| {
                    usize::try_from(index)
                        .ok()
                        .and_then(|i| edit.fields.row_data(i))
                })
                .is_some_and(|field| field.key == "private_key")
        };
        if !is_private_key || text.trim().is_empty() {
            return;
        }
        let Ok(Some((_, public_key, fingerprint))) = self.hooks.ssh_keys.import(text) else {
            return;
        };
        let guard = self.manager.borrow();
        let Some(edit) = guard.as_ref().and_then(|manager| manager.edit.as_ref()) else {
            return;
        };
        for row in 0..edit.fields.row_count() {
            if let Some(mut field) = edit.fields.row_data(row) {
                let value = match field.key.as_str() {
                    "public_key" => &public_key,
                    "fingerprint" => &fingerprint,
                    _ => continue,
                };
                field.value = value.as_str().into();
                edit.fields.set_row_data(row, field);
            }
        }
    }

    /// The field's generate button: the generator slide-over, whose "Use this password" fills
    /// this field and returns to the form (its copy button works as everywhere).
    fn open_generator_for(&self, index: i32) {
        if let Some(manager) = self.manager.borrow().as_ref() {
            let state =
                slint::ComponentHandle::global::<crate::ui::GeneratorState>(&manager.window);
            state.set_use_target(index);
            state.set_can_use(true);
        }
        self.open_detail_generator();
    }

    /// Fills edit-form row `target` from the generator slide-over.
    pub(super) fn use_generated(&self, target: i32, value: &str) -> bool {
        let guard = self.manager.borrow();
        let Some(edit) = guard.as_ref().and_then(|manager| manager.edit.as_ref()) else {
            return false;
        };
        let Some(index) = usize::try_from(target)
            .ok()
            .filter(|index| *index < edit.fields.row_count())
        else {
            return false;
        };
        if let Some(mut field) = edit.fields.row_data(index) {
            field.value = value.into();
            edit.fields.set_row_data(index, field);
        }
        true
    }

    fn add_custom_field(&self, kind: i32) {
        if !(0..=2).contains(&kind) {
            return;
        }
        let guard = self.manager.borrow();
        if let Some(edit) = guard.as_ref().and_then(|manager| manager.edit.as_ref()) {
            edit.fields.push(edit_form::custom_field(kind));
        }
    }

    fn remove_custom_field(&self, index: i32) {
        let guard = self.manager.borrow();
        if let Some(edit) = guard.as_ref().and_then(|manager| manager.edit.as_ref())
            && let Ok(index) = usize::try_from(index)
            && let Some(row) = edit.fields.row_data(index)
            && row.custom
            && !row.withheld
        {
            edit.fields.remove(index);
        }
    }

    fn add_uri_field(&self) {
        let guard = self.manager.borrow();
        let Some(edit) = guard.as_ref().and_then(|manager| manager.edit.as_ref()) else {
            return;
        };
        let uris = edit
            .fields
            .iter()
            .filter(|field| field.key.starts_with("uri:"))
            .count();
        let last_uri = edit
            .fields
            .iter()
            .enumerate()
            .filter(|(_, field)| field.key.starts_with("uri:"))
            .last();
        let after_last = last_uri.map_or(edit.fields.row_count(), |(index, _)| index + 1);
        edit.fields.insert(after_last, edit_form::uri_field(uris));
    }
}
