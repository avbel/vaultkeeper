//! Manager edit form: start from the detail draft or an empty one, save through the vault.

use std::rc::Rc;

use bwl_vault::{
    VaultService,
    model::{ItemData, ItemDraft, ItemId, ItemKind},
};
use slint::{Model, ModelRc, SharedString, VecModel};

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
}

impl<S: VaultService> App<S> {
    pub(super) fn bind_manager_edit(&self, window: &ManagerWindow) {
        window.on_new_item(handler!(self, |app, kind| app.new_item(kind)));
        window.on_edit_generate(handler!(self, |app, index| app.generate_into(index)));
        window.on_edit_add_uri(handler!(self, |app| app.add_uri_field()));
        window.on_edit_save(handler!(self, |app| app.save_edit()));
        window.on_edit_cancel(handler!(self, |app| app.cancel_edit()));
    }

    pub(super) fn start_edit(&self) {
        let start = self.manager.borrow().as_ref().and_then(|manager| {
            manager
                .detail
                .as_ref()
                .filter(|detail| detail.summary.editable && !detail.summary.deleted)
                .map(|detail| {
                    (
                        detail.summary.id.clone(),
                        detail.draft.clone(),
                        detail.summary.kind,
                    )
                })
        });
        if let Some((id, draft, kind)) = start {
            self.open_edit(
                Some(id),
                draft,
                &format!("Edit {}", kind_label(kind).to_lowercase()),
            );
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
        let folder_index = manager
            .folder_choices
            .iter()
            .position(|choice| choice == &draft.folder_id)
            .and_then(|index| i32::try_from(index).ok())
            .unwrap_or(0);
        let window = &manager.window;
        window.set_edit_title(title.into());
        window.set_edit_fields(ModelRc::from(Rc::clone(&fields)));
        window.set_edit_error(SharedString::new());
        window.set_edit_favorite(draft.favorite);
        window.set_edit_reprompt(draft.reprompt);
        window.set_edit_folder_index(folder_index);
        window.set_can_add_uri(matches!(draft.data, ItemData::Login { .. }));
        window.set_saving(false);
        window.set_detail_mode(2);
        manager.edit = Some(Edit {
            id,
            base: draft,
            fields,
        });
        drop(guard);
        self.update_ticker();
    }

    pub(super) fn cancel_edit(&self) {
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            manager.edit = None;
            manager.window.set_edit_fields(ModelRc::default());
            manager
                .window
                .set_detail_mode(i32::from(manager.detail.is_some()));
        }
        self.update_ticker();
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
        let folder_id = usize::try_from(window.get_edit_folder_index())
            .ok()
            .and_then(|index| manager.folder_choices.get(index).cloned())
            .unwrap_or_else(|| edit.base.folder_id.clone());
        let draft = edit_form::apply(
            edit.base.clone(),
            values
                .iter()
                .map(|field| (field.key.as_str(), field.value.as_str())),
        )
        .map(|draft| ItemDraft {
            favorite: window.get_edit_favorite(),
            reprompt: window.get_edit_reprompt(),
            folder_id,
            ..draft
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

    fn edit_saved(&self, result: &bwl_vault::Result<ItemId>) {
        let mut guard = self.manager.borrow_mut();
        let Some(manager) = guard.as_mut() else {
            return;
        };
        manager.window.set_saving(false);
        match result {
            Ok(id) => {
                manager.edit = None;
                manager.selected = Some(id.clone());
                manager.window.set_edit_fields(ModelRc::default());
                // `on_vault_changed` runs next and reloads the detail in view mode.
                manager.window.set_detail_mode(1);
            }
            Err(error) => manager
                .window
                .set_edit_error(crate::viewmodel::error_text(error).into()),
        }
    }

    fn generate_into(&self, index: i32) {
        let value = match self.generate_password() {
            Ok(value) => value,
            Err(error) => {
                self.toast(&error, true);
                return;
            }
        };
        let guard = self.manager.borrow();
        let Some(edit) = guard.as_ref().and_then(|manager| manager.edit.as_ref()) else {
            return;
        };
        let Some(index) = usize::try_from(index).ok() else {
            return;
        };
        if let Some(mut field) = edit.fields.row_data(index) {
            field.value = value.as_str().into();
            edit.fields.set_row_data(index, field);
        }
    }

    /// Fills the edit form's password field from the generator slide-over.
    pub(super) fn use_generated(&self, value: &str) -> bool {
        let guard = self.manager.borrow();
        let Some(edit) = guard.as_ref().and_then(|manager| manager.edit.as_ref()) else {
            return false;
        };
        let Some(index) = edit.fields.iter().position(|field| field.key == "password") else {
            return false;
        };
        if let Some(mut field) = edit.fields.row_data(index) {
            field.value = value.into();
            edit.fields.set_row_data(index, field);
        }
        true
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
