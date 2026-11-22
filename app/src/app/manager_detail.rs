//! Manager detail pane: fields, reveal and copy, favorite, folder move, delete, attachments.
//! The collections panel lives in [`super::manager_assign`].

use std::{rc::Rc, sync::Arc};

use slint::{Model, ModelRc, VecModel};
use vk_vault::{
    VaultService,
    model::{AttachmentView, ItemDraft, ItemId, ItemSummary, OrganizationView},
};

use super::{App, handler, manager_assign::render_assign};
use crate::{
    assign::{self, AssignForm},
    detail::{self, FieldKind, FieldSpec},
    ui::{AttachmentRow, DetailHeader, ManagerWindow},
    viewmodel::{self, group_code, human_size, kind_code, kind_label},
};

pub(super) struct Detail {
    pub(super) summary: ItemSummary,
    pub(super) draft: ItemDraft,
    specs: Vec<FieldSpec>,
    revealed: Vec<bool>,
    fields_model: Rc<VecModel<crate::ui::DetailField>>,
    pub(super) attachments: Vec<AttachmentView>,
    has_totp: bool,
    totp_expires: i32,
    /// The open collections panel; kept while background syncs reload the same item.
    pub(super) assign: Option<AssignForm>,
}

impl Detail {
    pub(super) fn strings(&self) -> Vec<String> {
        let mut strings = vec![
            self.summary.name.to_string(),
            self.summary.subtitle.to_string(),
        ];
        strings.extend(
            self.fields_model
                .iter()
                .map(|field| field.value.to_string()),
        );
        strings.extend(
            self.attachments
                .iter()
                .map(|attachment| attachment.file_name.to_string()),
        );
        strings
    }
}

/// What a reload of the shown item keeps from the pane as it was.
struct Kept {
    revealed: Vec<bool>,
    confirm_delete: bool,
    attachment_confirm: bool,
}

impl Kept {
    /// `cleared`: the item needs no master password now, or it was confirmed. A field stays
    /// revealed only where the same field is still at the same place.
    fn of(
        previous: &Detail,
        summary: &ItemSummary,
        specs: &[FieldSpec],
        attachments: &[AttachmentView],
        cleared: bool,
    ) -> Self {
        let may_reveal = cleared && previous.summary.reprompt == summary.reprompt;
        let revealed = specs
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                may_reveal
                    && previous.revealed.get(index).copied().unwrap_or(false)
                    && previous
                        .specs
                        .get(index)
                        .is_some_and(|old| old.label == spec.label && old.secret == spec.secret)
            })
            .collect();
        let same_attachments = previous
            .attachments
            .iter()
            .map(|attachment| &attachment.id)
            .eq(attachments.iter().map(|attachment| &attachment.id));
        Self {
            revealed,
            confirm_delete: previous.summary.deleted == summary.deleted,
            attachment_confirm: same_attachments,
        }
    }
}

fn fields_model(
    draft: &ItemDraft,
    specs: &[FieldSpec],
    revealed: &[bool],
) -> Rc<VecModel<crate::ui::DetailField>> {
    Rc::new(VecModel::from(
        specs
            .iter()
            .zip(revealed)
            .map(|(spec, shown)| spec.to_ui(revealed_value(draft, spec, *shown)))
            .collect::<Vec<_>>(),
    ))
}

/// Clears the confirmations and busy state of a newly shown item; a reload keeps those still
/// about the same thing, and never ends the busy state of a transfer still running.
fn reset_pane_state(window: &ManagerWindow, kept: Option<&Kept>) {
    if !kept.is_some_and(|kept| kept.confirm_delete) {
        window.set_confirm_delete(false);
    }
    if !kept.is_some_and(|kept| kept.attachment_confirm) {
        window.set_attachment_confirm(-1);
    }
    if kept.is_none() {
        window.set_attach_busy(false);
    }
}

fn revealed_value<'a>(draft: &'a ItemDraft, spec: &FieldSpec, shown: bool) -> Option<&'a str> {
    spec.secret
        .filter(|_| shown)
        .and_then(|secret| detail::secret_value(draft, secret))
}

/// Where a detail field's copy comes from.
enum Source {
    Vault(ItemSummary, vk_vault::model::CopyField),
    Plain(String, zeroize::Zeroizing<String>),
}

fn attachment_rows(attachments: &[AttachmentView]) -> Vec<AttachmentRow> {
    attachments
        .iter()
        .map(|attachment| AttachmentRow {
            name: attachment.file_name.as_ref().into(),
            size: human_size(attachment.size_bytes).into(),
        })
        .collect()
}

/// Seconds before a failed TOTP computation is tried again.
const TOTP_RETRY_SECS: i32 = 3;

/// The item has no usable TOTP (none any more, an unusable seed), as opposed to a failure worth
/// retrying.
fn totp_gone(error: &vk_vault::Error) -> bool {
    matches!(
        error,
        vk_vault::Error::NoSuchField
            | vk_vault::Error::NotFound
            | vk_vault::Error::Gen(_)
            | vk_vault::Error::Crypto(_)
    )
}

fn organization_name(
    organizations: &[OrganizationView],
    summary: &ItemSummary,
) -> Option<Arc<str>> {
    let organization = summary.organization_id.as_ref()?;
    organizations
        .iter()
        .find(|candidate| &candidate.id == organization)
        .map(|org| Arc::clone(&org.name))
}

fn to_i32(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

impl<S: VaultService> App<S> {
    pub(super) fn bind_manager_detail(&self, window: &ManagerWindow) {
        window.on_copy_field(handler!(self, false, |app, index| app.copy_detail_field(index)));
        window.on_reveal_field(handler!(self, |app, index| app.toggle_reveal(index)));
        window.on_open_uri(handler!(self, |app, index| app.open_detail_uri(index)));
        window.on_toggle_favorite(handler!(self, |app| app.toggle_favorite()));
        window.on_edit(handler!(self, |app| app.start_edit()));
        window.on_delete_confirmed(handler!(self, |app| app.delete_selected()));
        window.on_restore(handler!(self, |app| app.restore_selected()));
        window.on_move_to_folder(handler!(self, |app, index| app.move_to_folder(index)));
        window.on_attachment_save(handler!(self, |app, index| app.save_attachment(index)));
        window.on_attachment_delete(handler!(self, |app, index| app.delete_attachment(index)));
        window.on_attach_file(handler!(self, |app| app.attach_file()));
    }

    fn organizations_cached(&self) -> Vec<OrganizationView> {
        self.vault.organizations().unwrap_or_default()
    }

    /// Decrypts the item (the draft is kept only while the pane shows it) and fills the pane.
    pub(super) fn show_detail(&self, id: &ItemId) {
        self.fill_detail(id, false);
    }

    /// `reload`: the same item re-read after a vault change, which keeps what the user has open
    /// on it (revealed fields, a running upload, a delete confirmation).
    fn fill_detail(&self, id: &ItemId, reload: bool) {
        let draft = match self.vault.draft(id) {
            Ok(draft) => draft,
            Err(error) => {
                self.toast(&viewmodel::error_text(&error), true);
                return;
            }
        };
        let attachments = self.vault.attachments(id).unwrap_or_default();
        let organizations = self.organizations_cached();
        let collections = self.vault.collections().unwrap_or_default();
        let mut guard = self.manager.borrow_mut();
        let Some(manager) = guard.as_mut() else {
            return;
        };
        let Some(summary) = manager
            .rows
            .position(id)
            .and_then(|row| manager.rows.item(row))
        else {
            return;
        };
        let folder_name = summary.folder_id.as_ref().and_then(|folder| {
            manager
                .folders
                .iter()
                .find(|candidate| &candidate.id == folder)
                .map(|folder| Arc::clone(&folder.name))
        });
        let organization_name = organization_name(&organizations, &summary);
        let specs = detail::fields(&draft);
        let previous = manager
            .detail
            .take()
            .filter(|previous| &previous.summary.id == id);
        let kept = previous.as_ref().filter(|_| reload).map(|previous| {
            Kept::of(
                previous,
                &summary,
                &specs,
                &attachments,
                self.reprompt_cleared(&summary),
            )
        });
        let revealed = kept
            .as_ref()
            .map_or_else(|| vec![false; specs.len()], |kept| kept.revealed.clone());
        let fields_model = fields_model(&draft, &specs, &revealed);
        let window = &manager.window;
        window.set_detail_header(DetailHeader {
            name: summary.name.as_ref().into(),
            kind: kind_code(summary.kind),
            kind_label: kind_label(summary.kind).into(),
            location: detail::location(folder_name.as_deref(), organization_name.as_deref()).into(),
            favorite: summary.favorite,
            deleted: summary.deleted,
            editable: summary.editable,
            collections: assign::collection_names(&draft.collection_ids, &collections).into(),
            can_assign: assign::available(draft.organization_id.as_ref(), &organizations),
        });
        window.set_detail_fields(ModelRc::from(Rc::clone(&fields_model)));
        window.set_attachments(ModelRc::new(VecModel::from(attachment_rows(&attachments))));
        let folder_index = manager
            .folder_choices
            .iter()
            .position(|choice| choice == &summary.folder_id)
            .map_or(0, to_i32);
        window.set_detail_folder_index(folder_index);
        reset_pane_state(window, kept.as_ref());
        let pending_here = self
            .reprompt_pending
            .borrow()
            .as_ref()
            .is_some_and(|(pending, _)| pending == id);
        window.set_reprompt_visible(pending_here);
        window.set_detail_mode(1);
        let has_totp = specs.iter().any(|spec| spec.kind == FieldKind::Totp);
        let assign = previous
            .filter(|_| !summary.deleted)
            .and_then(|previous| previous.assign)
            .filter(|_| summary.editable);
        render_assign(window, assign.as_ref());
        manager.selected = Some(id.clone());
        manager.edit = None;
        manager.switch_to = None;
        manager.window.set_confirm_leave(false);
        manager.window.set_edit_fields(ModelRc::default());
        manager.detail = Some(Detail {
            revealed,
            summary,
            draft,
            specs,
            fields_model,
            attachments,
            has_totp,
            totp_expires: 0,
            assign,
        });
        drop(guard);
        self.refresh_detail_totp();
        self.update_ticker();
    }

    /// After a vault change: re-read the shown item, or clear the pane if it is gone.
    pub(super) fn reload_detail(&self) {
        let (id, viewing) = {
            let guard = self.manager.borrow();
            let Some(manager) = guard.as_ref() else {
                return;
            };
            (
                manager.selected.clone(),
                manager.window.get_detail_mode() == 1,
            )
        };
        let Some(id) = id else {
            return;
        };
        let listed = self
            .manager
            .borrow()
            .as_ref()
            .is_some_and(|manager| manager.rows.position(&id).is_some());
        if listed && viewing {
            self.fill_detail(&id, true);
        } else if !listed {
            self.clear_detail();
        }
    }

    pub(super) fn clear_detail(&self) {
        if let Some(manager) = self.manager.borrow_mut().as_mut() {
            manager.selected = None;
            manager.detail = None;
            if manager.edit.is_none() {
                manager.window.set_detail_mode(0);
            }
            manager.window.set_detail_fields(ModelRc::default());
            manager.window.set_attachments(ModelRc::default());
            manager.window.set_selected(-1);
        }
        self.update_ticker();
    }

    /// Recomputes the detail pane's TOTP code when it is missing or expired.
    pub(super) fn refresh_detail_totp(&self) {
        let now = self.ui_now();
        let summary = self.manager.borrow().as_ref().and_then(|manager| {
            manager
                .detail
                .as_ref()
                .filter(|detail| detail.has_totp && detail.totp_expires <= now)
                .map(|detail| detail.summary.clone())
        });
        let Some(summary) = summary else {
            return;
        };
        if !self.reprompt_cleared(&summary) {
            if let Some(manager) = self.manager.borrow().as_ref() {
                manager
                    .window
                    .set_detail_totp_code(detail::TOTP_MASK.into());
            }
            return;
        }
        let id = summary.id;
        let code = self.vault.totp(&id, self.hooks.clock.unix_now());
        if let Some(manager) = self.manager.borrow_mut().as_mut()
            && let Some(detail) = manager.detail.as_mut()
        {
            match code {
                Ok(code) => {
                    let remaining = i32::try_from(code.remaining).unwrap_or(30);
                    detail.totp_expires = now + remaining;
                    manager
                        .window
                        .set_detail_totp_code(group_code(&code.code).into());
                    manager.window.set_detail_totp_expires(detail.totp_expires);
                    manager
                        .window
                        .set_detail_totp_period(i32::try_from(code.period).unwrap_or(30));
                }
                Err(error) if totp_gone(&error) => {
                    detail.has_totp = false;
                    tracing::warn!(%error, "TOTP unavailable");
                }
                Err(error) => {
                    // A transient failure (an IPC timeout) must not hide the code for good, nor
                    // leave an expired one on screen.
                    detail.totp_expires = now + TOTP_RETRY_SECS;
                    manager
                        .window
                        .set_detail_totp_code(detail::TOTP_MASK.into());
                    tracing::warn!(%error, "TOTP not computed; retrying");
                }
            }
        }
    }

    pub(super) fn detail_has_totp(&self) -> bool {
        self.manager.borrow().as_ref().is_some_and(|manager| {
            manager.window.get_detail_mode() == 1
                && manager
                    .detail
                    .as_ref()
                    .is_some_and(|detail| detail.has_totp)
        })
    }

    fn detail_summary_needing_reprompt(&self) -> Option<ItemSummary> {
        let summary = self
            .manager
            .borrow()
            .as_ref()
            .and_then(|manager| manager.detail.as_ref().map(|detail| detail.summary.clone()))?;
        (!self.reprompt_cleared(&summary)).then_some(summary)
    }

    fn detail_spec_is_draft_secret(&self, index: i32) -> bool {
        self.manager.borrow().as_ref().is_some_and(|manager| {
            manager.detail.as_ref().is_some_and(|detail| {
                usize::try_from(index)
                    .ok()
                    .and_then(|index| detail.specs.get(index))
                    .is_some_and(|spec| spec.copy.is_none() && spec.secret.is_some())
            })
        })
    }

    pub(super) fn copy_detail_field(&self, index: i32) -> bool {
        if self.detail_spec_is_draft_secret(index)
            && let Some(summary) = self.detail_summary_needing_reprompt()
        {
            self.request_reprompt(&summary, super::reprompt::Pending::CopyDetail(index));
            return false;
        }
        let source = {
            let guard = self.manager.borrow();
            let Some(detail) = guard.as_ref().and_then(|manager| manager.detail.as_ref()) else {
                return false;
            };
            let Some(spec) = usize::try_from(index)
                .ok()
                .and_then(|index| detail.specs.get(index))
            else {
                return false;
            };
            match (spec.copy, spec.secret) {
                (Some(field), _) => Source::Vault(detail.summary.clone(), field),
                (None, Some(secret)) => Source::Plain(
                    spec.label.to_lowercase(),
                    zeroize::Zeroizing::new(
                        detail::secret_value(&detail.draft, secret)
                            .unwrap_or_default()
                            .to_owned(),
                    ),
                ),
                (None, None) => Source::Plain(
                    spec.label.to_lowercase(),
                    zeroize::Zeroizing::new(spec.value.clone()),
                ),
            }
        };
        match source {
            Source::Vault(summary, field) => self.copy_item_field(&summary, field),
            Source::Plain(label, value) => self.copy_text(&label, &value),
        }
    }

    pub(super) fn toggle_reveal(&self, index: i32) {
        if let Some(summary) = self.detail_summary_needing_reprompt() {
            self.request_reprompt(&summary, super::reprompt::Pending::Reveal(index));
            return;
        }
        let mut guard = self.manager.borrow_mut();
        let Some(detail) = guard.as_mut().and_then(|manager| manager.detail.as_mut()) else {
            return;
        };
        let Some(index) = usize::try_from(index)
            .ok()
            .filter(|index| *index < detail.specs.len())
        else {
            return;
        };
        let spec = &detail.specs[index];
        let Some(secret) = spec.secret else {
            return;
        };
        let reveal = !detail.revealed[index];
        detail.revealed[index] = reveal;
        let value = reveal
            .then(|| detail::secret_value(&detail.draft, secret))
            .flatten();
        detail.fields_model.set_row_data(index, spec.to_ui(value));
    }

    fn open_detail_uri(&self, index: i32) {
        let uri = self.manager.borrow().as_ref().and_then(|manager| {
            let detail = manager.detail.as_ref()?;
            let spec = detail.specs.get(usize::try_from(index).ok()?)?;
            (spec.kind == FieldKind::Uri).then(|| spec.value.clone())
        });
        if let Some(uri) = uri
            && let Err(error) = self.hooks.opener.open(&uri)
        {
            self.toast(&error.to_string(), true);
        }
    }

    fn selected_draft(&self) -> Option<(ItemId, ItemDraft)> {
        self.manager.borrow().as_ref().and_then(|manager| {
            manager
                .detail
                .as_ref()
                .map(|detail| (detail.summary.id.clone(), detail.draft.clone()))
        })
    }

    pub(super) fn require_online(&self) -> bool {
        if self.vault.is_offline() {
            self.toast("You're offline: changes need the server", true);
            return false;
        }
        true
    }

    pub(super) fn toggle_favorite(&self) {
        let Some((id, draft)) = self.selected_draft() else {
            return;
        };
        if !self.require_online() {
            return;
        }
        let draft = ItemDraft {
            favorite: !draft.favorite,
            ..draft
        };
        self.save_item(Some(id), draft, Self::toast_on_error);
    }

    fn toast_on_error(&self, result: &vk_vault::Result<ItemId>) {
        if let Err(error) = result {
            self.toast(&viewmodel::error_text(error), true);
        }
    }

    fn move_to_folder(&self, index: i32) {
        let folder = self.manager.borrow().as_ref().and_then(|manager| {
            usize::try_from(index)
                .ok()
                .and_then(|index| manager.folder_choices.get(index).cloned())
        });
        let (Some(folder), Some((id, draft))) = (folder, self.selected_draft()) else {
            return;
        };
        if draft.folder_id == folder || !self.require_online() {
            return;
        }
        self.save_item(
            Some(id),
            ItemDraft {
                folder_id: folder,
                ..draft
            },
            Self::toast_on_error,
        );
    }

    /// Saves, hands the result to `done`, then refreshes every view.
    pub(super) fn save_item(
        &self,
        id: Option<ItemId>,
        draft: ItemDraft,
        done: impl FnOnce(&Self, &vk_vault::Result<ItemId>) + 'static,
    ) {
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.save(id, draft).await },
            handler!(self, |app, result| {
                done(&app, &result);
                app.on_vault_changed();
            }),
        );
    }

    fn delete_selected(&self) {
        let Some(summary) = self
            .manager
            .borrow()
            .as_ref()
            .and_then(|manager| manager.detail.as_ref().map(|detail| detail.summary.clone()))
        else {
            return;
        };
        if !self.require_online() {
            return;
        }
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move {
                if summary.deleted {
                    vault.delete_permanently(&summary.id).await
                } else {
                    vault.trash(&summary.id).await
                }
            },
            handler!(self, |app, result| app.after_write(result)),
        );
    }

    fn restore_selected(&self) {
        let Some((id, _)) = self.selected_draft() else {
            return;
        };
        if !self.require_online() {
            return;
        }
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.restore(&id).await },
            handler!(self, |app, result| app.after_write(result)),
        );
    }

    pub(super) fn after_write(&self, result: vk_vault::Result<()>) {
        if let Err(error) = result {
            self.toast(&viewmodel::error_text(&error), true);
        }
        self.on_vault_changed();
    }

    fn selected_attachment(&self, index: i32) -> Option<(ItemId, AttachmentView)> {
        self.manager.borrow().as_ref().and_then(|manager| {
            let detail = manager.detail.as_ref()?;
            let attachment = detail.attachments.get(usize::try_from(index).ok()?)?;
            Some((detail.summary.id.clone(), attachment.clone()))
        })
    }

    fn set_attach_busy(&self, status: Option<String>) {
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_attach_busy(status.is_some());
            manager
                .window
                .set_attach_status(status.unwrap_or_default().into());
        }
    }

    fn attachments_online(&self) -> bool {
        if self.vault.is_offline() {
            self.toast("Attachments need a server connection", true);
            return false;
        }
        true
    }

    fn save_attachment(&self, index: i32) {
        let Some((id, attachment)) = self.selected_attachment(index) else {
            return;
        };
        if !self.attachments_online() {
            return;
        }
        let name = attachment.file_name.clone();
        self.pick_file(
            move |files| files.save_file(&name),
            move |app, dest| {
                let still_open = app
                    .manager
                    .borrow()
                    .as_ref()
                    .and_then(|manager| manager.detail.as_ref())
                    .is_some_and(|detail| detail.summary.id == id);
                if !still_open {
                    return;
                }
                app.set_attach_busy(Some(format!("Saving {}…", attachment.file_name)));
                let vault = Arc::clone(&app.vault);
                app.exec.spawn(
                    async move { vault.download_attachment(&id, &attachment.id, dest).await },
                    handler!(app, |app, result| app.attachment_done(result)),
                );
            },
        );
    }

    fn delete_attachment(&self, index: i32) {
        let Some((id, attachment)) = self.selected_attachment(index) else {
            return;
        };
        if !self.attachments_online() {
            return;
        }
        self.set_attach_busy(Some(format!("Deleting {}…", attachment.file_name)));
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.delete_attachment(&id, &attachment.id).await },
            handler!(self, |app, result| app.attachment_done(result)),
        );
    }

    fn attach_file(&self) {
        let Some((id, _)) = self.selected_draft() else {
            return;
        };
        if !self.attachments_online() {
            return;
        }
        self.pick_file(
            |files| files.open_file(),
            move |app, source| {
                if !app.selected_draft().is_some_and(|(open, _)| open == id) {
                    return;
                }
                let name = source
                    .file_name()
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
                app.set_attach_busy(Some(format!("Uploading {name}…")));
                let vault = Arc::clone(&app.vault);
                app.exec.spawn(
                    async move { vault.upload_attachment(&id, source).await.map(drop) },
                    handler!(app, |app, result| app.attachment_done(result)),
                );
            },
        );
    }

    fn attachment_done(&self, result: vk_vault::Result<()>) {
        self.set_attach_busy(None);
        if let Err(error) = result {
            self.toast(&viewmodel::file_error_text(&error), true);
            return;
        }
        self.on_vault_changed();
    }

    pub(super) fn open_detail_generator(&self) {
        let has_result = !self.generator.borrow().current().is_empty();
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_detail_mode(3);
        }
        if !has_result {
            self.regenerate();
        }
    }

    pub(super) fn close_detail_generator(&self) {
        if let Some(manager) = self.manager.borrow().as_ref() {
            let mode = match (manager.edit.is_some(), manager.detail.is_some()) {
                (true, _) => 2,
                (false, true) => 1,
                (false, false) => 0,
            };
            manager.window.set_detail_mode(mode);
            // Only the edit form's generate button offers "Use this password".
            let state =
                slint::ComponentHandle::global::<crate::ui::GeneratorState>(&manager.window);
            state.set_can_use(false);
            state.set_use_target(-1);
        }
        self.flush_generator_prefs();
        // The ticker stopped while the generator covered the code.
        self.refresh_totp();
    }
}

#[cfg(test)]
mod tests {
    use super::totp_gone;

    #[test]
    fn only_a_missing_code_hides_the_totp_for_good() {
        assert!(totp_gone(&vk_vault::Error::NoSuchField));
        assert!(totp_gone(&vk_vault::Error::NotFound));
        assert!(!totp_gone(&vk_vault::Error::Offline));
        assert!(!totp_gone(&vk_vault::Error::Locked));
        assert!(!totp_gone(&vk_vault::Error::Io(std::io::Error::other(
            "the daemon did not answer in time"
        ))));
    }
}
