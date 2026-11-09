//! Manager detail pane: the "Collections" panel that moves an item into an organization or
//! changes its collections there (see [`crate::assign`]).

use std::{rc::Rc, sync::Arc};

use bwl_vault::VaultService;
use slint::{ModelRc, SharedString, VecModel};

use super::{App, handler};
use crate::{
    assign::AssignForm,
    ui::{AssignChoice, ManagerWindow},
    viewmodel,
};

fn to_i32(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// Pushes the form to the window; `None` hides the panel.
pub(super) fn render_assign(window: &ManagerWindow, form: Option<&AssignForm>) {
    let Some(form) = form else {
        window.set_assign_visible(false);
        window.set_assign_busy(false);
        window.set_assign_choices(ModelRc::default());
        return;
    };
    let labels: Vec<SharedString> = form
        .organization_labels()
        .iter()
        .map(|label| label.as_ref().into())
        .collect();
    let choices: Vec<AssignChoice> = form
        .choices()
        .iter()
        .map(|choice| AssignChoice {
            name: choice.name.as_ref().into(),
            checked: choice.checked,
            enabled: choice.enabled,
        })
        .collect();
    window.set_assign_org_options(ModelRc::from(Rc::new(VecModel::from(labels))));
    window.set_assign_org_index(to_i32(form.organization_index()));
    window.set_assign_org_fixed(form.fixed());
    window.set_assign_choices(ModelRc::from(Rc::new(VecModel::from(choices))));
    window.set_assign_warning(form.warning().into());
    window.set_assign_can_submit(form.can_submit());
    window.set_assign_visible(true);
}

impl<S: VaultService> App<S> {
    pub(super) fn bind_manager_assign(&self, window: &ManagerWindow) {
        window.on_assign_open(handler!(self, |app| app.open_assign()));
        window.on_assign_org_selected(handler!(self, |app, index| {
            if let Ok(index) = usize::try_from(index) {
                app.update_assign(|form| form.pick_organization(index));
            }
        }));
        window.on_assign_toggled(handler!(self, |app, index, checked| {
            if let Ok(index) = usize::try_from(index) {
                app.update_assign(|form| form.toggle(index, checked));
            }
        }));
        window.on_assign_submit(handler!(self, |app| app.submit_assign()));
        window.on_assign_cancel(handler!(self, |app| app.close_assign()));
    }

    fn open_assign(&self) {
        if !self.require_online() {
            return;
        }
        let organizations = self.vault.organizations().unwrap_or_default();
        let collections = self.vault.collections().unwrap_or_default();
        let mut guard = self.manager.borrow_mut();
        let Some(manager) = guard.as_mut() else {
            return;
        };
        let Some(detail) = manager.detail.as_mut() else {
            return;
        };
        detail.assign = AssignForm::open(
            detail.draft.organization_id.as_ref(),
            &detail.draft.collection_ids,
            &organizations,
            &collections,
        );
        render_assign(&manager.window, detail.assign.as_ref());
    }

    fn update_assign(&self, change: impl FnOnce(&mut AssignForm)) {
        let mut guard = self.manager.borrow_mut();
        let Some(manager) = guard.as_mut() else {
            return;
        };
        if let Some(form) = manager
            .detail
            .as_mut()
            .and_then(|detail| detail.assign.as_mut())
        {
            change(form);
            render_assign(&manager.window, Some(form));
        }
    }

    fn close_assign(&self) {
        let mut guard = self.manager.borrow_mut();
        let Some(manager) = guard.as_mut() else {
            return;
        };
        if let Some(detail) = manager.detail.as_mut() {
            detail.assign = None;
        }
        render_assign(&manager.window, None);
    }

    fn submit_assign(&self) {
        let request = self.manager.borrow().as_ref().and_then(|manager| {
            let detail = manager.detail.as_ref()?;
            let form = detail.assign.as_ref()?;
            form.can_submit().then(|| {
                (
                    detail.summary.id.clone(),
                    Arc::clone(form.organization_id()),
                    form.picked(),
                    form.fixed(),
                )
            })
        });
        let Some((id, organization_id, picked, fixed)) = request else {
            return;
        };
        if !self.require_online() {
            return;
        }
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_assign_busy(true);
        }
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move {
                vault
                    .assign_collections(&id, &organization_id, picked)
                    .await
            },
            handler!(self, |app, result| {
                match result {
                    Ok(()) => {
                        app.close_assign();
                        let done = if fixed {
                            "Collections saved"
                        } else {
                            "Moved to the organization"
                        };
                        app.toast(done, false);
                    }
                    Err(error) => {
                        if let Some(manager) = app.manager.borrow().as_ref() {
                            manager.window.set_assign_busy(false);
                        }
                        app.toast(&viewmodel::error_text(&error), true);
                    }
                }
                app.on_vault_changed();
            }),
        );
    }
}
