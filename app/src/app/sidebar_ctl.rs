//! Manager sidebar: entry selection drives the list filter; folders are managed inline.

use std::sync::Arc;

use bwl_vault::{VaultService, model::Filter};
use slint::{Model, ModelRc, VecModel};

use super::{App, handler};
use crate::{
    sidebar::{self, Counts, SidebarKey},
    ui::ManagerWindow,
    viewmodel,
};

impl<S: VaultService> App<S> {
    pub(super) fn bind_sidebar(&self, window: &ManagerWindow) {
        window.on_sidebar_select(handler!(self, |app, index| app.select_sidebar_index(index)));
        window.on_create_folder(handler!(self, |app, name| app.create_folder(&name)));
        window.on_rename_folder(handler!(self, |app, index, name| app.rename_folder(index, &name)));
        window.on_delete_folder(handler!(self, |app, index| app.delete_folder(index)));
    }

    /// Counts, folders and collections; keeps the selected entry when it still exists.
    pub(super) fn refresh_sidebar(&self) {
        let all = self.vault.search("", &Filter::default());
        let trash = self.vault.search(
            "",
            &Filter {
                trash: true,
                ..Filter::default()
            },
        );
        let folders = self.vault.folders();
        let organizations = self.vault.organizations().unwrap_or_default();
        let collections = self.vault.collections().unwrap_or_default();
        let (Ok(all), Ok(trash), Ok(folders)) = (all, trash, folders) else {
            return;
        };
        let counts = Counts::tally(&all, trash.len());
        let data = sidebar::build(&folders, &organizations, &collections, &counts);
        let (labels, choices) = super::manager::folder_options(&folders);
        let mut guard = self.manager.borrow_mut();
        let Some(manager) = guard.as_mut() else {
            return;
        };
        let selected = data.index_of(&manager.sidebar_key).unwrap_or_else(|| {
            manager.sidebar_key = SidebarKey::All;
            manager.filter = Filter::default();
            0
        });
        manager.sidebar_model.set_vec(data.entries.clone());
        manager
            .window
            .set_sidebar_selected(i32::try_from(selected).unwrap_or(0));
        manager
            .window
            .set_folder_options(ModelRc::new(VecModel::from(labels)));
        manager.sidebar = data;
        manager.counts = counts;
        manager.folders = folders;
        manager.folder_choices = choices;
    }

    fn select_sidebar_index(&self, index: i32) {
        let key = self.manager.borrow().as_ref().and_then(|manager| {
            usize::try_from(index)
                .ok()
                .and_then(|index| manager.sidebar.keys.get(index).cloned())
        });
        if let Some(key) = key {
            self.select_sidebar_key(&key);
        }
    }

    /// Returns false for keys that are not in the sidebar (e.g. headers).
    pub(super) fn select_sidebar_key(&self, key: &SidebarKey) -> bool {
        let Some(filter) = sidebar::filter_for(key) else {
            return false;
        };
        {
            let mut guard = self.manager.borrow_mut();
            let Some(manager) = guard.as_mut() else {
                return false;
            };
            let Some(index) = manager.sidebar.index_of(key) else {
                return false;
            };
            manager.sidebar_key = key.clone();
            manager.filter = filter;
            manager
                .window
                .set_sidebar_selected(i32::try_from(index).unwrap_or(0));
            manager.window.invoke_scroll_top();
        }
        self.refresh_list();
        true
    }

    fn folder_at(&self, index: i32) -> Option<(usize, Arc<str>)> {
        self.manager.borrow().as_ref().and_then(|manager| {
            let index = usize::try_from(index).ok()?;
            match manager.sidebar.keys.get(index)? {
                SidebarKey::Folder(id) => Some((index, Arc::clone(id))),
                _ => None,
            }
        })
    }

    fn set_folder_busy(&self, index: usize, busy: bool) {
        if let Some(manager) = self.manager.borrow().as_ref()
            && let Some(mut entry) = manager.sidebar_model.row_data(index)
        {
            entry.busy = busy;
            manager.sidebar_model.set_row_data(index, entry);
        }
    }

    fn folders_online(&self) -> bool {
        if self.vault.is_offline() {
            self.toast("Folders can't be changed while offline", true);
            return false;
        }
        true
    }

    fn create_folder(&self, name: &str) {
        let name = name.trim().to_owned();
        if name.is_empty() || !self.folders_online() {
            return;
        }
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_sidebar_creating(true);
        }
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.create_folder(&name).await.map(drop) },
            handler!(self, |app, result| {
                if let Some(manager) = app.manager.borrow().as_ref() {
                    manager.window.set_sidebar_creating(false);
                }
                app.folder_done(&result);
            }),
        );
    }

    fn rename_folder(&self, index: i32, name: &str) {
        let name = name.trim().to_owned();
        let Some((row, id)) = self.folder_at(index) else {
            return;
        };
        if name.is_empty() || !self.folders_online() {
            return;
        }
        self.set_folder_busy(row, true);
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.rename_folder(&id, &name).await },
            handler!(self, |app, result| app.folder_done(&result)),
        );
    }

    fn delete_folder(&self, index: i32) {
        let Some((row, id)) = self.folder_at(index) else {
            return;
        };
        if !self.folders_online() {
            return;
        }
        self.set_folder_busy(row, true);
        let deleting_selected = self
            .manager
            .borrow()
            .as_ref()
            .is_some_and(|manager| manager.sidebar_key == SidebarKey::Folder(Arc::clone(&id)));
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.delete_folder(&id).await },
            handler!(self, |app, result| {
                if deleting_selected && result.is_ok() {
                    app.select_sidebar_key(&SidebarKey::NoFolder);
                }
                app.folder_done(&result);
            }),
        );
    }

    fn folder_done(&self, result: &bwl_vault::Result<()>) {
        if let Err(error) = result {
            self.toast(&viewmodel::error_text(error), true);
        }
        // Rebuilds the sidebar entries, which also clears the row spinner.
        self.on_vault_changed();
    }
}
