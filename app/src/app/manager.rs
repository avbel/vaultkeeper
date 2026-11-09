//! Manager window: list, sidebar, detail; this file holds lifecycle, list and keyboard handling.

use std::{rc::Rc, sync::Arc};

use bwl_vault::{
    VaultService,
    model::{Filter, FolderView, ItemId, ItemKind},
};
use slint::{CloseRequestResponse, ComponentHandle, Model, ModelRc, SharedString, VecModel};

use super::{
    App, OFFLINE_TOAST, handler, hide, manager_detail::Detail, manager_edit::Edit, retire, show,
};
use crate::{
    keymap::{self, Command, Mods},
    rows::RowsModel,
    settings::WindowGeometry,
    sidebar::{Counts, SidebarData, SidebarKey},
    ui::{ManagerWindow, SidebarEntry},
    viewmodel::{self, SHORTCUT_KINDS},
};

pub(super) struct Manager {
    pub(super) window: ManagerWindow,
    pub(super) rows: Rc<RowsModel>,
    pub(super) sidebar: SidebarData,
    pub(super) sidebar_model: Rc<VecModel<SidebarEntry>>,
    pub(super) sidebar_key: SidebarKey,
    pub(super) counts: Counts,
    pub(super) filter: Filter,
    pub(super) folders: Vec<FolderView>,
    /// Folder for each entry of the folder pickers: `None` = "No folder".
    pub(super) folder_choices: Vec<Option<Arc<str>>>,
    pub(super) selected: Option<ItemId>,
    pub(super) detail: Option<Detail>,
    pub(super) edit: Option<Edit>,
    /// The row clicked while the form had unsaved changes, waiting for Save / Discard / Cancel.
    pub(super) switch_to: Option<ItemId>,
}

impl Manager {
    pub(super) fn strings(&self) -> Vec<String> {
        let mut strings = self.rows.visible_strings();
        strings.extend(
            self.sidebar
                .entries
                .iter()
                .map(|entry| entry.label.to_string()),
        );
        strings.extend(self.folders.iter().map(|folder| folder.name.to_string()));
        if let Some(detail) = &self.detail {
            strings.extend(detail.strings());
        }
        if let Some(edit) = &self.edit {
            strings.extend(edit.fields.iter().map(|field| field.value.to_string()));
        }
        strings.push(self.window.get_query().to_string());
        strings
    }

    fn selected_row(&self) -> Option<usize> {
        usize::try_from(self.window.get_selected()).ok()
    }
}

fn to_i32(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

impl<S: VaultService> App<S> {
    pub(super) fn open_manager(&self) {
        let existing = self
            .manager
            .borrow()
            .as_ref()
            .map(|manager| manager.window.clone_strong());
        if let Some(window) = existing {
            show(&window, "manager");
            window.invoke_focus_search();
            return;
        }
        let window = match ManagerWindow::new() {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot create the Manager window");
                return;
            }
        };
        self.apply_theme(&window);
        let rows = RowsModel::new(None);
        window.set_rows(ModelRc::from(Rc::clone(&rows)));
        let sidebar_model = Rc::new(VecModel::default());
        window.set_sidebar_entries(ModelRc::from(Rc::clone(&sidebar_model)));
        self.bind_manager(&window);
        self.bind_manager_detail(&window);
        self.bind_manager_edit(&window);
        self.bind_sidebar(&window);
        self.bind_reprompt(&window);
        self.bind_generator(&window.global::<crate::ui::GeneratorState>());
        *self.manager.borrow_mut() = Some(Manager {
            window: window.clone_strong(),
            rows,
            sidebar: SidebarData::default(),
            sidebar_model,
            sidebar_key: SidebarKey::All,
            counts: Counts::default(),
            filter: Filter::default(),
            folders: Vec::new(),
            folder_choices: Vec::new(),
            selected: None,
            detail: None,
            edit: None,
            switch_to: None,
        });
        self.restore_geometry(&window);
        self.refresh_manager();
        self.refresh_accounts_menu();
        self.restore_clip_status();
        show(&window, "manager");
        self.hooks.dock.set_visible(true);
        if self.vault.is_offline() {
            self.toast(OFFLINE_TOAST, false);
        }
    }

    pub(super) fn close_manager(&self) {
        let Some(manager) = self.manager.borrow_mut().take() else {
            return;
        };
        self.save_geometry(&manager.window);
        hide(&manager.window);
        retire(manager);
        self.window_closed();
        self.hooks.dock.set_visible(false);
        self.update_ticker();
    }

    fn bind_manager(&self, window: &ManagerWindow) {
        window.window().on_close_requested(handler!(
            self,
            CloseRequestResponse::HideWindow,
            |app| {
                app.close_manager();
                CloseRequestResponse::HideWindow
            }
        ));
        window.on_search_edited(handler!(self, |app, _text| app.refresh_list()));
        window.on_row_clicked(handler!(self, |app, row| app.select_row(row)));
        window.on_row_double_clicked(handler!(self, |app, row| {
            app.select_row(row);
            if !app.editing() {
                app.start_edit();
            }
        }));
        window.on_copy_row(handler!(self, false, |app, row, code| app
            .copy_manager_row(row, code)));
        window.on_visible_range_changed(handler!(self, |app| app.refresh_totp()));
        window.on_key_command(handler!(self, false, |app, text, cmd, shift, alt| {
            keymap::command(&text, Mods { cmd, shift, alt })
                .is_some_and(|command| app.manager_command(command))
        }));
        window.on_open_settings(handler!(self, |app| app.open_settings()));
        window.on_lock(handler!(self, |app| app.lock()));
        window.on_switch_account(handler!(self, |app, index| app.switch_account_at(index)));
        window.on_add_account(handler!(self, |app| app.add_account()));
        window.on_logout_confirmed(handler!(self, |app| app.logout()));
        window.on_toast_dismissed(handler!(self, |app| {
            if let Some(manager) = app.manager.borrow().as_ref() {
                manager.window.set_toast_shown(false);
            }
        }));
        window.on_status_tick(handler!(self, |app| app.refresh_status()));
        window.on_close_generator(handler!(self, |app| app.close_detail_generator()));
        window.on_clear_filters(handler!(self, |app| app.clear_filters()));
        window.set_inset_title_bar(cfg!(target_os = "macos"));
    }

    fn restore_geometry(&self, window: &ManagerWindow) {
        let Some(geometry) = self
            .settings
            .borrow()
            .manager_geometry
            .map(WindowGeometry::clamped)
        else {
            return;
        };
        window.window().set_position(slint::LogicalPosition::new(
            lossless_f32(geometry.x),
            lossless_f32(geometry.y),
        ));
        window.window().set_size(slint::LogicalSize::new(
            lossless_f32(geometry.width),
            lossless_f32(geometry.height),
        ));
        window.set_sidebar_collapsed(geometry.sidebar_collapsed);
    }

    fn save_geometry(&self, window: &ManagerWindow) {
        let scale = window.window().scale_factor();
        let position = window.window().position().to_logical(scale);
        let size = window.window().size().to_logical(scale);
        let geometry = WindowGeometry {
            x: pixels(position.x),
            y: pixels(position.y),
            width: u32::try_from(pixels(size.width)).unwrap_or(0),
            height: u32::try_from(pixels(size.height)).unwrap_or(0),
            sidebar_collapsed: window.get_sidebar_collapsed(),
        };
        self.update_settings(|settings| settings.manager_geometry = Some(geometry));
    }

    fn clear_filters(&self) {
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_query(SharedString::new());
        }
        self.select_sidebar_key(&SidebarKey::All);
    }

    /// Re-reads list, sidebar, detail and footer after a vault change.
    pub(super) fn refresh_manager(&self) {
        if self.manager.borrow().is_none() {
            return;
        }
        self.refresh_sidebar();
        self.refresh_list();
        self.reload_detail();
        self.refresh_status();
        let offline = self.vault.is_offline();
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_online(!offline);
        }
    }

    pub(super) fn refresh_list(&self) {
        let Some((query, filter)) = self
            .manager
            .borrow()
            .as_ref()
            .map(|manager| (manager.window.get_query(), manager.filter.clone()))
        else {
            return;
        };
        let result = self.vault.search(&query, &filter);
        let guard = self.manager.borrow();
        let Some(manager) = guard.as_ref() else {
            return;
        };
        match result {
            Ok(items) => {
                manager.rows.set_items(items);
                let row = manager
                    .selected
                    .as_ref()
                    .and_then(|id| manager.rows.position(id));
                manager.window.set_selected(row.map_or(-1, to_i32));
                manager
                    .window
                    .set_empty_text(empty_text(&query, &filter).into());
                let empty_kind = if !query.is_empty() {
                    1
                } else if filter == Filter::default() {
                    0
                } else {
                    2
                };
                manager.window.set_empty_kind(empty_kind);
                manager
                    .window
                    .set_loading(self.syncing.get() && manager.rows.is_empty());
            }
            Err(error) => {
                drop(guard);
                self.toast(&viewmodel::error_text(&error), true);
                return;
            }
        }
        drop(guard);
        self.refresh_totp();
    }

    pub(super) fn select_row(&self, row: i32) {
        let item = {
            let guard = self.manager.borrow();
            let Some(manager) = guard.as_ref() else {
                return;
            };
            let Some(item) = usize::try_from(row)
                .ok()
                .and_then(|row| manager.rows.item(row))
            else {
                return;
            };
            if let Some(edit) = &manager.edit {
                if manager.window.get_saving() || edit.id.as_ref() == Some(&item.id) {
                    return;
                }
                drop(guard);
                self.ask_before_leaving_edit(item.id);
                return;
            }
            manager.window.set_selected(row);
            manager.window.invoke_scroll_to(row);
            item
        };
        self.show_detail(&item.id);
    }

    fn move_selection(&self, delta: i32) -> bool {
        let next = {
            let guard = self.manager.borrow();
            let Some(manager) = guard.as_ref() else {
                return false;
            };
            let count = to_i32(manager.rows.len());
            if count == 0 {
                return true;
            }
            manager.window.set_keyboard_nav(true);
            (manager.window.get_selected() + delta).clamp(0, count - 1)
        };
        self.select_row(next);
        true
    }

    fn copy_manager_row(&self, row: i32, code: i32) -> bool {
        let item = self.manager.borrow().as_ref().and_then(|manager| {
            usize::try_from(row)
                .ok()
                .and_then(|row| manager.rows.item(row))
        });
        match (item, viewmodel::copy_field(code)) {
            (Some(item), Some(field)) => self.copy_item_field(&item, field),
            _ => false,
        }
    }

    fn copy_selected(&self, field: bwl_vault::model::CopyField) -> bool {
        let item = self.manager.borrow().as_ref().and_then(|manager| {
            manager
                .selected_row()
                .and_then(|row| manager.rows.item(row))
        });
        if let Some(item) = item {
            self.copy_item_field(&item, field);
        }
        true
    }

    fn editing(&self) -> bool {
        self.manager
            .borrow()
            .as_ref()
            .is_some_and(|manager| manager.edit.is_some())
    }

    fn manager_command(&self, command: Command) -> bool {
        use bwl_vault::model::CopyField;
        if self.editing() {
            return match command {
                Command::Escape => {
                    self.cancel_edit();
                    true
                }
                Command::Lock => {
                    self.lock();
                    true
                }
                Command::CloseWindow => {
                    self.close_manager();
                    true
                }
                _ => false,
            };
        }
        match command {
            Command::Up => self.move_selection(-1),
            Command::Down => self.move_selection(1),
            Command::CopyPassword => self.copy_selected(CopyField::Password),
            Command::CopyUsername => self.copy_selected(CopyField::Username),
            Command::CopyTotp => self.copy_selected(CopyField::Totp),
            // Nothing to type into from the Manager; ⌘⇧↩ keeps opening the item's URI there.
            Command::AutoType => {
                self.open_selected_uri();
                true
            }
            Command::OpenInManager => false,
            Command::Edit => {
                self.start_edit();
                true
            }
            Command::ToggleFavorite => {
                self.toggle_favorite();
                true
            }
            Command::New => {
                self.new_item(0);
                true
            }
            Command::Generator => {
                self.open_detail_generator();
                true
            }
            Command::Settings => {
                self.open_settings();
                true
            }
            Command::FilterKind(number) => {
                let kind = SHORTCUT_KINDS
                    .get(usize::from(number).saturating_sub(1))
                    .copied();
                kind.is_some_and(|kind| self.select_sidebar_key(&SidebarKey::Kind(kind)))
            }
            Command::Escape => self.manager_escape(),
            Command::Lock => {
                self.lock();
                true
            }
            Command::ToggleSidebar => {
                if let Some(manager) = self.manager.borrow().as_ref() {
                    let collapsed = manager.window.get_sidebar_collapsed();
                    manager.window.set_sidebar_collapsed(!collapsed);
                }
                true
            }
            Command::FocusSearch => {
                if let Some(manager) = self.manager.borrow().as_ref() {
                    manager.window.invoke_focus_search();
                }
                true
            }
            Command::QuickPanel => {
                self.toggle_quick_panel();
                true
            }
            Command::CloseWindow => {
                self.close_manager();
                true
            }
            Command::Quit => {
                self.quit();
                true
            }
        }
    }

    fn manager_escape(&self) -> bool {
        let (has_query, generator) = {
            let guard = self.manager.borrow();
            let Some(manager) = guard.as_ref() else {
                return false;
            };
            (
                !manager.window.get_query().is_empty(),
                manager.window.get_detail_mode() == 3,
            )
        };
        if generator {
            self.close_detail_generator();
        } else if has_query {
            if let Some(manager) = self.manager.borrow().as_ref() {
                manager.window.set_query(SharedString::new());
            }
            self.refresh_list();
        } else {
            return false;
        }
        true
    }

    fn open_selected_uri(&self) {
        let uri = self.manager.borrow().as_ref().and_then(|manager| {
            manager
                .selected_row()
                .and_then(|row| manager.rows.item(row))
                .and_then(|item| item.primary_uri)
        });
        if let Some(uri) = uri
            && let Err(error) = self.hooks.opener.open(&uri)
        {
            self.toast(&error.to_string(), true);
        }
    }

    /// Selects an item from outside (Quick Panel ⌘O): clears search and filter so it is listed.
    pub(super) fn reveal_in_manager(&self, id: &ItemId) {
        self.open_manager();
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_query(SharedString::new());
        }
        self.select_sidebar_key(&SidebarKey::All);
        let row = self
            .manager
            .borrow()
            .as_ref()
            .and_then(|manager| manager.rows.position(id));
        if let Some(row) = row {
            self.select_row(to_i32(row));
        }
    }
}

pub(super) fn folder_options(folders: &[FolderView]) -> (Vec<SharedString>, Vec<Option<Arc<str>>>) {
    let mut sorted: Vec<&FolderView> = folders.iter().collect();
    sorted.sort_by_cached_key(|folder| folder.name.to_lowercase());
    let labels = std::iter::once(SharedString::from("No folder"))
        .chain(sorted.iter().map(|folder| folder.name.as_ref().into()))
        .collect();
    let choices = std::iter::once(None)
        .chain(sorted.iter().map(|folder| Some(Arc::clone(&folder.id))))
        .collect();
    (labels, choices)
}

/// Screen coordinates are far below 2^24, where f32 stops being exact.
fn lossless_f32(value: impl Into<i64>) -> f32 {
    let value: i64 = value.into().clamp(-(1 << 24), 1 << 24);
    #[allow(
        clippy::cast_precision_loss,
        reason = "clamped to the exactly representable range"
    )]
    let value = value as f32;
    value
}

/// Rounds a logical coordinate to whole pixels, saturating out-of-range values.
fn pixels(value: f32) -> i32 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "rounded first; `as` saturates"
    )]
    let value = value.round() as i32;
    value
}

fn empty_text(query: &str, filter: &Filter) -> &'static str {
    if !query.is_empty() {
        "No matches"
    } else if filter.trash {
        "Trash is empty"
    } else if filter.kind == Some(ItemKind::SshKey) {
        "No SSH keys"
    } else {
        "No items"
    }
}
