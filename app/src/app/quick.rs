//! Quick Panel: search-first pop-up, 8 rows, copy and dismiss.

use std::rc::Rc;

use bwl_vault::{
    VaultService,
    model::{CopyField, Filter},
};
use slint::{ComponentHandle, ModelRc, SharedString};

use super::{App, OFFLINE_TOAST, handler, hide, retire, show};
use crate::{
    keymap::{self, Command, Mods},
    rows::RowsModel,
    ui::QuickPanel,
    viewmodel,
};

pub const QUICK_ROWS: usize = 8;

pub(super) struct Quick {
    pub(super) window: QuickPanel,
    pub(super) rows: Rc<RowsModel>,
}

impl<S: VaultService> App<S> {
    /// Opens the panel; while locked it shows an inline master password field instead of results.
    pub(super) fn open_quick_panel(&self) {
        let locked = !matches!(
            self.vault.state(),
            bwl_vault::model::SessionState::Unlocked { .. }
        );
        // Clone the handle: showing a window can run its change handlers, which call back in.
        let existing = self
            .quick
            .borrow()
            .as_ref()
            .map(|quick| quick.window.clone_strong());
        if let Some(window) = existing {
            // Switching between the password and search fields moves focus; don't read that as
            // the panel losing focus. `focus-search` re-arms the tracking.
            window.invoke_pause_focus_tracking();
            window.set_locked(locked);
            if !locked {
                self.refresh_quick();
            }
            show(&window, "quick panel");
            window.invoke_focus_search();
            return;
        }
        let window = match QuickPanel::new() {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot create the Quick Panel");
                return;
            }
        };
        self.apply_theme(&window);
        let rows = RowsModel::new(Some(QUICK_ROWS));
        window.set_rows(ModelRc::from(Rc::clone(&rows)));
        self.bind_quick(&window);
        window.set_locked(locked);
        window.set_touch_id_available(self.touch_id_enrolled());
        let size = window
            .window()
            .size()
            .to_logical(window.window().scale_factor());
        if let Some(origin) = self
            .hooks
            .placement
            .quick_panel_origin(size.width, size.height)
        {
            window.window().set_position(origin);
        }
        *self.quick.borrow_mut() = Some(Quick {
            window: window.clone_strong(),
            rows,
        });
        if !locked {
            self.refresh_quick();
        }
        show(&window, "quick panel");
        window.invoke_focus_search();
        if !locked && self.vault.is_offline() {
            self.toast(OFFLINE_TOAST, false);
        }
    }

    pub(super) fn close_quick_panel(&self) {
        let Some(quick) = self.quick.borrow_mut().take() else {
            return;
        };
        hide(&quick.window);
        retire(quick);
        self.window_closed();
        self.update_ticker();
    }

    fn bind_quick(&self, window: &QuickPanel) {
        window.on_search_edited(handler!(self, |app, _text| app.refresh_quick()));
        window.on_row_clicked(handler!(self, |app, row| {
            if let Some(quick) = app.quick.borrow().as_ref() {
                quick.window.set_selected(row);
            }
        }));
        window.on_row_double_clicked(handler!(self, |app, row| {
            if let Some(quick) = app.quick.borrow().as_ref() {
                quick.window.set_selected(row);
            }
            app.quick_command(Command::OpenInManager);
        }));
        window.on_copy_row(handler!(self, false, |app, row, code| app.copy_quick_row(row, code)));
        window.on_key_command(handler!(self, false, |app, text, cmd, shift, alt| {
            keymap::command(&text, Mods { cmd, shift, alt })
                .is_some_and(|command| app.quick_command(command))
        }));
        // The change handler can run after this panel was replaced by a new one; only close
        // the panel that actually lost focus.
        let sender = window.as_weak();
        window.on_focus_lost(handler!(self, |app| {
            let current = app
                .quick
                .borrow()
                .as_ref()
                .map(|quick| quick.window.as_weak());
            if let (Some(sender), Some(current)) =
                (sender.upgrade(), current.and_then(|weak| weak.upgrade()))
                && std::ptr::eq(sender.window(), current.window())
            {
                app.close_quick_panel();
            }
        }));
        window.on_toast_dismissed(handler!(self, |app| {
            if let Some(quick) = app.quick.borrow().as_ref() {
                quick.window.set_toast_shown(false);
            }
        }));
        window.on_unlock(handler!(self, |app, password| app
            .unlock(zeroize::Zeroizing::new(password.to_string()))));
        window.on_unlock_touch_id(handler!(self, |app| app.unlock_touch_id()));
    }

    /// Re-runs the panel's search; an empty query lists the most recently used items.
    pub(super) fn refresh_quick(&self) {
        let Some(query) = self
            .quick
            .borrow()
            .as_ref()
            .filter(|quick| !quick.window.get_locked())
            .map(|quick| quick.window.get_query())
        else {
            return;
        };
        let result = self.vault.search(&query, &Filter::default());
        match result {
            Ok(items) => {
                if let Some(quick) = self.quick.borrow().as_ref() {
                    quick.rows.set_items(items);
                    quick.window.set_selected(0);
                }
            }
            Err(error) => self.toast(&viewmodel::error_text(&error), true),
        }
        self.refresh_totp();
    }

    fn quick_item(&self, row: Option<i32>) -> Option<bwl_vault::model::ItemSummary> {
        self.quick.borrow().as_ref().and_then(|quick| {
            let row = row.unwrap_or_else(|| quick.window.get_selected());
            usize::try_from(row)
                .ok()
                .and_then(|row| quick.rows.item(row))
        })
    }

    fn copy_quick_row(&self, row: i32, code: i32) -> bool {
        match (self.quick_item(Some(row)), viewmodel::copy_field(code)) {
            (Some(item), Some(field)) => self.copy_item_field(&item, field),
            _ => false,
        }
    }

    /// Keyboard copies dismiss the panel, like Spotlight; mouse copies keep it open.
    fn copy_and_dismiss(&self, field: CopyField) -> bool {
        if let Some(item) = self.quick_item(None)
            && self.copy_item_field(&item, field)
        {
            self.close_quick_panel();
        }
        true
    }

    fn move_quick_selection(&self, delta: i32) -> bool {
        if let Some(quick) = self.quick.borrow().as_ref() {
            quick.window.set_keyboard_nav(true);
            let count = i32::try_from(quick.rows.len()).unwrap_or(0);
            if count > 0 {
                quick
                    .window
                    .set_selected((quick.window.get_selected() + delta).clamp(0, count - 1));
            }
        }
        true
    }

    fn quick_escape(&self) -> bool {
        let has_query = self
            .quick
            .borrow()
            .as_ref()
            .is_some_and(|quick| !quick.window.get_query().is_empty());
        if has_query {
            if let Some(quick) = self.quick.borrow().as_ref() {
                quick.window.set_query(SharedString::new());
            }
            self.refresh_quick();
        } else {
            self.close_quick_panel();
        }
        true
    }

    fn quick_command(&self, command: Command) -> bool {
        let locked = self
            .quick
            .borrow()
            .as_ref()
            .is_some_and(|quick| quick.window.get_locked());
        if locked {
            return match command {
                Command::Escape | Command::CloseWindow | Command::QuickPanel => {
                    self.close_quick_panel();
                    true
                }
                Command::Quit => {
                    self.quit();
                    true
                }
                _ => false,
            };
        }
        match command {
            Command::Up => self.move_quick_selection(-1),
            Command::Down => self.move_quick_selection(1),
            Command::CopyPassword => self.copy_and_dismiss(CopyField::Password),
            Command::CopyUsername => self.copy_and_dismiss(CopyField::Username),
            Command::CopyTotp => self.copy_and_dismiss(CopyField::Totp),
            Command::OpenUri => {
                if let Some(uri) = self.quick_item(None).and_then(|item| item.primary_uri)
                    && let Err(error) = self.hooks.opener.open(&uri)
                {
                    self.toast(&error.to_string(), true);
                }
                self.close_quick_panel();
                true
            }
            Command::OpenInManager | Command::Edit => {
                let item = self.quick_item(None);
                self.close_quick_panel();
                if let Some(item) = item {
                    self.reveal_in_manager(&item.id);
                    if command == Command::Edit {
                        self.start_edit();
                    }
                } else {
                    self.open_manager();
                }
                true
            }
            Command::New | Command::Generator | Command::Settings => {
                self.close_quick_panel();
                self.open_manager();
                match command {
                    Command::New => self.new_item(0),
                    Command::Generator => self.open_detail_generator(),
                    _ => self.open_settings(),
                }
                true
            }
            Command::Escape => self.quick_escape(),
            Command::Lock => {
                self.lock();
                true
            }
            Command::QuickPanel | Command::CloseWindow => {
                self.close_quick_panel();
                true
            }
            Command::Quit => {
                self.quit();
                true
            }
            Command::FocusSearch => true,
            Command::ToggleFavorite | Command::FilterKind(_) | Command::ToggleSidebar => false,
        }
    }
}
