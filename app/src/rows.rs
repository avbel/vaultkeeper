//! Lazy list model over a search result. Rows are converted to `RowData` only when the view asks
//! for them, so a 400-item result costs one `Arc` clone, not 400 string conversions.

use std::{cell::RefCell, ops::Range, rc::Rc, sync::Arc};

use slint::{Model, ModelNotify, ModelTracker};
use vk_vault::model::{ItemId, ItemKind, ItemSummary};

use crate::{
    site_icon::{IconCache, icon_host},
    ui::RowData,
    viewmodel::to_row,
};

pub struct RowsModel {
    items: RefCell<Arc<[ItemSummary]>>,
    limit: usize,
    icons: Rc<IconCache>,
    notify: ModelNotify,
}

impl RowsModel {
    /// `limit` caps the rows shown (the Quick Panel shows 8). Rows show the icons in `icons`
    /// that have loaded and never load any themselves.
    #[must_use]
    pub fn new(limit: Option<usize>, icons: Rc<IconCache>) -> Rc<Self> {
        Rc::new(Self {
            items: RefCell::new(Arc::from([])),
            limit: limit.unwrap_or(usize::MAX),
            icons,
            notify: ModelNotify::default(),
        })
    }

    pub fn set_items(&self, items: Arc<[ItemSummary]>) {
        *self.items.borrow_mut() = items;
        self.notify.reset();
    }

    pub fn clear(&self) {
        self.set_items(Arc::from([]));
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.borrow().len().min(self.limit)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total matches, including rows beyond the display limit.
    #[must_use]
    pub fn total(&self) -> usize {
        self.items.borrow().len()
    }

    #[must_use]
    pub fn item(&self, row: usize) -> Option<ItemSummary> {
        (row < self.len())
            .then(|| self.items.borrow().get(row).cloned())
            .flatten()
    }

    #[must_use]
    pub fn position(&self, id: &ItemId) -> Option<usize> {
        self.items
            .borrow()
            .iter()
            .take(self.limit)
            .position(|item| &item.id == id)
    }

    /// Distinct icon hosts of the logins in `range`, top first.
    #[must_use]
    pub fn icon_hosts(&self, range: Range<usize>) -> Vec<Arc<str>> {
        let items = self.items.borrow();
        let end = range.end.min(self.len());
        let mut hosts: Vec<Arc<str>> = Vec::new();
        for host in items[range.start.min(end)..end]
            .iter()
            .filter_map(item_host)
        {
            if !hosts.iter().any(|known| known.as_ref() == host) {
                hosts.push(Arc::from(host));
            }
        }
        hosts
    }

    /// Redraws the rows in `range` whose login has `host`'s icon.
    pub fn icon_loaded(&self, host: &str, range: Range<usize>) {
        let rows: Vec<usize> = {
            let items = self.items.borrow();
            let end = range.end.min(self.len());
            (range.start.min(end)..end)
                .filter(|&row| item_host(&items[row]).is_some_and(|known| known == host))
                .collect()
        };
        for row in rows {
            self.notify.row_changed(row);
        }
    }

    /// Strings this model can currently show, for tests that check nothing leaks across accounts.
    #[must_use]
    pub fn visible_strings(&self) -> Vec<String> {
        (0..self.len())
            .filter_map(|row| self.row_data(row))
            .flat_map(|row| [row.name.to_string(), row.subtitle.to_string()])
            .collect()
    }
}

impl Model for RowsModel {
    type Data = RowData;

    fn row_count(&self) -> usize {
        self.len()
    }

    fn row_data(&self, row: usize) -> Option<RowData> {
        let items = self.items.borrow();
        let item = items.get(row).filter(|_| row < self.limit)?;
        let icon = if self.icons.is_empty() {
            None
        } else {
            item_host(item).and_then(|host| self.icons.image(&host))
        };
        Some(to_row(item, icon))
    }

    fn model_tracker(&self) -> &dyn ModelTracker {
        &self.notify
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Only logins show a site icon, as in the official clients.
pub(crate) fn item_host(item: &ItemSummary) -> Option<String> {
    (item.kind == ItemKind::Login)
        .then_some(item.primary_uri.as_deref())
        .flatten()
        .and_then(icon_host)
}

#[cfg(test)]
mod tests {
    use vk_vault::model::ItemKind;

    use super::*;

    fn summary(id: &str, has_totp: bool) -> ItemSummary {
        ItemSummary {
            id: ItemId(Arc::from(id)),
            kind: ItemKind::Login,
            name: Arc::from(format!("name {id}")),
            subtitle: Arc::from("user"),
            favorite: false,
            folder_id: None,
            organization_id: None,
            primary_uri: None,
            has_password: true,
            has_totp,
            reprompt: false,
            deleted: false,
            editable: true,
        }
    }

    #[test]
    fn limit_caps_rows() {
        let model = RowsModel::new(Some(2), Rc::default());
        model.set_items(Arc::from(vec![
            summary("a", false),
            summary("b", false),
            summary("c", false),
        ]));
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.total(), 3);
        assert!(model.row_data(2).is_none());
        assert!(model.item(2).is_none());
        assert_eq!(model.position(&ItemId(Arc::from("c"))), None);
        assert_eq!(model.position(&ItemId(Arc::from("b"))), Some(1));
    }

    #[test]
    fn clear_empties_the_model() {
        let model = RowsModel::new(None, Rc::default());
        model.set_items(Arc::from(vec![summary("a", true)]));
        model.clear();
        assert!(model.is_empty());
        assert_eq!(model.visible_strings(), Vec::<String>::new());
    }
}
