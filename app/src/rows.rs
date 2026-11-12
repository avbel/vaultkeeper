//! Lazy list model over a search result. Rows are converted to `RowData` only when the view asks
//! for them, so a 400-item result costs one `Arc` clone, not 400 string conversions.

use std::{cell::RefCell, collections::HashMap, ops::Range, rc::Rc, sync::Arc};

use slint::{Model, ModelNotify, ModelTracker};
use vk_vault::model::{ItemId, ItemKind, ItemSummary};

use crate::{
    site_icon::{IconCache, icon_host},
    ui::RowData,
    viewmodel::{TotpCell, to_row},
};

pub struct RowsModel {
    items: RefCell<Arc<[ItemSummary]>>,
    limit: usize,
    totp: RefCell<HashMap<usize, TotpCell>>,
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
            totp: RefCell::new(HashMap::new()),
            icons,
            notify: ModelNotify::default(),
        })
    }

    pub fn set_items(&self, items: Arc<[ItemSummary]>) {
        *self.items.borrow_mut() = items;
        self.totp.borrow_mut().clear();
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

    /// Rows in `range` that show a TOTP cell whose code is missing or expired at `now`.
    #[must_use]
    pub fn stale_totp_rows(&self, range: Range<usize>, now: i32) -> Vec<(usize, ItemId)> {
        let items = self.items.borrow();
        let totp = self.totp.borrow();
        let end = range.end.min(self.len());
        (range.start.min(end)..end)
            .filter(|&row| items[row].has_totp)
            .filter(|row| totp.get(row).is_none_or(|cell| cell.expires <= now))
            .map(|row| (row, items[row].id.clone()))
            .collect()
    }

    #[must_use]
    pub fn has_totp_in(&self, range: Range<usize>) -> bool {
        let items = self.items.borrow();
        let end = range.end.min(self.len());
        items[range.start.min(end)..end]
            .iter()
            .any(|item| item.has_totp)
    }

    pub fn set_totp(&self, row: usize, cell: TotpCell) {
        if row >= self.len() {
            return;
        }
        self.totp.borrow_mut().insert(row, cell);
        self.notify.row_changed(row);
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
        Some(to_row(item, self.totp.borrow().get(&row), icon))
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

    fn cell(expires: i32) -> TotpCell {
        TotpCell {
            code: "123 456".into(),
            expires,
            period: 30,
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
    fn stale_totp_rows_are_missing_or_expired_within_range() {
        let model = RowsModel::new(None, Rc::default());
        model.set_items(Arc::from(vec![
            summary("a", true),
            summary("b", false),
            summary("c", true),
            summary("d", true),
        ]));
        let ids =
            |rows: Vec<(usize, ItemId)>| rows.into_iter().map(|(row, _)| row).collect::<Vec<_>>();
        assert_eq!(ids(model.stale_totp_rows(0..3, 0)), vec![0, 2]);
        model.set_totp(0, cell(30));
        assert_eq!(ids(model.stale_totp_rows(0..3, 10)), vec![2]);
        assert_eq!(ids(model.stale_totp_rows(0..3, 30)), vec![0, 2]);
        assert_eq!(ids(model.stale_totp_rows(2..100, 0)), vec![2, 3]);
        assert!(model.has_totp_in(1..3));
        assert!(!model.has_totp_in(1..2));
        assert!(!model.has_totp_in(10..20));
    }

    #[test]
    fn set_items_drops_totp_cells() {
        let model = RowsModel::new(None, Rc::default());
        model.set_items(Arc::from(vec![summary("a", true)]));
        model.set_totp(0, cell(30));
        assert_eq!(model.row_data(0).expect("row").totp_code, "123 456");
        model.set_items(Arc::from(vec![summary("a", true)]));
        assert_eq!(model.row_data(0).expect("row").totp_code, "");
        model.clear();
        assert!(model.is_empty());
        assert_eq!(model.visible_strings(), Vec::<String>::new());
    }
}
