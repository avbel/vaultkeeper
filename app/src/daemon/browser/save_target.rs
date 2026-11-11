//! Select eligible targets for a save prompt; password comparison happens separately.

use vk_ipc::browser::protocol::SaveKind;
use vk_vault::model::ItemSummary;

pub enum SaveTarget<'a> {
    Ignore,
    Create,
    Compare(&'a ItemSummary),
    Choose(Vec<&'a ItemSummary>),
}

/// `matches` must be the current vault's non-deleted login matches for the page.
#[must_use]
pub fn select<'a>(username: &str, kind: &SaveKind, matches: &'a [ItemSummary]) -> SaveTarget<'a> {
    if username.is_empty() {
        if !matches!(kind, SaveKind::Change) {
            return SaveTarget::Ignore;
        }
        let editable: Vec<_> = matches.iter().filter(|item| item.editable).collect();
        return match editable.as_slice() {
            [] => SaveTarget::Ignore,
            [item] => SaveTarget::Compare(item),
            _ => SaveTarget::Choose(editable),
        };
    }
    let folded = username.to_lowercase();
    let mut matching = matches
        .iter()
        .filter(|item| item.subtitle.to_lowercase() == folded);
    match matching.find(|item| item.editable) {
        Some(item) => SaveTarget::Compare(item),
        None if matches
            .iter()
            .any(|item| item.subtitle.to_lowercase() == folded) =>
        {
            SaveTarget::Ignore
        }
        None => SaveTarget::Create,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_vault::model::{ItemId, ItemKind};

    fn item(id: &str, username: &str, editable: bool) -> ItemSummary {
        ItemSummary {
            id: ItemId(id.into()),
            kind: ItemKind::Login,
            name: id.into(),
            subtitle: username.into(),
            favorite: false,
            folder_id: None,
            organization_id: None,
            primary_uri: None,
            has_password: true,
            has_totp: false,
            reprompt: false,
            deleted: false,
            editable,
        }
    }

    #[test]
    fn chooses_only_editable_targets_without_silently_duplicating_read_only_items() {
        let matches = [
            item("a", "User", false),
            item("b", "user", true),
            item("c", "other", true),
        ];
        assert!(
            matches!(select("USER", &SaveKind::Login, &matches), SaveTarget::Compare(item) if item.id.0.as_ref() == "b")
        );
        assert!(matches!(
            select("new", &SaveKind::Login, &matches),
            SaveTarget::Create
        ));
        assert!(matches!(
            select("", &SaveKind::Login, &matches),
            SaveTarget::Ignore
        ));
        assert!(
            matches!(select("", &SaveKind::Change, &matches), SaveTarget::Choose(items) if items.len() == 2)
        );
        assert!(matches!(
            select("User", &SaveKind::Login, &matches[..1]),
            SaveTarget::Ignore
        ));
        assert!(matches!(
            select("", &SaveKind::Change, &matches[..1]),
            SaveTarget::Ignore
        ));
        assert!(matches!(
            select("", &SaveKind::Change, &matches[1..2]),
            SaveTarget::Compare(_)
        ));
    }
}
