//! Manager sidebar: entries, per-entry counts and the `Filter` each entry selects.

use std::{collections::HashMap, sync::Arc};

use bwl_vault::model::{
    CollectionView, Filter, FolderView, ItemKind, ItemSummary, OrganizationView,
};

use crate::{ui::SidebarEntry, viewmodel::SHORTCUT_KINDS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidebarKey {
    Header,
    All,
    Favorites,
    Kind(ItemKind),
    NoFolder,
    Folder(Arc<str>),
    Organization(Arc<str>),
    /// `Filter` has no collection field yet, so this filters by its organization.
    Collection {
        organization: Arc<str>,
        id: Arc<str>,
    },
    Trash,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counts {
    pub all: usize,
    pub favorites: usize,
    pub kinds: HashMap<ItemKind, usize>,
    pub no_folder: usize,
    pub folders: HashMap<Arc<str>, usize>,
    pub organizations: HashMap<Arc<str>, usize>,
    pub trash: usize,
}

impl Counts {
    /// One pass over the non-deleted items; `trash` is counted separately by the caller.
    #[must_use]
    pub fn tally(items: &[ItemSummary], trash: usize) -> Self {
        let mut counts = Self {
            all: items.len(),
            trash,
            ..Self::default()
        };
        for item in items {
            counts.favorites += usize::from(item.favorite);
            *counts.kinds.entry(item.kind).or_default() += 1;
            match &item.folder_id {
                Some(folder) => *counts.folders.entry(Arc::clone(folder)).or_default() += 1,
                None => counts.no_folder += 1,
            }
            if let Some(organization) = &item.organization_id {
                *counts
                    .organizations
                    .entry(Arc::clone(organization))
                    .or_default() += 1;
            }
        }
        counts
    }
}

const ICON_ALL: i32 = 0;
const ICON_FAVORITES: i32 = 1;
const ICON_FOLDER: i32 = 7;
const ICON_ORG: i32 = 8;
const ICON_COLLECTION: i32 = 9;
const ICON_TRASH: i32 = 10;

const fn kind_icon(kind: ItemKind) -> i32 {
    match kind {
        ItemKind::Login => 2,
        ItemKind::Card => 3,
        ItemKind::Identity => 4,
        ItemKind::SecureNote => 5,
        ItemKind::SshKey => 6,
        ItemKind::Unsupported(_) => 0,
    }
}

const fn kind_plural(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "Logins",
        ItemKind::Card => "Cards",
        ItemKind::Identity => "Identities",
        ItemKind::SecureNote => "Secure notes",
        ItemKind::SshKey => "SSH keys",
        ItemKind::Unsupported(_) => "Other",
    }
}

#[derive(Default)]
pub struct SidebarData {
    pub keys: Vec<SidebarKey>,
    pub entries: Vec<SidebarEntry>,
}

impl SidebarData {
    fn push(&mut self, key: SidebarKey, kind: i32, label: &str, count: Option<usize>, icon: i32) {
        self.keys.push(key);
        self.entries.push(SidebarEntry {
            kind,
            label: label.into(),
            count: count
                .map(|count| count.to_string())
                .unwrap_or_default()
                .into(),
            icon,
            busy: false,
        });
    }

    fn header(&mut self, label: &str) {
        self.push(SidebarKey::Header, 0, label, None, 0);
    }

    #[must_use]
    pub fn index_of(&self, key: &SidebarKey) -> Option<usize> {
        self.keys.iter().position(|candidate| candidate == key)
    }
}

fn sorted_by_name<T>(items: &[T], name: impl Fn(&T) -> &str) -> Vec<&T> {
    let mut sorted: Vec<&T> = items.iter().collect();
    sorted.sort_by_cached_key(|item| name(item).to_lowercase());
    sorted
}

#[must_use]
pub fn build(
    folders: &[FolderView],
    organizations: &[OrganizationView],
    collections: &[CollectionView],
    counts: &Counts,
) -> SidebarData {
    let mut data = SidebarData::default();
    data.push(SidebarKey::All, 1, "All items", Some(counts.all), ICON_ALL);
    data.push(
        SidebarKey::Favorites,
        1,
        "Favorites",
        Some(counts.favorites),
        ICON_FAVORITES,
    );
    data.header("Types");
    for kind in SHORTCUT_KINDS {
        let count = counts.kinds.get(&kind).copied().unwrap_or(0);
        data.push(
            SidebarKey::Kind(kind),
            1,
            kind_plural(kind),
            Some(count),
            kind_icon(kind),
        );
    }
    data.header("Folders");
    data.push(
        SidebarKey::NoFolder,
        1,
        "No folder",
        Some(counts.no_folder),
        ICON_FOLDER,
    );
    for folder in sorted_by_name(folders, |folder| &folder.name) {
        let count = counts.folders.get(&folder.id).copied().unwrap_or(0);
        data.push(
            SidebarKey::Folder(Arc::clone(&folder.id)),
            2,
            &folder.name,
            Some(count),
            ICON_FOLDER,
        );
    }
    if !organizations.is_empty() {
        data.header("Collections");
    }
    for organization in sorted_by_name(organizations, |organization| &organization.name) {
        let count = counts
            .organizations
            .get(&organization.id)
            .copied()
            .unwrap_or(0);
        let key = SidebarKey::Organization(Arc::clone(&organization.id));
        data.push(key, 3, &organization.name, Some(count), ICON_ORG);
        let own = collections
            .iter()
            .filter(|collection| collection.organization_id == organization.id)
            .cloned()
            .collect::<Vec<_>>();
        for collection in sorted_by_name(&own, |collection| &collection.name) {
            let key = SidebarKey::Collection {
                organization: Arc::clone(&organization.id),
                id: Arc::clone(&collection.id),
            };
            data.push(key, 4, &collection.name, None, ICON_COLLECTION);
        }
    }
    data.header("");
    data.push(
        SidebarKey::Trash,
        1,
        "Trash",
        Some(counts.trash),
        ICON_TRASH,
    );
    data
}

#[must_use]
pub fn filter_for(key: &SidebarKey) -> Option<Filter> {
    let filter = match key {
        SidebarKey::Header => return None,
        SidebarKey::All => Filter::default(),
        SidebarKey::Favorites => Filter {
            favorites_only: true,
            ..Filter::default()
        },
        SidebarKey::Kind(kind) => Filter {
            kind: Some(*kind),
            ..Filter::default()
        },
        SidebarKey::NoFolder => Filter {
            folder: Some(None),
            ..Filter::default()
        },
        SidebarKey::Folder(id) => Filter {
            folder: Some(Some(Arc::clone(id))),
            ..Filter::default()
        },
        SidebarKey::Organization(organization) | SidebarKey::Collection { organization, .. } => {
            Filter {
                organization: Some(Some(Arc::clone(organization))),
                ..Filter::default()
            }
        }
        SidebarKey::Trash => Filter {
            trash: true,
            ..Filter::default()
        },
    };
    Some(filter)
}

#[cfg(test)]
mod tests {
    use bwl_vault::model::ItemId;

    use super::*;

    fn item(
        kind: ItemKind,
        folder: Option<&str>,
        org: Option<&str>,
        favorite: bool,
    ) -> ItemSummary {
        ItemSummary {
            id: ItemId(Arc::from("x")),
            kind,
            name: Arc::from("n"),
            subtitle: Arc::from(""),
            favorite,
            folder_id: folder.map(Arc::from),
            organization_id: org.map(Arc::from),
            primary_uri: None,
            has_password: false,
            has_totp: false,
            reprompt: false,
            deleted: false,
            editable: true,
        }
    }

    fn folder(id: &str, name: &str) -> FolderView {
        FolderView {
            id: Arc::from(id),
            name: Arc::from(name),
        }
    }

    #[test]
    fn tally_counts_every_dimension() {
        let items = [
            item(ItemKind::Login, Some("f1"), None, true),
            item(ItemKind::Login, None, Some("o1"), false),
            item(ItemKind::Card, Some("f1"), None, false),
        ];
        let counts = Counts::tally(&items, 4);
        assert_eq!(counts.all, 3);
        assert_eq!(counts.favorites, 1);
        assert_eq!(counts.kinds.get(&ItemKind::Login), Some(&2));
        assert_eq!(counts.kinds.get(&ItemKind::Card), Some(&1));
        assert_eq!(counts.no_folder, 1);
        assert_eq!(counts.folders.get("f1"), Some(&2));
        assert_eq!(counts.organizations.get("o1"), Some(&1));
        assert_eq!(counts.trash, 4);
    }

    #[test]
    fn build_orders_sections_and_sorts_folders() {
        let items = [item(ItemKind::Login, Some("b"), Some("o"), false)];
        let counts = Counts::tally(&items, 0);
        let data = build(
            &[folder("b", "work"), folder("a", "Finance")],
            &[OrganizationView {
                id: Arc::from("o"),
                name: Arc::from("Acme"),
            }],
            &[CollectionView {
                id: Arc::from("c"),
                organization_id: Arc::from("o"),
                name: Arc::from("Engineering"),
                read_only: false,
            }],
            &counts,
        );
        let labels: Vec<String> = data
            .entries
            .iter()
            .map(|entry| entry.label.to_string())
            .collect();
        assert_eq!(
            labels,
            [
                "All items",
                "Favorites",
                "Types",
                "Logins",
                "Cards",
                "Identities",
                "Secure notes",
                "SSH keys",
                "Folders",
                "No folder",
                "Finance",
                "work",
                "Collections",
                "Acme",
                "Engineering",
                "",
                "Trash",
            ]
        );
        assert_eq!(data.keys.len(), data.entries.len());
        let work = data
            .index_of(&SidebarKey::Folder(Arc::from("b")))
            .expect("work");
        assert_eq!(data.entries[work].count, "1");
        assert_eq!(data.entries[work].kind, 2);
        let collection = data
            .entries
            .iter()
            .find(|entry| entry.label == "Engineering")
            .expect("c");
        assert_eq!(collection.kind, 4);
        assert_eq!(collection.count, "");
    }

    #[test]
    fn no_collections_section_without_organizations() {
        let data = build(&[], &[], &[], &Counts::default());
        assert!(
            data.entries
                .iter()
                .all(|entry| entry.label != "Collections")
        );
    }

    #[test]
    fn filters_per_key() {
        assert_eq!(filter_for(&SidebarKey::Header), None);
        assert_eq!(filter_for(&SidebarKey::All), Some(Filter::default()));
        assert!(
            filter_for(&SidebarKey::Favorites)
                .expect("f")
                .favorites_only
        );
        assert_eq!(
            filter_for(&SidebarKey::Kind(ItemKind::Card))
                .expect("k")
                .kind,
            Some(ItemKind::Card)
        );
        assert_eq!(
            filter_for(&SidebarKey::NoFolder).expect("n").folder,
            Some(None)
        );
        assert_eq!(
            filter_for(&SidebarKey::Folder(Arc::from("f")))
                .expect("f")
                .folder,
            Some(Some(Arc::from("f")))
        );
        let collection = SidebarKey::Collection {
            organization: Arc::from("o"),
            id: Arc::from("c"),
        };
        assert_eq!(
            filter_for(&collection).expect("c").organization,
            Some(Some(Arc::from("o")))
        );
        assert!(filter_for(&SidebarKey::Trash).expect("t").trash);
    }
}
