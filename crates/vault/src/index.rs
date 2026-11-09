//! The decrypted list: one [`Entry`] per cipher holding the encrypted cipher plus the few
//! decrypted fields the list and search need. Secrets stay encrypted until `reveal`/`draft`.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};

use bwl_api::models::{Cipher, Collection, Folder, Profile, SyncResponse, cipher_type};
use nucleo_matcher::{
    Config, Matcher, Utf32Str,
    pattern::{AtomKind, CaseMatching, Normalization, Pattern},
};
use serde::{Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    Result,
    keys::{KeyRing, decrypt_text},
    model::{CollectionView, Filter, FolderView, ItemId, ItemKind, ItemSummary, OrganizationView},
    store::CACHE_FORMAT,
};

/// Rank of fuzzy name matches and of fuzzy matches elsewhere; they follow every exact rank.
const FUZZY_NAME: u8 = 5;
const FUZZY_ANY: u8 = 6;

thread_local! {
    // The matcher keeps a scoring matrix that is expensive to allocate; one per searching thread.
    static MATCHER: RefCell<Matcher> = RefCell::new(Matcher::new(Config::DEFAULT));
}

/// Most-recently-used list length; older entries fall off.
pub(crate) const MRU_LIMIT: usize = 50;
const UNDECRYPTABLE: &str = "[cannot decrypt]";
const FIELD_SEPARATOR: char = '\0';

pub(crate) fn kind_of(raw: u8) -> ItemKind {
    match raw {
        cipher_type::LOGIN => ItemKind::Login,
        cipher_type::SECURE_NOTE => ItemKind::SecureNote,
        cipher_type::CARD => ItemKind::Card,
        cipher_type::IDENTITY => ItemKind::Identity,
        cipher_type::SSH_KEY => ItemKind::SshKey,
        other => ItemKind::Unsupported(other),
    }
}

pub(crate) struct Entry {
    pub cipher: Cipher,
    pub summary: ItemSummary,
    /// Lowercase `name \0 subtitle \0 uri \0 uri ...`, precomputed so search does no allocation.
    hay: Zeroizing<String>,
    name_end: usize,
    subtitle_end: usize,
}

impl Entry {
    fn new(cipher: Cipher, keys: &KeyRing, ids: &mut Interner) -> Self {
        let fields = list_fields(&cipher, keys).unwrap_or_else(|error| {
            tracing::warn!(%error, "could not decrypt a cipher for the list");
            ListFields {
                name: Zeroizing::new(UNDECRYPTABLE.to_owned()),
                subtitle: Zeroizing::default(),
                uris: Vec::new(),
            }
        });

        let capacity = fields.name.len()
            + fields.subtitle.len()
            + fields.uris.iter().map(|uri| uri.len() + 1).sum::<usize>()
            + 1;
        let mut hay = Zeroizing::new(String::with_capacity(capacity));
        push_lowercase(&mut hay, &fields.name);
        let name_end = hay.len();
        hay.push(FIELD_SEPARATOR);
        push_lowercase(&mut hay, &fields.subtitle);
        let subtitle_end = hay.len();
        for uri in &fields.uris {
            hay.push(FIELD_SEPARATOR);
            push_lowercase(&mut hay, uri);
        }

        let login = cipher.login.as_ref();
        let summary = ItemSummary {
            id: ItemId(Arc::from(cipher.id.as_str())),
            kind: kind_of(cipher.r#type),
            name: Arc::from(fields.name.as_str()),
            subtitle: Arc::from(fields.subtitle.as_str()),
            favorite: cipher.favorite,
            folder_id: cipher.folder_id.as_deref().map(|id| ids.get(id)),
            organization_id: cipher.organization_id.as_deref().map(|id| ids.get(id)),
            primary_uri: fields.uris.first().map(|uri| Arc::from(uri.as_str())),
            has_password: login.is_some_and(|login| is_set(login.password.as_deref())),
            has_totp: login.is_some_and(|login| is_set(login.totp.as_deref())),
            reprompt: cipher.reprompt == 1,
            deleted: cipher.deleted_date.is_some(),
            editable: cipher.edit,
        };
        Self {
            cipher,
            summary,
            hay,
            name_end,
            subtitle_end,
        }
    }

    fn name_key(&self) -> &str {
        &self.hay[..self.name_end]
    }

    /// 0 name prefix, 1 name, 2 subtitle, 3 URI, 4 every word somewhere; `None` = no match.
    fn rank(&self, query: &str, terms: &[&str]) -> Option<u8> {
        let name = self.name_key();
        if name.starts_with(query) {
            return Some(0);
        }
        if name.contains(query) {
            return Some(1);
        }
        if self.hay[self.name_end..self.subtitle_end].contains(query) {
            return Some(2);
        }
        if self.hay[self.subtitle_end..].contains(query) {
            return Some(3);
        }
        if terms.len() > 1 && terms.iter().all(|term| self.hay.contains(term)) {
            return Some(4);
        }
        None
    }

    /// Typos and abbreviations ("gthb" for GitHub): each query word must appear in order, gaps
    /// allowed, within the name or the subtitle (one field per word, never across fields, and
    /// never in URIs, where long strings would match almost anything). Ranked `FUZZY_NAME` when
    /// every word matched in the name. `chars` holds non-ASCII text decoded for the matcher; it
    /// is zeroized when the search ends.
    fn fuzzy_rank(
        &self,
        pattern: &Pattern,
        matcher: &mut Matcher,
        chars: &mut Vec<char>,
    ) -> Option<(u8, u32)> {
        let name = self.name_key();
        let subtitle = &self.hay[self.name_end + FIELD_SEPARATOR.len_utf8()..self.subtitle_end];
        let mut total = 0u32;
        let mut all_in_name = true;
        for atom in &pattern.atoms {
            let in_name = atom.score(Utf32Str::new(name, chars), matcher);
            let in_subtitle = atom.score(Utf32Str::new(subtitle, chars), matcher);
            let best = match (in_name, in_subtitle) {
                (Some(name), Some(subtitle)) if subtitle > name => {
                    all_in_name = false;
                    subtitle
                }
                (Some(name), _) => name,
                (None, Some(subtitle)) => {
                    all_in_name = false;
                    subtitle
                }
                (None, None) => return None,
            };
            total = total.saturating_add(u32::from(best));
        }
        Some((if all_in_name { FUZZY_NAME } else { FUZZY_ANY }, total))
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        wipe_shared(&mut self.summary.name);
        wipe_shared(&mut self.summary.subtitle);
        if let Some(uri) = &mut self.summary.primary_uri {
            wipe_shared(uri);
        }
    }
}

/// Zeroizes a decrypted string unless the UI still holds a clone; it drops its copies on lock.
fn wipe_shared(text: &mut Arc<str>) {
    if let Some(owned) = Arc::get_mut(text) {
        owned.zeroize();
    }
}

fn is_set(field: Option<&str>) -> bool {
    field.is_some_and(|text| !text.is_empty())
}

/// Per-character lowercase with the Greek final sigma folded into σ. `str::to_lowercase` picks
/// ς or σ from the word position, so the same word could lowercase differently in an item name
/// and in a query typed in capitals or cut off mid-word; folding makes both sides agree.
fn push_lowercase(out: &mut String, text: &str) {
    for c in text.chars() {
        out.extend(
            c.to_lowercase()
                .map(|lower| if lower == 'ς' { 'σ' } else { lower }),
        );
    }
}

fn fold_query(query: &str) -> String {
    let mut folded = String::with_capacity(query.len());
    push_lowercase(&mut folded, query.trim());
    folded
}

struct ListFields {
    name: Zeroizing<String>,
    subtitle: Zeroizing<String>,
    uris: Vec<Zeroizing<String>>,
}

fn list_fields(cipher: &Cipher, keys: &KeyRing) -> Result<ListFields> {
    let key = keys.cipher_key(cipher)?;
    let name = decrypt_text(cipher.name.as_deref(), &key)?;
    let mut uris = Vec::new();
    let subtitle = match cipher.r#type {
        cipher_type::LOGIN => match &cipher.login {
            Some(login) => {
                let list = login.uris.as_deref().unwrap_or_default();
                uris.reserve_exact(list.len());
                for uri in list {
                    let text = decrypt_text(uri.uri.as_deref(), &key)?;
                    if !text.is_empty() {
                        uris.push(text);
                    }
                }
                decrypt_text(login.username.as_deref(), &key)?
            }
            None => Zeroizing::default(),
        },
        cipher_type::CARD => match &cipher.card {
            Some(card) => {
                let brand = decrypt_text(card.brand.as_deref(), &key)?;
                let number = decrypt_text(card.number.as_deref(), &key)?;
                card_subtitle(&brand, &number)
            }
            None => Zeroizing::default(),
        },
        cipher_type::IDENTITY => match &cipher.identity {
            Some(identity) => {
                let email = decrypt_text(identity.email.as_deref(), &key)?;
                if email.is_empty() {
                    let first = decrypt_text(identity.first_name.as_deref(), &key)?;
                    let last = decrypt_text(identity.last_name.as_deref(), &key)?;
                    Zeroizing::new(format!("{} {}", *first, *last).trim().to_owned())
                } else {
                    email
                }
            }
            None => Zeroizing::default(),
        },
        cipher_type::SSH_KEY => match &cipher.ssh_key {
            Some(ssh) => decrypt_text(ssh.key_fingerprint.as_deref(), &key)?,
            None => Zeroizing::default(),
        },
        _ => Zeroizing::default(),
    };
    Ok(ListFields {
        name,
        subtitle,
        uris,
    })
}

/// "Visa *4242" — the brand and the last four digits, never more of the number.
fn card_subtitle(brand: &str, number: &str) -> Zeroizing<String> {
    let digits = number.chars().count();
    let last4: String = number.chars().skip(digits.saturating_sub(4)).collect();
    let last4 = Zeroizing::new(last4);
    Zeroizing::new(match (brand.is_empty(), last4.is_empty()) {
        (_, true) => brand.to_owned(),
        (true, false) => format!("*{}", *last4),
        (false, false) => format!("{brand} *{}", *last4),
    })
}

/// Shares one `Arc<str>` per folder / organization id across all rows.
#[derive(Default)]
struct Interner(HashMap<String, Arc<str>>);

impl Interner {
    fn get(&mut self, id: &str) -> Arc<str> {
        if let Some(shared) = self.0.get(id) {
            return Arc::clone(shared);
        }
        let shared: Arc<str> = Arc::from(id);
        self.0.insert(id.to_owned(), Arc::clone(&shared));
        shared
    }
}

pub(crate) struct VaultData {
    pub profile: Profile,
    folders: Vec<Folder>,
    folder_views: Vec<FolderView>,
    collections: Vec<Collection>,
    collection_views: Vec<CollectionView>,
    org_views: Vec<OrganizationView>,
    /// Sorted by lowercase name.
    entries: Vec<Entry>,
    by_id: HashMap<Arc<str>, usize>,
    /// False for a cache older than [`CACHE_FORMAT`]: its ciphers lack what the models don't
    /// name, and an update built from one would delete that on the server.
    complete: bool,
}

impl VaultData {
    pub(crate) fn empty(profile: Profile) -> Self {
        Self {
            profile,
            folders: Vec::new(),
            folder_views: Vec::new(),
            collections: Vec::new(),
            collection_views: Vec::new(),
            org_views: Vec::new(),
            entries: Vec::new(),
            by_id: HashMap::new(),
            complete: true,
        }
    }

    pub(crate) fn build(sync: SyncResponse, keys: &KeyRing) -> Self {
        let SyncResponse {
            profile,
            folders,
            collections,
            ciphers,
        } = sync;
        let mut ids = Interner::default();

        let mut folder_views: Vec<FolderView> = folders
            .iter()
            .map(|folder| folder_view(folder, keys, &mut ids))
            .collect();
        sort_by_name(&mut folder_views, |view| &view.name);

        let org_views: Vec<OrganizationView> = profile
            .organizations
            .iter()
            .map(|org| OrganizationView {
                id: ids.get(&org.id),
                name: Arc::from(org.name.as_str()),
            })
            .collect();

        let mut collection_views: Vec<CollectionView> = collections
            .iter()
            .map(|collection| collection_view(collection, keys, &mut ids))
            .collect();
        sort_by_name(&mut collection_views, |view| &view.name);

        let mut entries: Vec<Entry> = ciphers
            .into_iter()
            .map(|cipher| Entry::new(cipher, keys, &mut ids))
            .collect();
        entries.sort_by(|a, b| a.name_key().cmp(b.name_key()));

        let mut data = Self {
            profile,
            folders,
            folder_views,
            collections,
            collection_views,
            org_views,
            entries,
            by_id: HashMap::new(),
            complete: true,
        };
        data.reindex();
        data
    }

    #[must_use]
    pub(crate) fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self
    }

    pub(crate) const fn is_complete(&self) -> bool {
        self.complete
    }

    fn reindex(&mut self) {
        self.by_id.clear();
        self.by_id.reserve(self.entries.len());
        for (position, entry) in self.entries.iter().enumerate() {
            self.by_id.insert(Arc::clone(&entry.summary.id.0), position);
        }
    }

    fn interner(&self) -> Interner {
        let mut ids = Interner::default();
        for view in &self.folder_views {
            ids.0.insert(view.id.to_string(), Arc::clone(&view.id));
        }
        for view in &self.org_views {
            ids.0.insert(view.id.to_string(), Arc::clone(&view.id));
        }
        ids
    }

    pub(crate) fn entry(&self, id: &str) -> Option<&Entry> {
        self.by_id.get(id).map(|&position| &self.entries[position])
    }

    pub(crate) fn upsert_cipher(&mut self, cipher: Cipher, keys: &KeyRing) {
        let mut ids = self.interner();
        let entry = Entry::new(cipher, keys, &mut ids);
        if let Some(position) = self.by_id.get(entry.summary.id.0.as_ref()).copied() {
            self.entries.remove(position);
        }
        let position = self
            .entries
            .partition_point(|known| known.name_key() <= entry.name_key());
        self.entries.insert(position, entry);
        self.reindex();
    }

    pub(crate) fn remove_cipher(&mut self, id: &str) -> bool {
        let Some(position) = self.by_id.get(id).copied() else {
            return false;
        };
        self.entries.remove(position);
        self.reindex();
        true
    }

    pub(crate) fn upsert_folder(&mut self, folder: Folder, keys: &KeyRing) {
        let mut ids = self.interner();
        let view = folder_view(&folder, keys, &mut ids);
        self.folders.retain(|known| known.id != folder.id);
        self.folder_views.retain(|known| *known.id != *folder.id);
        self.folders.push(folder);
        self.folder_views.push(view);
        sort_by_name(&mut self.folder_views, |view| &view.name);
    }

    /// The server moves the folder's items to "no folder"; mirror that until the next sync.
    pub(crate) fn remove_folder(&mut self, id: &str) {
        self.folders.retain(|known| known.id != id);
        self.folder_views.retain(|known| &*known.id != id);
        for entry in &mut self.entries {
            if entry.cipher.folder_id.as_deref() == Some(id) {
                entry.cipher.folder_id = None;
                entry.summary.folder_id = None;
            }
        }
    }

    pub(crate) fn has_folder(&self, id: &str) -> bool {
        self.folders.iter().any(|folder| folder.id == id)
    }

    pub(crate) fn folder_views(&self) -> Vec<FolderView> {
        self.folder_views.clone()
    }

    pub(crate) fn org_views(&self) -> Vec<OrganizationView> {
        self.org_views.clone()
    }

    pub(crate) fn collection_views(&self) -> Vec<CollectionView> {
        self.collection_views.clone()
    }

    pub(crate) fn search(
        &self,
        query: &str,
        filter: &Filter,
        mru: &VecDeque<ItemId>,
    ) -> Arc<[ItemSummary]> {
        let query = fold_query(query);
        if query.is_empty() {
            return self.recent_first(filter, mru);
        }
        let terms: Vec<&str> = query.split_whitespace().collect();
        let pattern = Pattern::new(
            &query,
            CaseMatching::Ignore,
            Normalization::Smart,
            AtomKind::Fuzzy,
        );
        let mut chars = Zeroizing::new(Vec::new());
        let mut hits: Vec<(u8, u32, usize)> = MATCHER.with_borrow_mut(|matcher| {
            self.entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| passes(entry, filter))
                .filter_map(|(position, entry)| {
                    entry
                        .rank(&query, &terms)
                        .map(|rank| (rank, 0, position))
                        .or_else(|| {
                            entry
                                .fuzzy_rank(&pattern, matcher, &mut chars)
                                .map(|(rank, score)| (rank, score, position))
                        })
                })
                .collect()
        });
        // Stable, so rows of equal rank and score keep their name order.
        hits.sort_by_key(|&(rank, score, _)| (rank, std::cmp::Reverse(score)));
        hits.iter()
            .map(|&(_, _, position)| self.entries[position].summary.clone())
            .collect()
    }

    fn recent_first(&self, filter: &Filter, mru: &VecDeque<ItemId>) -> Arc<[ItemSummary]> {
        let mut seen = HashSet::with_capacity(mru.len());
        let mut out = Vec::with_capacity(self.entries.len());
        for id in mru {
            if let Some(&position) = self.by_id.get(id.0.as_ref()) {
                let entry = &self.entries[position];
                if passes(entry, filter) && seen.insert(position) {
                    out.push(entry.summary.clone());
                }
            }
        }
        for (position, entry) in self.entries.iter().enumerate() {
            if !seen.contains(&position) && passes(entry, filter) {
                out.push(entry.summary.clone());
            }
        }
        out.into()
    }

    /// Changes whenever the set of live SSH keys (or one of them) changes.
    pub(crate) fn ssh_digest(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        for entry in self.ssh_entries() {
            entry.cipher.id.hash(&mut hasher);
            entry.cipher.revision_date.hash(&mut hasher);
        }
        hasher.finish()
    }

    pub(crate) fn ssh_entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries
            .iter()
            .filter(|entry| entry.summary.kind == ItemKind::SshKey && !entry.summary.deleted)
    }

    /// The cached form: the sync response shape, every field still encrypted.
    pub(crate) fn to_json(&self) -> serde_json::Result<Vec<u8>> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Snapshot<'a> {
            cache_format: u32,
            profile: &'a Profile,
            folders: &'a [Folder],
            collections: &'a [Collection],
            ciphers: Ciphers<'a>,
        }

        struct Ciphers<'a>(&'a [Entry]);

        impl Serialize for Ciphers<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_seq(self.0.iter().map(|entry| &entry.cipher))
            }
        }

        serde_json::to_vec(&Snapshot {
            cache_format: if self.complete { CACHE_FORMAT } else { 0 },
            profile: &self.profile,
            folders: &self.folders,
            collections: &self.collections,
            ciphers: Ciphers(&self.entries),
        })
    }
}

impl Drop for VaultData {
    fn drop(&mut self) {
        for view in &mut self.folder_views {
            wipe_shared(&mut view.name);
        }
        for view in &mut self.collection_views {
            wipe_shared(&mut view.name);
        }
    }
}

fn folder_view(folder: &Folder, keys: &KeyRing, ids: &mut Interner) -> FolderView {
    let name = decrypt_text(Some(&folder.name), keys.user()).unwrap_or_else(|error| {
        tracing::warn!(%error, "could not decrypt a folder name");
        Zeroizing::new(UNDECRYPTABLE.to_owned())
    });
    FolderView {
        id: ids.get(&folder.id),
        name: Arc::from(name.as_str()),
    }
}

fn collection_view(collection: &Collection, keys: &KeyRing, ids: &mut Interner) -> CollectionView {
    let name = keys
        .org(&collection.organization_id)
        .ok_or(crate::Error::Crypto(bwl_crypto::Error::Decrypt))
        .and_then(|key| decrypt_text(Some(&collection.name), key))
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "could not decrypt a collection name");
            Zeroizing::new(UNDECRYPTABLE.to_owned())
        });
    CollectionView {
        id: Arc::from(collection.id.as_str()),
        organization_id: ids.get(&collection.organization_id),
        name: Arc::from(name.as_str()),
        read_only: collection.read_only,
    }
}

fn sort_by_name<T>(views: &mut [T], name: impl Fn(&T) -> &Arc<str>) {
    views.sort_by_cached_key(|view| name(view).to_lowercase());
}

fn passes(entry: &Entry, filter: &Filter) -> bool {
    let summary = &entry.summary;
    summary.deleted == filter.trash
        && filter.kind.is_none_or(|kind| summary.kind == kind)
        && filter
            .folder
            .as_ref()
            .is_none_or(|folder| summary.folder_id == *folder)
        && filter
            .organization
            .as_ref()
            .is_none_or(|organization| summary.organization_id == *organization)
        && (!filter.favorites_only || summary.favorite)
        && filter.collection.as_ref().is_none_or(|collection| {
            entry
                .cipher
                .collection_ids
                .iter()
                .any(|id| id.as_str() == collection.as_ref())
        })
}

pub(crate) fn record_recent(mru: &mut VecDeque<ItemId>, id: &ItemId) {
    mru.retain(|known| known != id);
    mru.push_front(id.clone());
    mru.truncate(MRU_LIMIT);
}

#[cfg(test)]
mod tests {
    use bwl_api::models::Cipher;

    use super::*;
    use crate::testutil::{self, card, folder, identity, legacy_login, login, note, ring, ssh};

    fn ids(found: &[ItemSummary]) -> Vec<&str> {
        found.iter().map(|item| &*item.id.0).collect()
    }

    fn sample(keys: &KeyRing) -> VaultData {
        let mut in_folder = note("n1", "Zebra notes", keys);
        in_folder.folder_id = Some("f1".into());
        in_folder.favorite = true;
        let mut trashed = note("n2", "Old note", keys);
        trashed.deleted_date = Some("2026-11-01T00:00:00.000Z".into());
        VaultData::build(
            testutil::sync(
                vec![
                    login("l1", "GitHub", "octocat", "pw1", keys),
                    in_folder,
                    card("c1", "Travel card", keys),
                    identity("i1", "Passport", "ada@example.com", keys),
                    ssh("s1", "Deploy key", keys),
                    trashed,
                    legacy_login("l2", "bank login", "pw2", keys),
                ],
                vec![
                    folder("f1", "Personal", keys),
                    folder("f2", "archive", keys),
                ],
            ),
            keys,
        )
    }

    #[test]
    fn summaries_carry_the_list_fields_only() {
        let keys = ring();
        let data = sample(&keys);
        let github = &data.entry("l1").unwrap().summary;
        assert_eq!(github.kind, ItemKind::Login);
        assert_eq!(&*github.name, "GitHub");
        assert_eq!(&*github.subtitle, "octocat");
        assert_eq!(
            github.primary_uri.as_deref(),
            Some("https://Example.com/login")
        );
        assert!(github.has_password && github.has_totp && github.editable);
        assert!(!github.deleted && !github.reprompt);

        assert_eq!(&*data.entry("c1").unwrap().summary.subtitle, "Visa *4242");
        assert_eq!(
            &*data.entry("i1").unwrap().summary.subtitle,
            "ada@example.com"
        );
        assert_eq!(
            &*data.entry("s1").unwrap().summary.subtitle,
            "SHA256:fingerprint"
        );
        assert_eq!(&*data.entry("n1").unwrap().summary.subtitle, "");
        assert_eq!(
            data.entry("n1").unwrap().summary.folder_id.as_deref(),
            Some("f1")
        );
        assert_eq!(&*data.entry("l2").unwrap().summary.subtitle, "legacy-user");
        assert!(data.entry("n2").unwrap().summary.deleted);
    }

    #[test]
    fn identity_without_email_shows_the_name_and_card_without_number_the_brand() {
        let keys = ring();
        let mut bare_card = card("c2", "Gift card", &keys);
        if let Some(card) = &mut bare_card.card {
            card.number = None;
        }
        let data = VaultData::build(
            testutil::sync(vec![identity("i2", "Me", "", &keys), bare_card], vec![]),
            &keys,
        );
        assert_eq!(&*data.entry("i2").unwrap().summary.subtitle, "Ada Lovelace");
        assert_eq!(&*data.entry("c2").unwrap().summary.subtitle, "Visa");
        assert_eq!(&*card_subtitle("", "42"), "*42");
    }

    #[test]
    fn undecryptable_ciphers_stay_listed_with_a_placeholder_name() {
        let keys = ring();
        let foreign = login("x1", "Secret", "u", "p", &ring());
        let unknown_org = Cipher {
            organization_id: Some("org-we-cannot-read".into()),
            ..note("x2", "Org note", &keys)
        };
        let data = VaultData::build(testutil::sync(vec![foreign, unknown_org], vec![]), &keys);
        assert_eq!(&*data.entry("x1").unwrap().summary.name, UNDECRYPTABLE);
        assert_eq!(&*data.entry("x2").unwrap().summary.name, UNDECRYPTABLE);
    }

    #[test]
    fn search_ranks_name_prefix_then_name_then_subtitle_then_uri() {
        let keys = ring();
        let data = VaultData::build(
            testutil::sync(
                vec![
                    login("a", "Example admin", "root", "p", &keys),
                    login("b", "My example", "root", "p", &keys),
                    login("c", "Mail", "example-user", "p", &keys),
                    login("d", "Router", "admin", "p", &keys),
                ],
                vec![],
            ),
            &keys,
        );
        let none = VecDeque::new();
        // "d" only matches through its URI (https://Example.com/login), like every login here.
        assert_eq!(
            ids(&data.search("EXAMPLE", &Filter::default(), &none)),
            ["a", "b", "c", "d"]
        );
        assert_eq!(
            ids(&data.search("  admin ", &Filter::default(), &none)),
            ["a", "d"]
        );
        assert_eq!(
            ids(&data.search("root my", &Filter::default(), &none)),
            ["b"]
        );
        assert_eq!(
            ids(&data.search("second.example.org", &Filter::default(), &none)).len(),
            4
        );
        assert!(
            data.search("nothing like this", &Filter::default(), &none)
                .is_empty()
        );
    }

    #[test]
    fn typos_and_abbreviations_match_fuzzily_after_every_exact_match() {
        let keys = ring();
        let data = VaultData::build(
            testutil::sync(
                vec![
                    login("hub", "GitHub", "octocat", "p", &keys),
                    login("lab", "GitLab", "gthb-bot", "p", &keys),
                    login("zur", "Zürich Bank", "anna", "p", &keys),
                    login("mail", "Mail", "gthb", "p", &keys),
                ],
                vec![],
            ),
            &keys,
        );
        let none = VecDeque::new();
        let find = |query: &str| ids(&data.search(query, &Filter::default(), &none)).join(",");
        // "lab" and "mail" hold "gthb" exactly in the username (rank 2, name order); "hub" only
        // fuzzily in its name, so it follows them.
        assert_eq!(find("gthb"), "lab,mail,hub");
        assert_eq!(find("gtlb"), "lab", "an abbreviation of the name");
        assert_eq!(find("zurich"), "zur", "accents fold");
        assert_eq!(find("git octo"), "hub", "every word must match");
        assert_eq!(find("qqq"), "", "no letters in order, no match");
    }

    #[test]
    fn greek_final_sigma_matches_in_any_case_and_position() {
        let keys = ring();
        let data = VaultData::build(
            testutil::sync(
                vec![
                    login("odysseus", "Οδυσσεύς", "u", "p", &keys),
                    login("caps", "ΟΔΥΣΣΕΥΣ", "u", "p", &keys),
                ],
                vec![],
            ),
            &keys,
        );
        let none = VecDeque::new();
        // A prefix typed in capitals: `str::to_lowercase` would end it in ς and miss both.
        let prefix = data.search("ΟΔΥΣ", &Filter::default(), &none);
        let mut both = ids(&prefix);
        both.sort_unstable();
        assert_eq!(both, ["caps", "odysseus"]);
        for query in ["ΟΔΥΣΣΕΎΣ", "Οδυσσεύς", "οδυσσεύσ"] {
            assert_eq!(
                ids(&data.search(query, &Filter::default(), &none)),
                ["odysseus"],
                "{query}"
            );
        }
        for query in ["ΟΔΥΣΣΕΥΣ", "οδυσσευς"] {
            assert_eq!(
                ids(&data.search(query, &Filter::default(), &none)),
                ["caps"],
                "{query}"
            );
        }
    }

    #[test]
    fn filters_select_kind_folder_organization_favorites_and_trash() {
        let keys = ring();
        let data = sample(&keys);
        let none = VecDeque::new();
        let search = |filter: Filter| {
            ids(&data.search("", &filter, &none))
                .iter()
                .map(|id| (*id).to_owned())
                .collect::<Vec<_>>()
        };

        assert_eq!(
            search(Filter::default()),
            ["l2", "s1", "l1", "i1", "c1", "n1"]
        );
        assert_eq!(
            search(Filter {
                kind: Some(ItemKind::Login),
                ..Filter::default()
            }),
            ["l2", "l1"]
        );
        assert_eq!(
            search(Filter {
                folder: Some(Some("f1".into())),
                ..Filter::default()
            }),
            ["n1"]
        );
        assert_eq!(
            search(Filter {
                folder: Some(None),
                ..Filter::default()
            })
            .len(),
            5
        );
        assert_eq!(
            search(Filter {
                organization: Some(None),
                ..Filter::default()
            })
            .len(),
            6
        );
        assert_eq!(
            search(Filter {
                organization: Some(Some("o1".into())),
                ..Filter::default()
            }),
            Vec::<String>::new()
        );
        assert_eq!(
            search(Filter {
                favorites_only: true,
                ..Filter::default()
            }),
            ["n1"]
        );
        assert_eq!(
            search(Filter {
                trash: true,
                ..Filter::default()
            }),
            ["n2"]
        );
    }

    #[test]
    fn collection_filter_matches_any_assigned_collection() {
        let keys = ring();
        let in_both = Cipher {
            collection_ids: vec!["col-a".into(), "col-b".into()],
            ..note("x1", "Shared runbook", &keys)
        };
        let in_b = Cipher {
            collection_ids: vec!["col-b".into()],
            ..login("x2", "Deploy", "ci", "pw", &keys)
        };
        let personal = note("x3", "Diary", &keys);
        let data = VaultData::build(testutil::sync(vec![in_both, in_b, personal], vec![]), &keys);
        let none = VecDeque::new();
        let in_collection = |id: &str, query: &str| {
            let filter = Filter {
                collection: Some(id.into()),
                ..Filter::default()
            };
            ids(&data.search(query, &filter, &none))
                .iter()
                .map(|id| (*id).to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(in_collection("col-a", ""), ["x1"]);
        assert_eq!(in_collection("col-b", ""), ["x2", "x1"]);
        assert_eq!(in_collection("col-b", "deploy"), ["x2"]);
        assert_eq!(in_collection("col-c", ""), Vec::<String>::new());
        assert_eq!(ids(&data.search("", &Filter::default(), &none)).len(), 3);
    }

    #[test]
    fn empty_query_lists_recent_items_first_and_the_list_is_bounded() {
        let keys = ring();
        let data = sample(&keys);
        let mut mru = VecDeque::new();
        record_recent(&mut mru, &ItemId("c1".into()));
        record_recent(&mut mru, &ItemId("n2".into()));
        record_recent(&mut mru, &ItemId("l1".into()));
        record_recent(&mut mru, &ItemId("c1".into()));
        let found = data.search("", &Filter::default(), &mru);
        // n2 is in the trash, so the default filter skips it even though it is recent.
        assert_eq!(ids(&found), ["c1", "l1", "l2", "s1", "i1", "n1"]);

        for n in 0..(MRU_LIMIT + 10) {
            record_recent(&mut mru, &ItemId(format!("id-{n}").into()));
        }
        assert_eq!(mru.len(), MRU_LIMIT);
        assert_eq!(&*mru[0].0, format!("id-{}", MRU_LIMIT + 9));
    }

    #[test]
    fn upsert_and_remove_keep_the_name_order_and_the_id_index() {
        let keys = ring();
        let mut data = sample(&keys);
        let none = VecDeque::new();
        data.upsert_cipher(note("n9", "aardvark", &keys), &keys);
        data.upsert_cipher(login("l1", "Zzz renamed", "octocat", "pw1", &keys), &keys);
        let order = ids(&data.search("", &Filter::default(), &none))
            .iter()
            .map(|id| (*id).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(order, ["n9", "l2", "s1", "i1", "c1", "n1", "l1"]);
        assert_eq!(&*data.entry("l1").unwrap().summary.name, "Zzz renamed");

        assert!(data.remove_cipher("n9"));
        assert!(!data.remove_cipher("n9"));
        assert!(data.entry("n9").is_none());
        assert_eq!(&*data.entry("c1").unwrap().summary.name, "Travel card");
    }

    #[test]
    fn folders_are_sorted_and_deleting_one_unfiles_its_items() {
        let keys = ring();
        let mut data = sample(&keys);
        let names = |data: &VaultData| {
            data.folder_views()
                .iter()
                .map(|f| f.name.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&data), ["archive", "Personal"]);
        data.upsert_folder(folder("f1", "Banking", &keys), &keys);
        assert_eq!(names(&data), ["archive", "Banking"]);
        assert!(data.has_folder("f1"));

        data.remove_folder("f1");
        assert_eq!(names(&data), ["archive"]);
        assert!(!data.has_folder("f1"));
        let entry = data.entry("n1").unwrap();
        assert_eq!(entry.summary.folder_id, None);
        assert_eq!(entry.cipher.folder_id, None);
    }

    #[test]
    fn folder_and_org_ids_are_shared_between_rows() {
        let keys = ring();
        let mut one = note("a", "A", &keys);
        one.folder_id = Some("f1".into());
        let mut two = note("b", "B", &keys);
        two.folder_id = Some("f1".into());
        let data = VaultData::build(
            testutil::sync(vec![one, two], vec![folder("f1", "F", &keys)]),
            &keys,
        );
        let a = data.entry("a").unwrap().summary.folder_id.clone().unwrap();
        let b = data.entry("b").unwrap().summary.folder_id.clone().unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn ssh_digest_tracks_live_ssh_keys_only() {
        let keys = ring();
        let mut data = sample(&keys);
        let before = data.ssh_digest();
        data.upsert_cipher(note("n5", "Unrelated", &keys), &keys);
        assert_eq!(data.ssh_digest(), before);
        data.upsert_cipher(ssh("s2", "Second key", &keys), &keys);
        let two_keys = data.ssh_digest();
        assert_ne!(two_keys, before);
        assert_eq!(data.ssh_entries().count(), 2);
        let mut trashed = ssh("s2", "Second key", &keys);
        trashed.deleted_date = Some("2026-11-08T00:00:00.000Z".into());
        data.upsert_cipher(trashed, &keys);
        assert_eq!(data.ssh_digest(), before);
    }

    #[test]
    fn cache_json_round_trips_as_a_sync_response() {
        let keys = ring();
        let data = sample(&keys);
        let json = data.to_json().unwrap();
        let parsed: SyncResponse = serde_json::from_slice(&json).unwrap();
        let format: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(format["cacheFormat"], CACHE_FORMAT);
        let stale = VaultData::build(testutil::sync(Vec::new(), Vec::new()), &keys)
            .with_complete(false)
            .to_json()
            .unwrap();
        let stale: serde_json::Value = serde_json::from_slice(&stale).unwrap();
        assert_eq!(stale["cacheFormat"], 0, "stays incomplete until a sync");
        assert_eq!(parsed.ciphers.len(), 7);
        assert_eq!(parsed.folders.len(), 2);
        assert_eq!(parsed.profile.id, testutil::USER_ID);
        let rebuilt = VaultData::build(parsed, &keys);
        assert_eq!(&*rebuilt.entry("l1").unwrap().summary.name, "GitHub");
        assert!(
            !String::from_utf8_lossy(&json).contains("octocat"),
            "the cache holds no plaintext"
        );
    }

    #[test]
    fn dropping_rows_zeroizes_strings_nobody_else_holds() {
        let keys = ring();
        let data = sample(&keys);
        let held = data.entry("l1").unwrap().summary.name.clone();
        drop(data);
        assert_eq!(
            &*held, "GitHub",
            "a clone the UI still holds stays readable"
        );

        let mut text: Arc<str> = Arc::from("secret");
        wipe_shared(&mut text);
        assert_eq!(&*text, "\0\0\0\0\0\0");
    }
}
