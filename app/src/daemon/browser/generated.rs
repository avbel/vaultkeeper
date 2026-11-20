//! Passwords generated for a page, kept until they are saved so a missed or failed save prompt
//! cannot lose them. Each one is sealed under the account's user key: it outlives a lock, but
//! only that account, unlocked, can read it. Memory only; a log out or account switch drops all.

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use subtle::ConstantTimeEq as _;
use vk_gen::generator::{generate_passphrase, generate_password};
use vk_ipc::browser::protocol::FieldLimits;
use vk_vault::{Vault, VaultService as _};
use zeroize::Zeroizing;

use super::dispatch::canonical_origin;
use crate::settings::GeneratorPrefs;

const LIFETIME: Duration = Duration::from_hours(24);
/// Per account. The oldest goes first, so a flood of requests cannot grow the list.
const MAX_ENTRIES: usize = 20;
const MIN_LENGTH: u16 = 5;
const MAX_LENGTH: u16 = 128;
const PASSPHRASE_TRIES: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedSummary {
    pub id: u64,
    pub origin: String,
    pub created: SystemTime,
}

struct Entry {
    id: u64,
    account: Arc<str>,
    /// Canonical origin (`https://host[:port]`).
    origin: String,
    created: SystemTime,
    sealed: String,
}

#[derive(Default)]
pub struct GeneratedStore {
    entries: Vec<Entry>,
    next_id: u64,
}

impl GeneratedStore {
    pub fn add(
        &mut self,
        account: Arc<str>,
        origin: String,
        sealed: String,
        now: SystemTime,
    ) -> u64 {
        self.expire(now);
        self.next_id += 1;
        self.entries.push(Entry {
            id: self.next_id,
            account,
            origin,
            created: now,
            sealed,
        });
        let account = &self.entries[self.entries.len() - 1].account;
        let held = self
            .entries
            .iter()
            .filter(|e| e.account == *account)
            .count();
        if held > MAX_ENTRIES {
            let account = Arc::clone(account);
            if let Some(oldest) = self.entries.iter().position(|e| e.account == account) {
                self.entries.remove(oldest);
            }
        }
        self.next_id
    }

    pub fn expire(&mut self, now: SystemTime) {
        self.entries.retain(|entry| {
            now.duration_since(entry.created)
                .is_ok_and(|age| age < LIFETIME)
        });
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn remove(&mut self, id: u64) {
        self.entries.retain(|entry| entry.id != id);
    }

    /// Newest first.
    #[must_use]
    pub fn list(&self, account: &str) -> Vec<GeneratedSummary> {
        self.entries
            .iter()
            .rev()
            .filter(|entry| &*entry.account == account)
            .map(|entry| GeneratedSummary {
                id: entry.id,
                origin: entry.origin.clone(),
                created: entry.created,
            })
            .collect()
    }

    #[must_use]
    pub fn has_origin(&self, account: &str, origin: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| &*entry.account == account && entry.origin == origin)
    }

    fn get(&self, account: &str, id: u64) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.id == id && &*entry.account == account)
    }
}

pub type SharedGenerated = Arc<Mutex<GeneratedStore>>;

fn lock(store: &Mutex<GeneratedStore>) -> std::sync::MutexGuard<'_, GeneratedStore> {
    store.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Seals and keeps `password` for `origin`. Fails when the vault is locked or logged out.
pub fn remember(
    vault: &Vault,
    store: &Mutex<GeneratedStore>,
    origin: &str,
    password: &str,
) -> vk_vault::Result<u64> {
    let (account, sealed) = vault.seal_local(password.as_bytes())?;
    Ok(lock(store).add(account, canonical_origin(origin), sealed, SystemTime::now()))
}

/// The entry generated for `origin` whose password is `password`, if any.
#[must_use]
pub fn find(
    vault: &Vault,
    store: &Mutex<GeneratedStore>,
    origin: &str,
    password: &str,
) -> Option<u64> {
    let account = vault.active_account_id()?;
    let origin = canonical_origin(origin);
    let candidates: Vec<(u64, String)> = {
        let mut store = lock(store);
        store.expire(SystemTime::now());
        store
            .entries
            .iter()
            .filter(|entry| entry.account == account && entry.origin == origin)
            .map(|entry| (entry.id, entry.sealed.clone()))
            .collect()
    };
    candidates.into_iter().find_map(|(id, sealed)| {
        let opened = vault.open_local(&account, &sealed).ok()?;
        bool::from(opened.as_slice().ct_eq(password.as_bytes())).then_some(id)
    })
}

/// The origin and password of entry `id` of the active account.
pub fn open(
    vault: &Vault,
    store: &Mutex<GeneratedStore>,
    id: u64,
) -> vk_vault::Result<(String, Zeroizing<String>)> {
    let account = vault
        .active_account_id()
        .ok_or(vk_vault::Error::LoggedOut)?;
    let (origin, sealed) = {
        let store = lock(store);
        let entry = store.get(&account, id).ok_or(vk_vault::Error::NotFound)?;
        (entry.origin.clone(), entry.sealed.clone())
    };
    let bytes = vault.open_local(&account, &sealed)?;
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| vk_vault::Error::NotFound)?;
    Ok((origin, Zeroizing::new(text)))
}

/// Seconds since the Unix epoch, for the UI.
#[must_use]
pub fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn host_of(origin: &str) -> String {
    url::Url::parse(origin)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| origin.to_owned())
}

/// Saves entry `id` as a new login for its page, with no username, and drops the entry.
pub async fn save_as_login(
    vault: &Vault,
    store: &Mutex<GeneratedStore>,
    id: u64,
) -> vk_vault::Result<vk_vault::model::ItemId> {
    let (origin, password) = open(vault, store, id)?;
    let draft = super::save::new_login(&host_of(&origin), &origin, "", &password);
    let item = vault.save(None, draft).await?;
    lock(store).remove(id);
    Ok(item)
}

/// The UI socket's view of the store. Nothing is listed while the vault is locked, so the
/// sites someone signed up to stay private too.
pub struct GeneratedHost {
    pub vault: Arc<Vault>,
    pub store: SharedGenerated,
}

impl vk_ipc::GeneratedHost for GeneratedHost {
    fn list(&self) -> Vec<vk_ipc::GeneratedDto> {
        if self.vault.browser_snapshot().is_err() {
            return Vec::new();
        }
        let Some(account) = self.vault.active_account_id() else {
            return Vec::new();
        };
        let mut store = lock(&self.store);
        store.expire(SystemTime::now());
        store
            .list(&account)
            .into_iter()
            .map(|entry| vk_ipc::GeneratedDto {
                id: entry.id,
                host: host_of(&entry.origin),
                created_unix: unix_secs(entry.created),
            })
            .collect()
    }

    fn reveal(&self, id: u64) -> Result<Zeroizing<String>, vk_ipc::dto::WireError> {
        open(&self.vault, &self.store, id)
            .map(|(_, password)| password)
            .map_err(|error| (&error).into())
    }

    fn save(&self, id: u64) -> vk_ipc::SaveFuture {
        let (vault, store) = (Arc::clone(&self.vault), Arc::clone(&self.store));
        Box::pin(async move {
            save_as_login(&vault, &store, id)
                .await
                .map(|item| item.0)
                .map_err(|error| (&error).into())
        })
    }

    fn forget(&self, id: u64) {
        lock(&self.store).remove(id);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FitError {
    /// The field cannot hold a strong password, or its limits contradict each other.
    Limits,
    Generator,
}

/// A password from the user's generator settings that the field accepts. A passphrase that does
/// not fit falls back to a password, and minimum digit or symbol counts give way to the length.
pub fn generate(
    prefs: &GeneratorPrefs,
    limits: FieldLimits,
) -> Result<Zeroizing<String>, FitError> {
    let min = limits.min_length.unwrap_or(0).max(MIN_LENGTH);
    let max = limits.max_length.unwrap_or(MAX_LENGTH).min(MAX_LENGTH);
    if min > max {
        return Err(FitError::Limits);
    }
    let fits = |value: &str| (usize::from(min)..=usize::from(max)).contains(&value.chars().count());
    if prefs.passphrase_mode {
        let options = prefs.passphrase_options();
        for _ in 0..PASSPHRASE_TRIES {
            let value = generate_passphrase(&options).map_err(|_| FitError::Generator)?;
            if fits(&value) {
                return Ok(value);
            }
        }
    }
    let mut options = prefs.password_options();
    let length = u16::from(options.length).clamp(min, max);
    options.length = u8::try_from(length).map_err(|_| FitError::Limits)?;
    generate_password(&options).or_else(|_| {
        options.min_numbers = options.min_numbers.min(1);
        options.min_special = options.min_special.min(1);
        generate_password(&options).map_err(|_| FitError::Generator)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(min: Option<u16>, max: Option<u16>) -> FieldLimits {
        FieldLimits {
            min_length: min,
            max_length: max,
        }
    }

    #[test]
    fn the_saved_length_is_used_when_the_field_allows_it() {
        let prefs = GeneratorPrefs {
            length: 20,
            ..GeneratorPrefs::default()
        };
        assert_eq!(
            generate(&prefs, limits(None, None)).expect("fits").len(),
            20
        );
        assert_eq!(
            generate(&prefs, limits(None, Some(12)))
                .expect("fits")
                .len(),
            12
        );
        assert_eq!(
            generate(&prefs, limits(Some(32), None))
                .expect("fits")
                .len(),
            32
        );
    }

    #[test]
    fn minimum_counts_give_way_to_a_short_field() {
        let prefs = GeneratorPrefs {
            length: 14,
            numbers: true,
            special: true,
            min_numbers: 4,
            min_special: 4,
            ..GeneratorPrefs::default()
        };
        assert_eq!(
            generate(&prefs, limits(None, Some(6))).expect("fits").len(),
            6
        );
    }

    #[test]
    fn a_passphrase_that_does_not_fit_becomes_a_password() {
        let prefs = GeneratorPrefs {
            passphrase_mode: true,
            words: 6,
            separator: "-".into(),
            ..GeneratorPrefs::default()
        };
        let value = generate(&prefs, limits(None, Some(10))).expect("fits");
        assert_eq!(value.len(), 10);
        assert!(!value.contains('-'));
        let long = generate(&prefs, limits(None, None)).expect("fits");
        assert_eq!(long.matches('-').count(), 5);
    }

    #[test]
    fn fields_too_short_or_contradictory_are_refused() {
        let prefs = GeneratorPrefs::default();
        assert_eq!(
            generate(&prefs, limits(None, Some(4))).expect_err("refused"),
            FitError::Limits
        );
        assert_eq!(
            generate(&prefs, limits(Some(20), Some(10))).expect_err("refused"),
            FitError::Limits
        );
    }

    fn summary_ids(store: &GeneratedStore, account: &str) -> Vec<u64> {
        store.list(account).iter().map(|s| s.id).collect()
    }

    #[test]
    fn the_oldest_entry_of_an_account_goes_when_it_is_full() {
        let mut store = GeneratedStore::default();
        let now = SystemTime::now();
        let other = store.add("b".into(), "https://b.com".into(), "s".into(), now);
        let first = store.add("a".into(), "https://a.com".into(), "s".into(), now);
        for _ in 1..MAX_ENTRIES {
            store.add("a".into(), "https://a.com".into(), "s".into(), now);
        }
        assert_eq!(store.list("a").len(), MAX_ENTRIES);
        let newest = store.add("a".into(), "https://a.com".into(), "s".into(), now);
        let ids = summary_ids(&store, "a");
        assert_eq!(ids.len(), MAX_ENTRIES);
        assert_eq!(ids[0], newest);
        assert!(!ids.contains(&first));
        assert_eq!(summary_ids(&store, "b"), [other]);
    }

    #[test]
    fn entries_expire_after_a_day_and_belong_to_one_account() {
        let mut store = GeneratedStore::default();
        let then = SystemTime::now();
        let id = store.add("a".into(), "https://a.com".into(), "s".into(), then);
        assert!(store.has_origin("a", "https://a.com"));
        assert!(!store.has_origin("b", "https://a.com"));
        assert!(store.get("b", id).is_none());
        store.expire(then + Duration::from_hours(23));
        assert_eq!(summary_ids(&store, "a"), [id]);
        store.expire(then + Duration::from_hours(24));
        assert_eq!(store.list("a").len(), 0);
    }
}
