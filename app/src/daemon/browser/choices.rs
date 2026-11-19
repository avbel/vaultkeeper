//! The login the user picked for a site, kept per paired browser until log out. Only item ids
//! are stored; every use still goes through the vault's match, reprompt and Touch ID checks.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read as _},
    path::{Path, PathBuf},
};

use vk_vault::model::ItemId;

use crate::os::fs::write_private;

const MAX_STORE_BYTES: u64 = 1024 * 1024;
const MAX_ORIGINS_PER_KEY: usize = 256;
const MAX_KEYS: usize = 64;

type Choices = BTreeMap<String, BTreeMap<String, String>>;

/// Paired public key (base64) -> canonical origin -> item id. Writes go through to disk before
/// they show in memory, so what `get` returns is what a restart would load. A site beyond the
/// per-key limit is not remembered; the ones already stored are never evicted.
#[derive(Debug, Default)]
pub struct ChoiceStore {
    choices: Choices,
    path: PathBuf,
}

impl ChoiceStore {
    /// A missing, unreadable, corrupt or out-of-bounds file yields an empty store: remembering
    /// is a convenience and must not take browser integration down.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let choices = match read(path) {
            Ok(choices) => choices,
            Err(error) => {
                tracing::warn!(%error, "remembered browser logins dropped");
                Choices::new()
            }
        };
        Self {
            choices,
            path: path.to_path_buf(),
        }
    }

    #[must_use]
    pub fn get(&self, key: &str, origin: &str) -> Option<ItemId> {
        self.choices
            .get(key)?
            .get(origin)
            .map(|item| ItemId(item.as_str().into()))
    }

    pub fn set(&mut self, key: &str, origin: &str, item: &ItemId) -> io::Result<()> {
        if self.get(key, origin).as_ref() == Some(item) {
            return Ok(());
        }
        let mut next = self.choices.clone();
        if !next.contains_key(key) && next.len() >= MAX_KEYS {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "too many browsers with remembered logins",
            ));
        }
        let origins = next.entry(key.to_owned()).or_default();
        if !origins.contains_key(origin) && origins.len() >= MAX_ORIGINS_PER_KEY {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "too many remembered sites for this browser",
            ));
        }
        origins.insert(origin.to_owned(), item.0.to_string());
        self.write(&next)?;
        self.choices = next;
        Ok(())
    }

    /// Drops the browser's choices from memory even when the file cannot be updated, so a
    /// removed pairing is never answered from them again.
    pub fn forget_key(&mut self, key: &str) -> io::Result<()> {
        if self.choices.remove(key).is_none() {
            return Ok(());
        }
        self.write(&self.choices)
    }

    /// Keeps only the browsers still paired.
    pub fn retain_keys(&mut self, paired: &[String]) -> io::Result<()> {
        let before = self.choices.len();
        self.choices.retain(|key, _| paired.contains(key));
        if self.choices.len() == before {
            return Ok(());
        }
        self.write(&self.choices)
    }

    /// Forgets everything, in memory first and then on disk.
    pub fn clear(&mut self) -> io::Result<()> {
        let had_any = !self.choices.is_empty();
        self.choices.clear();
        if !had_any && !self.path.exists() {
            return Ok(());
        }
        self.write(&self.choices)
    }

    fn write(&self, choices: &Choices) -> io::Result<()> {
        if choices.is_empty() {
            return match fs::remove_file(&self.path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
                _ => Ok(()),
            };
        }
        let data = serde_json::to_vec(choices).map_err(io::Error::other)?;
        if data.len() as u64 > MAX_STORE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "remembered logins too large",
            ));
        }
        write_private(&self.path, &data)
    }
}

fn read(path: &Path) -> io::Result<Choices> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Choices::new()),
        Err(error) => return Err(error),
    };
    let mut data = Vec::new();
    file.take(MAX_STORE_BYTES + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_STORE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    let choices: Choices = serde_json::from_slice(&data).map_err(io::Error::other)?;
    let within_bounds = choices.len() <= MAX_KEYS
        && choices
            .values()
            .all(|origins| origins.len() <= MAX_ORIGINS_PER_KEY);
    if !within_bounds {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many entries",
        ));
    }
    Ok(choices)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "key-a";
    const OTHER: &str = "key-b";
    const SITE: &str = "https://example.com";

    fn item(id: &str) -> ItemId {
        ItemId(id.into())
    }

    fn path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("browser-choices.json")
    }

    #[test]
    fn a_choice_survives_a_reload_of_the_file() {
        let dir = tempfile::tempdir().expect("directory");
        let mut store = ChoiceStore::load(&path(&dir));
        assert_eq!(store.get(KEY, SITE), None);
        store.set(KEY, SITE, &item("login-1")).expect("set");
        assert_eq!(store.get(KEY, SITE), Some(item("login-1")));
        let reloaded = ChoiceStore::load(&path(&dir));
        assert_eq!(reloaded.get(KEY, SITE), Some(item("login-1")));
        assert_eq!(reloaded.get(OTHER, SITE), None);
        assert_eq!(reloaded.get(KEY, "https://other.test"), None);
    }

    #[test]
    fn a_new_pick_replaces_the_old_one() {
        let dir = tempfile::tempdir().expect("directory");
        let mut store = ChoiceStore::load(&path(&dir));
        store.set(KEY, SITE, &item("login-1")).expect("first");
        store.set(KEY, SITE, &item("login-2")).expect("second");
        assert_eq!(
            ChoiceStore::load(&path(&dir)).get(KEY, SITE),
            Some(item("login-2"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("directory");
        let mut store = ChoiceStore::load(&path(&dir));
        store.set(KEY, SITE, &item("login-1")).expect("set");
        let mode = fs::metadata(path(&dir))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn the_257th_site_of_a_browser_is_refused_and_the_stored_ones_stay() {
        let dir = tempfile::tempdir().expect("directory");
        let mut store = ChoiceStore::load(&path(&dir));
        for index in 0..256 {
            store
                .set(KEY, &format!("https://site{index}.test"), &item("login"))
                .expect("within the limit");
        }
        let refused = store
            .set(KEY, "https://site256.test", &item("login"))
            .expect_err("over the limit");
        assert_eq!(refused.kind(), io::ErrorKind::StorageFull);
        assert_eq!(store.get(KEY, "https://site256.test"), None);
        assert_eq!(store.get(KEY, "https://site0.test"), Some(item("login")));
        store
            .set(KEY, "https://site0.test", &item("changed"))
            .expect("an existing site can still change");
        store
            .set(OTHER, "https://site256.test", &item("login"))
            .expect("the limit is per browser");
        assert_eq!(ChoiceStore::load(&path(&dir)).choices[KEY].len(), 256);
    }

    #[test]
    fn the_65th_browser_is_refused() {
        let dir = tempfile::tempdir().expect("directory");
        let mut store = ChoiceStore::load(&path(&dir));
        for index in 0..64 {
            store
                .set(&format!("key-{index}"), SITE, &item("login"))
                .expect("within the limit");
        }
        let refused = store
            .set("key-64", SITE, &item("login"))
            .expect_err("over the limit");
        assert_eq!(refused.kind(), io::ErrorKind::StorageFull);
        store
            .set("key-0", "https://more.test", &item("login"))
            .expect("a known browser can still add sites");
    }

    #[test]
    fn a_corrupt_file_starts_empty_and_is_replaced_by_the_next_choice() {
        let dir = tempfile::tempdir().expect("directory");
        fs::write(path(&dir), b"{not json").expect("corrupt");
        let mut store = ChoiceStore::load(&path(&dir));
        assert_eq!(store.get(KEY, SITE), None);
        store.set(KEY, SITE, &item("login-1")).expect("set");
        assert_eq!(
            ChoiceStore::load(&path(&dir)).get(KEY, SITE),
            Some(item("login-1"))
        );
    }

    #[test]
    fn an_oversized_file_starts_empty() {
        let dir = tempfile::tempdir().expect("directory");
        let size = usize::try_from(MAX_STORE_BYTES).expect("limit") + 1;
        fs::write(path(&dir), vec![b' '; size]).expect("oversized");
        assert_eq!(ChoiceStore::load(&path(&dir)).get(KEY, SITE), None);
    }

    #[test]
    fn a_file_over_the_bounds_starts_empty() {
        let dir = tempfile::tempdir().expect("directory");
        let origins: BTreeMap<String, String> = (0..257)
            .map(|index| (format!("https://site{index}.test"), "login".into()))
            .collect();
        let choices: Choices = [(KEY.to_owned(), origins)].into();
        fs::write(path(&dir), serde_json::to_vec(&choices).expect("json")).expect("write");
        assert_eq!(
            ChoiceStore::load(&path(&dir)).get(KEY, "https://site0.test"),
            None
        );
    }

    #[test]
    fn forgetting_a_browser_leaves_the_others() {
        let dir = tempfile::tempdir().expect("directory");
        let mut store = ChoiceStore::load(&path(&dir));
        store.set(KEY, SITE, &item("login-1")).expect("set");
        store.set(OTHER, SITE, &item("login-2")).expect("set");
        store.forget_key(KEY).expect("forget");
        assert_eq!(store.get(KEY, SITE), None);
        let reloaded = ChoiceStore::load(&path(&dir));
        assert_eq!(reloaded.get(KEY, SITE), None);
        assert_eq!(reloaded.get(OTHER, SITE), Some(item("login-2")));
        store.forget_key("unknown").expect("unknown browser");
    }

    #[test]
    fn clear_forgets_everything_and_removes_the_file() {
        let dir = tempfile::tempdir().expect("directory");
        let mut store = ChoiceStore::load(&path(&dir));
        store.set(KEY, SITE, &item("login-1")).expect("set");
        store.set(OTHER, SITE, &item("login-2")).expect("set");
        store.clear().expect("clear");
        assert_eq!(store.get(KEY, SITE), None);
        assert!(!path(&dir).exists());
        store.clear().expect("clearing an empty store");
        assert_eq!(ChoiceStore::load(&path(&dir)).get(OTHER, SITE), None);
    }

    #[test]
    fn browsers_that_are_no_longer_paired_are_dropped() {
        let dir = tempfile::tempdir().expect("directory");
        let mut store = ChoiceStore::load(&path(&dir));
        store.set(KEY, SITE, &item("login-1")).expect("set");
        store.set(OTHER, SITE, &item("login-2")).expect("set");
        store.retain_keys(&[OTHER.to_owned()]).expect("retain");
        assert_eq!(store.get(KEY, SITE), None);
        let reloaded = ChoiceStore::load(&path(&dir));
        assert_eq!(reloaded.get(KEY, SITE), None);
        assert_eq!(reloaded.get(OTHER, SITE), Some(item("login-2")));
        store.retain_keys(&[]).expect("retain nothing");
        assert!(!path(&dir).exists());
    }

    #[test]
    fn a_failed_write_changes_nothing_in_memory() {
        let dir = tempfile::tempdir().expect("directory");
        let mut store = ChoiceStore::load(&dir.path().join("missing").join("choices.json"));
        assert!(store.set(KEY, SITE, &item("login-1")).is_err());
        assert_eq!(store.get(KEY, SITE), None);
    }
}
