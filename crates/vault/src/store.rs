//! On-disk cache: `accounts.json` (MRU order) and per account `accounts/<user_id>/account.json`
//! (server, email, KDF, protected keys, settings) plus `vault.json` (the sync response, still
//! encrypted). Files are written atomically (temp file + rename) with mode 0600, directories 0700.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, PoisonError},
};

use bwl_api::models::{PreloginResponse, SyncResponse};
use bwl_crypto::Kdf;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Error, Result};

const ACCOUNTS_FILE: &str = "accounts.json";
const ACCOUNTS_DIR: &str = "accounts";
const ACCOUNT_FILE: &str = "account.json";
const VAULT_FILE: &str = "vault.json";
const TEMP_DIR: &str = "tmp";
/// `vault.json` layout version, stored as `cacheFormat`. 2: ciphers keep the properties the
/// models don't name (passkeys, `archivedDate`); a file without it predates that and lost them.
pub(crate) const CACHE_FORMAT: u32 = 2;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccountsIndex {
    /// Most recently used first; the first one is active after a restart.
    #[serde(default)]
    pub accounts: Vec<IndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IndexEntry {
    pub id: String,
    pub server: Url,
    pub email: String,
}

impl AccountsIndex {
    pub(crate) fn touch(&mut self, entry: IndexEntry) {
        self.accounts.retain(|known| known.id != entry.id);
        self.accounts.insert(0, entry);
    }

    pub(crate) fn remove(&mut self, id: &str) {
        self.accounts.retain(|known| known.id != id);
    }

    pub(crate) fn find(&self, id: &str) -> Option<&IndexEntry> {
        self.accounts.iter().find(|known| known.id == id)
    }

    pub(crate) fn find_by_login(&self, server: &Url, email: &str) -> Option<&IndexEntry> {
        self.accounts.iter().find(|known| {
            same_server(&known.server, server) && known.email.eq_ignore_ascii_case(email.trim())
        })
    }
}

fn same_server(a: &Url, b: &Url) -> bool {
    a.origin() == b.origin() && a.path().trim_end_matches('/') == b.path().trim_end_matches('/')
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountRecord {
    pub id: String,
    pub server: Url,
    pub email: String,
    pub kdf: KdfRecord,
    /// EncString: user key wrapped by the stretched master key.
    pub key: String,
    /// EncString: PKCS#8 RSA private key wrapped by the user key.
    #[serde(default)]
    pub private_key: Option<String>,
    /// Device-independent preferences owned by the app; opaque to the vault.
    #[serde(default)]
    pub settings: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KdfRecord {
    pub kind: u8,
    pub iterations: u32,
    #[serde(default)]
    pub memory_mib: Option<u32>,
    #[serde(default)]
    pub parallelism: Option<u32>,
}

impl KdfRecord {
    pub(crate) fn from_prelogin(prelogin: &PreloginResponse) -> Self {
        Self {
            kind: prelogin.kdf,
            iterations: prelogin.kdf_iterations,
            memory_mib: prelogin.kdf_memory,
            parallelism: prelogin.kdf_parallelism,
        }
    }

    pub(crate) fn to_kdf(self) -> Result<Kdf> {
        Ok(Kdf::from_wire(
            self.kind,
            self.iterations,
            self.memory_mib,
            self.parallelism,
        )?)
    }
}

pub(crate) struct CachedVault {
    pub sync: SyncResponse,
    /// Written in [`CACHE_FORMAT`], so its ciphers are whole and safe to base an update on.
    pub complete: bool,
}

pub(crate) struct Store {
    root: PathBuf,
    /// Serializes every write and the account removal, so a late cache write can't land in a
    /// directory that a log out is deleting.
    writes: Mutex<()>,
}

impl Store {
    pub(crate) fn open(root: PathBuf) -> io::Result<Self> {
        create_private_dir(&root)?;
        create_private_dir(&root.join(ACCOUNTS_DIR))?;
        Ok(Self {
            root,
            writes: Mutex::new(()),
        })
    }

    pub(crate) fn lock_writes(&self) -> MutexGuard<'_, ()> {
        self.writes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The user id comes from the server, so it must be a UUID before it becomes a path segment.
    pub(crate) fn account_dir(&self, id: &str) -> Result<PathBuf> {
        uuid::Uuid::parse_str(id).map_err(|_| Error::protocol("account id is not a UUID"))?;
        Ok(self.root.join(ACCOUNTS_DIR).join(id))
    }

    pub(crate) fn load_index(&self) -> Result<AccountsIndex> {
        Ok(read_json(&self.root.join(ACCOUNTS_FILE))?.unwrap_or_default())
    }

    pub(crate) fn save_index(&self, index: &AccountsIndex) -> Result<()> {
        let bytes = serde_json::to_vec(index)?;
        let _writes = self.lock_writes();
        write_atomic(&self.root.join(ACCOUNTS_FILE), &bytes)?;
        Ok(())
    }

    pub(crate) fn load_account(&self, id: &str) -> Result<Option<AccountRecord>> {
        read_json(&self.account_dir(id)?.join(ACCOUNT_FILE))
    }

    /// Only a login creates the directory; later writes fail instead of recreating it.
    pub(crate) fn create_account(&self, record: &AccountRecord) -> Result<()> {
        let dir = self.account_dir(&record.id)?;
        let bytes = serde_json::to_vec(record)?;
        let _writes = self.lock_writes();
        create_private_dir(&dir)?;
        write_atomic(&dir.join(ACCOUNT_FILE), &bytes)?;
        Ok(())
    }

    pub(crate) fn save_account(&self, record: &AccountRecord) -> Result<()> {
        let dir = self.account_dir(&record.id)?;
        let bytes = serde_json::to_vec(record)?;
        let _writes = self.lock_writes();
        write_atomic(&dir.join(ACCOUNT_FILE), &bytes)?;
        Ok(())
    }

    pub(crate) fn load_vault(&self, id: &str) -> Result<Option<CachedVault>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Format {
            #[serde(default)]
            cache_format: u32,
        }

        let bytes = match fs::read(self.account_dir(id)?.join(VAULT_FILE)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let sync = serde_json::from_slice(&bytes)?;
        // A second pass that skips every value: cheaper than buffering the vault for a wrapper.
        let format: Format = serde_json::from_slice(&bytes)?;
        Ok(Some(CachedVault {
            sync,
            complete: format.cache_format >= CACHE_FORMAT,
        }))
    }

    /// Caller holds [`Store::lock_writes`] so the snapshot it serialized is the newest on disk.
    pub(crate) fn save_vault_locked(&self, id: &str, bytes: &[u8]) -> Result<()> {
        write_atomic(&self.account_dir(id)?.join(VAULT_FILE), bytes)?;
        Ok(())
    }

    pub(crate) fn remove_account(&self, id: &str) -> Result<()> {
        let dir = self.account_dir(id)?;
        let _writes = self.lock_writes();
        match fs::remove_dir_all(&dir) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }

    /// `accounts/<id>/tmp`, for attachment transfers; wiped with the account.
    pub(crate) fn temp_dir(&self, id: &str) -> Result<PathBuf> {
        let dir = self.account_dir(id)?;
        if !dir.is_dir() {
            return Err(Error::LoggedOut);
        }
        let temp = dir.join(TEMP_DIR);
        create_private_dir(&temp)?;
        Ok(temp)
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Writes next to the target and renames over it, so a crash leaves either the old or the new
/// file. The directory must already exist.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("cache path has no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("cache path has no file name"))?
        .to_string_lossy();
    let temp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = write_new_private(&temp, bytes).and_then(|()| fs::rename(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = private_options().open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    private_options().open(path)
}

#[cfg(unix)]
fn private_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    options
}

#[cfg(not(unix))]
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    // `create` leaves an existing directory's mode alone.
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("bwl-vault-test-{}", uuid::Uuid::new_v4().simple()))
    }

    const ID: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";

    fn record() -> AccountRecord {
        AccountRecord {
            id: ID.into(),
            server: Url::parse("https://vault.example.com").unwrap(),
            email: "a@example.com".into(),
            kdf: KdfRecord {
                kind: 0,
                iterations: 600_000,
                memory_mib: None,
                parallelism: None,
            },
            key: "2.a|b|c".into(),
            private_key: None,
            settings: serde_json::Value::Null,
        }
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn account_round_trip_with_private_modes() {
        let root = temp_root();
        let store = Store::open(root.clone()).unwrap();
        store.create_account(&record()).unwrap();
        let loaded = store.load_account(ID).unwrap().unwrap();
        assert_eq!(loaded.email, "a@example.com");
        assert_eq!(loaded.kdf.iterations, 600_000);

        #[cfg(unix)]
        {
            assert_eq!(mode(&root), 0o700);
            assert_eq!(mode(&root.join("accounts").join(ID)), 0o700);
            assert_eq!(
                mode(&root.join("accounts").join(ID).join("account.json")),
                0o600
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn later_writes_never_recreate_a_removed_account() {
        let root = temp_root();
        let store = Store::open(root.clone()).unwrap();
        store.create_account(&record()).unwrap();
        store.remove_account(ID).unwrap();
        store.remove_account(ID).unwrap();

        assert!(store.save_account(&record()).is_err());
        assert!(store.save_vault_locked(ID, b"{}").is_err());
        assert!(matches!(store.temp_dir(ID), Err(Error::LoggedOut)));
        assert!(!root.join("accounts").join(ID).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn non_uuid_ids_are_rejected_before_touching_the_disk() {
        let store = Store::open(temp_root()).unwrap();
        for id in ["../../etc", "", "a/b", "3bef05d6"] {
            assert!(store.account_dir(id).is_err(), "{id}");
        }
        fs::remove_dir_all(&store.root).unwrap();
    }

    #[test]
    fn a_vault_cache_without_the_current_format_is_reported_incomplete() {
        let root = temp_root();
        let store = Store::open(root.clone()).unwrap();
        store.create_account(&record()).unwrap();
        assert!(store.load_vault(ID).unwrap().is_none());
        let profile = r#""profile": {"id": "u1", "email": "a@example.com", "key": null}"#;

        store
            .save_vault_locked(ID, format!("{{{profile}}}").as_bytes())
            .unwrap();
        let old = store.load_vault(ID).unwrap().unwrap();
        assert!(!old.complete);
        assert_eq!(old.sync.profile.id, "u1");

        store
            .save_vault_locked(ID, format!(r#"{{"cacheFormat": 2, {profile}}}"#).as_bytes())
            .unwrap();
        assert!(store.load_vault(ID).unwrap().unwrap().complete);

        store.save_vault_locked(ID, b"{not json").unwrap();
        assert!(matches!(store.load_vault(ID), Err(Error::Cache(_))));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_files_read_as_none_and_garbage_as_cache_errors() {
        let root = temp_root();
        let store = Store::open(root.clone()).unwrap();
        assert!(store.load_account(ID).unwrap().is_none());
        assert_eq!(store.load_index().unwrap(), AccountsIndex::default());

        fs::write(root.join("accounts.json"), b"{not json").unwrap();
        assert!(matches!(store.load_index(), Err(Error::Cache(_))));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_write_replaces_content_and_leaves_no_temp_files() {
        let root = temp_root();
        let store = Store::open(root.clone()).unwrap();
        let path = root.join("file.json");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        let names: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| !name.to_ascii_lowercase().ends_with(".tmp")),
            "{names:?}"
        );
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
        assert!(write_atomic(&root.join("missing").join("x.json"), b"x").is_err());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn index_keeps_most_recent_first_and_matches_logins_loosely() {
        let entry = |id: &str, email: &str| IndexEntry {
            id: id.into(),
            server: Url::parse("https://vault.example.com/").unwrap(),
            email: email.into(),
        };
        let mut index = AccountsIndex::default();
        index.touch(entry("a", "a@example.com"));
        index.touch(entry("b", "b@example.com"));
        index.touch(entry("a", "a@example.com"));
        let ids: Vec<_> = index.accounts.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);

        let server = Url::parse("https://vault.example.com").unwrap();
        assert_eq!(
            index
                .find_by_login(&server, " B@Example.com")
                .map(|e| e.id.as_str()),
            Some("b")
        );
        let other = Url::parse("https://other.example.com").unwrap();
        assert!(index.find_by_login(&other, "b@example.com").is_none());

        index.remove("a");
        assert!(index.find("a").is_none());
        assert!(index.find("b").is_some());
    }

    #[test]
    fn kdf_record_converts_from_prelogin_and_validates() {
        let prelogin = PreloginResponse {
            kdf: 1,
            kdf_iterations: 3,
            kdf_memory: Some(64),
            kdf_parallelism: Some(4),
        };
        let record = KdfRecord::from_prelogin(&prelogin);
        assert!(matches!(record.to_kdf().unwrap(), Kdf::Argon2id { .. }));
        let broken = KdfRecord { kind: 7, ..record };
        assert!(matches!(broken.to_kdf(), Err(Error::Crypto(_))));
    }
}
