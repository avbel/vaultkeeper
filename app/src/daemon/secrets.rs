//! The daemon's token store. On macOS this is the login keychain (service `vaultkeeper`); on
//! Windows, sealed files under the data directory wrapped in DPAPI (windows-support.md §4.1); on
//! Linux, the same sealed files without a wrapper until systemd-creds arrives (linux-plan.md 2f).
//! The vault's key names start with the user id, so `delete_all_for(user_id)` removes every item
//! of that account on log out.

use std::{path::Path, sync::Arc};

use vk_vault::{SecretStore, SecretStoreError};
use zeroize::Zeroizing;

#[cfg(windows)]
use vk_vault::BlobWrapper;
#[cfg(any(windows, target_os = "linux", test))]
use vk_vault::SealedFileStore;

/// `prefix` namespaces the item names; production uses none, tests a unique one per run.
pub struct KeychainStore {
    prefix: String,
}

impl KeychainStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            prefix: String::new(),
        }
    }

    #[must_use]
    pub const fn with_prefix(prefix: String) -> Self {
        Self { prefix }
    }

    fn account(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }
}

impl Default for KeychainStore {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::needless_pass_by_value)] // shaped for `map_err`
fn store_error(error: vk_platform::Error) -> SecretStoreError {
    SecretStoreError::other(error.to_string())
}

impl SecretStore for KeychainStore {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
        vk_platform::keychain::get(&self.account(key)).map_err(store_error)
    }

    fn set(&self, key: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        vk_platform::keychain::set(&self.account(key), secret).map_err(store_error)
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        vk_platform::keychain::delete(&self.account(key)).map_err(store_error)
    }

    fn delete_all_for(&self, prefix: &str) -> Result<usize, SecretStoreError> {
        vk_platform::keychain::delete_all_for(&self.account(prefix)).map_err(store_error)
    }
}

/// Builds the token store the daemon injects. macOS keeps the login keychain; Windows and Linux
/// keep sealed files under `data_dir` written with the platform's atomic write, DPAPI-wrapped on
/// Windows.
#[must_use]
pub fn open(data_dir: &Path, keychain_prefix: Option<&str>) -> Arc<dyn SecretStore> {
    #[cfg(target_os = "macos")]
    {
        let _ = data_dir;
        match keychain_prefix {
            Some(prefix) => Arc::new(KeychainStore::with_prefix(prefix.to_owned())),
            None => Arc::new(KeychainStore::new()),
        }
    }
    #[cfg(windows)]
    {
        let _ = keychain_prefix;
        Arc::new(sealed_store(data_dir).with_wrapper(Arc::new(DpapiWrapper)))
    }
    #[cfg(target_os = "linux")]
    {
        let _ = keychain_prefix;
        Arc::new(sealed_store(data_dir))
    }
}

/// Portable, so the macOS tests exercise the Linux store as it is configured in production.
#[cfg(any(windows, target_os = "linux", test))]
fn sealed_store(data_dir: &Path) -> SealedFileStore {
    SealedFileStore::new(data_dir, vk_platform::fs::write_private_atomic)
}

#[cfg(windows)]
const DPAPI_ENTROPY_PREFIX: &[u8] = b"vaultkeeper dpapi v1:";

/// DPAPI with an entropy that names the account, so generic DPAPI tools (empty entropy) cannot
/// read our blobs. The entropy is public, like the account id; only the machine binding is secret.
#[cfg(windows)]
pub struct DpapiWrapper;

#[cfg(windows)]
impl BlobWrapper for DpapiWrapper {
    fn wrap(&self, user_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        vk_platform::dpapi::protect(plaintext, &entropy(user_id))
            .map_err(|error| dpapi_error(&error))
    }

    fn unwrap(&self, user_id: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
        vk_platform::dpapi::unprotect(blob, &entropy(user_id)).map_err(|error| {
            if is_definitive_dpapi_failure(&error) {
                SecretStoreError::undecryptable()
            } else {
                dpapi_error(&error)
            }
        })
    }
}

/// Only these codes mean the blob can never be opened again (corrupt, or bound to another
/// profile or machine). Anything else may be transient, and an undecryptable answer deletes the
/// refresh token.
#[cfg(windows)]
fn is_definitive_dpapi_failure(error: &std::io::Error) -> bool {
    const ERROR_INVALID_DATA: i32 = 13;
    const NTE_BAD_DATA: i32 = 0x8009_0005_u32.cast_signed();
    const NTE_BAD_KEY_STATE: i32 = 0x8009_000B_u32.cast_signed();
    matches!(
        error.raw_os_error(),
        Some(ERROR_INVALID_DATA | NTE_BAD_DATA | NTE_BAD_KEY_STATE)
    )
}

#[cfg(windows)]
fn entropy(user_id: &str) -> Vec<u8> {
    let mut entropy = Vec::with_capacity(DPAPI_ENTROPY_PREFIX.len() + user_id.len());
    entropy.extend_from_slice(DPAPI_ENTROPY_PREFIX);
    entropy.extend_from_slice(user_id.as_bytes());
    entropy
}

#[cfg(windows)]
fn dpapi_error(error: &std::io::Error) -> SecretStoreError {
    SecretStoreError::other(error.to_string())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Unique per run, so leftovers of a crashed run (owned by an older binary, whose items would
    /// make the keychain prompt) are never read. Items written and read by this test binary do
    /// not prompt while the login keychain is unlocked.
    fn store() -> KeychainStore {
        KeychainStore::with_prefix(format!(
            "vaultkeeper-app-test.{}.{}.",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ))
    }

    #[test]
    fn round_trip_and_account_wipe() {
        let store = store();
        let user = "3bef05d6-9070-48b4-b320-a5d425eec9fd";
        let other = "9d1c3e2a-0000-4000-8000-000000000001";
        assert!(
            store
                .get(&format!("{user}.refresh_token"))
                .expect("get")
                .is_none()
        );
        store
            .set(&format!("{user}.refresh_token"), b"refresh")
            .expect("set");
        store
            .set(&format!("{user}.two_factor_remember"), b"remember")
            .expect("set");
        store
            .set(&format!("{other}.refresh_token"), b"keep")
            .expect("set");
        assert_eq!(
            store
                .get(&format!("{user}.refresh_token"))
                .expect("get")
                .as_deref()
                .map(Vec::as_slice),
            Some(&b"refresh"[..])
        );

        assert_eq!(store.delete_all_for(user).expect("wipe"), 2);
        assert!(
            store
                .get(&format!("{user}.refresh_token"))
                .expect("get")
                .is_none()
        );
        assert!(
            store
                .get(&format!("{other}.refresh_token"))
                .expect("get")
                .is_some()
        );
        store
            .delete(&format!("{other}.refresh_token"))
            .expect("cleanup");
        store
            .delete(&format!("{other}.refresh_token"))
            .expect("deleting a missing item succeeds");
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    const USER: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";
    const OTHER: &str = "9d1c3e2a-0000-4000-8000-000000000001";

    #[test]
    fn entropy_names_the_account() {
        assert!(entropy(USER).starts_with(DPAPI_ENTROPY_PREFIX));
        assert_eq!(entropy(USER), entropy(USER));
        assert_ne!(entropy(USER), entropy(OTHER));
    }

    #[test]
    fn dpapi_wrapper_round_trips_and_binds_to_the_account() {
        let wrapper = DpapiWrapper;
        let blob = wrapper.wrap(USER, b"refresh token").expect("wrap");
        assert_ne!(blob, b"refresh token");
        let plaintext = wrapper.unwrap(USER, &blob).expect("unwrap");
        assert_eq!(plaintext.as_slice(), b"refresh token");

        let wrong = wrapper.unwrap(OTHER, &blob).expect_err("another account");
        assert!(wrong.is_undecryptable(), "{wrong:?}");
    }
}

#[cfg(test)]
mod sealed_tests {
    use super::*;

    #[test]
    fn unwrapped_sealed_store_round_trips_and_wipes_one_account() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = sealed_store(dir.path());
        let user = "3bef05d6-9070-48b4-b320-a5d425eec9fd";
        let other = "9d1c3e2a-0000-4000-8000-000000000001";
        // The daemon creates account dirs with its layout; the store only writes into them.
        for id in [user, other] {
            std::fs::create_dir_all(dir.path().join("accounts").join(id)).expect("account dir");
        }
        store.provide_key(user, &[7; 64]).expect("key");
        store.provide_key(other, &[9; 64]).expect("key");
        store
            .set(&format!("{user}.refresh_token"), b"refresh")
            .expect("set");
        store
            .set(&format!("{other}.refresh_token"), b"keep")
            .expect("set");
        assert_eq!(
            store
                .get(&format!("{user}.refresh_token"))
                .expect("get")
                .as_deref()
                .map(Vec::as_slice),
            Some(&b"refresh"[..])
        );
        store.delete_all_for(user).expect("wipe");
        assert!(
            store
                .get(&format!("{user}.refresh_token"))
                .expect("get")
                .is_none()
        );
        assert!(
            store
                .get(&format!("{other}.refresh_token"))
                .expect("get")
                .is_some()
        );
    }
}
