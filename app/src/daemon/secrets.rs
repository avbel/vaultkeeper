//! `SecretStore` over the login keychain (service `vaultkeeper`). The vault's key names start with
//! the user id, so `delete_all_for(user_id)` removes every item of that account on log out.

use vk_vault::{SecretStore, SecretStoreError};
use zeroize::Zeroizing;

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
    SecretStoreError(error.to_string())
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
