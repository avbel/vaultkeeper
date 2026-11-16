//! Where tokens live. The app backs [`SecretStore`] with the platform keychain; tests use
//! [`MemorySecretStore`]. Every key starts with the account's user id, so
//! [`SecretStore::delete_all_for`] with that id removes everything an account stored.

use std::{collections::BTreeMap, sync::Mutex};

use thiserror::Error;
use zeroize::Zeroizing;

/// How a [`SecretStore`] failed, so callers can tell a locked vault from a logged-out one and
/// from a token that the user key no longer opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretStoreErrorKind {
    Other,
    /// The sealed store has no key for this account (the vault is locked).
    Locked,
    /// A stored secret no longer decrypts because the user key rotated elsewhere.
    Undecryptable,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("secret store: {message}")]
pub struct SecretStoreError {
    message: String,
    kind: SecretStoreErrorKind,
}

impl SecretStoreError {
    #[must_use]
    pub fn other(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: SecretStoreErrorKind::Other,
        }
    }

    #[must_use]
    pub fn locked() -> Self {
        Self {
            message: "no key is loaded for this account".to_owned(),
            kind: SecretStoreErrorKind::Locked,
        }
    }

    #[must_use]
    pub fn undecryptable() -> Self {
        Self {
            message: "the stored secret cannot be decrypted; log in again".to_owned(),
            kind: SecretStoreErrorKind::Undecryptable,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> SecretStoreErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn is_locked(&self) -> bool {
        matches!(self.kind, SecretStoreErrorKind::Locked)
    }

    #[must_use]
    pub const fn is_undecryptable(&self) -> bool {
        matches!(self.kind, SecretStoreErrorKind::Undecryptable)
    }
}

impl From<String> for SecretStoreError {
    fn from(message: String) -> Self {
        Self::other(message)
    }
}

impl From<&str> for SecretStoreError {
    fn from(message: &str) -> Self {
        Self::other(message)
    }
}

pub trait SecretStore: Send + Sync + 'static {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError>;
    fn set(&self, key: &str, secret: &[u8]) -> Result<(), SecretStoreError>;
    /// Deleting a key that does not exist succeeds.
    fn delete(&self, key: &str) -> Result<(), SecretStoreError>;
    /// Deletes every key starting with `prefix` and returns how many were removed.
    fn delete_all_for(&self, prefix: &str) -> Result<usize, SecretStoreError>;

    /// Hands a store that seals secrets the user key as soon as it is available. The keychain has
    /// nothing to derive, so the default is a no-op.
    fn provide_key(&self, _user_id: &str, _user_key: &[u8]) -> Result<(), SecretStoreError> {
        Ok(())
    }

    /// Drops the seal key when the session zeroizes the user key; storing a secret afterwards
    /// must fail as [`SecretStoreErrorKind::Locked`] rather than look like a logged-out account.
    fn forget_key(&self, _user_id: &str) {}
}

pub(crate) fn refresh_token_key(user_id: &str) -> String {
    format!("{user_id}.refresh_token")
}

pub(crate) fn remember_token_key(user_id: &str) -> String {
    format!("{user_id}.two_factor_remember")
}

/// Process-local store for tests and for running without a keychain.
#[derive(Default)]
pub struct MemorySecretStore {
    items: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemorySecretStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stored key names, sorted.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Zeroizing<Vec<u8>>>> {
        self.items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl SecretStore for MemorySecretStore {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
        Ok(self.lock().get(key).cloned())
    }

    fn set(&self, key: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        self.lock()
            .insert(key.to_owned(), Zeroizing::new(secret.to_vec()));
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        self.lock().remove(key);
        Ok(())
    }

    fn delete_all_for(&self, prefix: &str) -> Result<usize, SecretStoreError> {
        let mut items = self.lock();
        let before = items.len();
        items.retain(|key, _| !key.starts_with(prefix));
        Ok(before - items.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_delete_round_trip() {
        let store = MemorySecretStore::new();
        assert!(store.get("a").unwrap().is_none());
        store.set("a", b"secret").unwrap();
        assert_eq!(
            store.get("a").unwrap().as_deref().map(Vec::as_slice),
            Some(&b"secret"[..])
        );
        store.set("a", b"other").unwrap();
        assert_eq!(
            store.get("a").unwrap().as_deref().map(Vec::as_slice),
            Some(&b"other"[..])
        );
        store.delete("a").unwrap();
        store.delete("a").unwrap();
        assert!(store.get("a").unwrap().is_none());
    }

    #[test]
    fn delete_all_for_removes_only_the_prefix() {
        let store = MemorySecretStore::new();
        let user = "3bef05d6-9070-48b4-b320-a5d425eec9fd";
        store.set(&refresh_token_key(user), b"r").unwrap();
        store.set(&remember_token_key(user), b"m").unwrap();
        store.set("other-user.refresh_token", b"x").unwrap();

        assert_eq!(store.delete_all_for(user).unwrap(), 2);
        assert_eq!(store.keys(), vec!["other-user.refresh_token".to_owned()]);
        assert_eq!(store.delete_all_for(user).unwrap(), 0);
    }

    #[test]
    fn key_names_start_with_the_user_id() {
        assert_eq!(refresh_token_key("u1"), "u1.refresh_token");
        assert_eq!(remember_token_key("u1"), "u1.two_factor_remember");
    }
}
