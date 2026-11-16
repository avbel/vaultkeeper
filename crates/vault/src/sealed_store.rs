//! [`SecretStore`] for systems without a keychain: each token is a file sealed under a key
//! derived from the user key (linux-support.md §5.1). An optional [`BlobWrapper`] is applied
//! around the AES layer, so a copied disk plus a phished master password still cannot read the
//! token (DPAPI does that on Windows).
//!
//! Files live under `accounts/<user_id>/` next to the cache: `refresh_token.enc` is sealed and
//! `two_factor_remember.enc` is only wrapped, because it is read before login while no user key
//! exists. The layout is `"VKS1" ‖ version ‖ nonce[12] ‖ AES-256-GCM(k, nonce, aad, secret)` with
//! `k = HKDF-SHA256(ikm = user key, salt = SHA-256(user_id), info = "vaultkeeper secrets v1")`
//! and `aad = magic ‖ version ‖ name ‖ user_id`.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::{TryRng, rngs::SysRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::secrets::{SecretStore, SecretStoreError};

const ACCOUNTS_DIR: &str = "accounts";
const MAGIC: &[u8; 4] = b"VKS1";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = MAGIC.len() + 1 + NONCE_LEN;
const KDF_INFO: &[u8] = b"vaultkeeper secrets v1";
const REFRESH_TOKEN: &str = "refresh_token";
const REMEMBER_TOKEN: &str = "two_factor_remember";
/// The same rule as `layout.rs`: an account id is a plain path segment, never a path.
const MAX_USER_ID_LEN: usize = 64;

type WriteFn = Arc<dyn Fn(&Path, &[u8]) -> io::Result<()> + Send + Sync>;

/// Machine binding around a stored blob: DPAPI on Windows, absent elsewhere. `user_id` names the
/// account, so the wrapper can bind each blob to it (DPAPI's entropy) and not only to the machine.
pub trait BlobWrapper: Send + Sync + 'static {
    fn wrap(&self, user_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError>;
    fn unwrap(&self, user_id: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretStoreError>;
}

pub struct SealedFileStore {
    root: PathBuf,
    keys: Mutex<HashMap<String, Zeroizing<[u8; KEY_LEN]>>>,
    wrapper: Option<Arc<dyn BlobWrapper>>,
    atomic_write: WriteFn,
}

impl SealedFileStore {
    /// `root` is the data dir holding `accounts/`; `write` is the host's private atomic write.
    pub fn new<W>(root: impl Into<PathBuf>, write: W) -> Self
    where
        W: Fn(&Path, &[u8]) -> io::Result<()> + Send + Sync + 'static,
    {
        Self {
            root: root.into(),
            keys: Mutex::new(HashMap::new()),
            wrapper: None,
            atomic_write: Arc::new(write),
        }
    }

    #[must_use]
    pub fn with_wrapper(mut self, wrapper: Arc<dyn BlobWrapper>) -> Self {
        self.wrapper = Some(wrapper);
        self
    }

    /// Derives and keeps the seal key, which must happen as soon as the user key is available.
    pub fn provide_key(&self, user_id: &str, user_key: &[u8]) -> Result<(), SecretStoreError> {
        if !valid_user_id(user_id) {
            return Err(refused(user_id));
        }
        self.lock_keys()
            .insert(user_id.to_owned(), seal_key(user_id, user_key));
        Ok(())
    }

    /// Drops the seal key, so a later `get` of a sealed token reports [`SecretStoreErrorKind::Locked`]
    /// instead of looking logged out.
    pub fn forget_key(&self, user_id: &str) {
        self.lock_keys().remove(user_id);
    }

    fn lock_keys(&self) -> MutexGuard<'_, HashMap<String, Zeroizing<[u8; KEY_LEN]>>> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn key_for(&self, user_id: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretStoreError> {
        self.lock_keys()
            .get(user_id)
            .cloned()
            .ok_or_else(SecretStoreError::locked)
    }

    fn path(&self, user_id: &str, name: &str) -> PathBuf {
        self.root
            .join(ACCOUNTS_DIR)
            .join(user_id)
            .join(format!("{name}.enc"))
    }

    fn get_sealed(
        &self,
        user_id: &str,
        name: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
        // The key is checked before the file, so a locked store never looks like a logged-out one.
        let key = self.key_for(user_id)?;
        let Some(bytes) = read_optional(&self.path(user_id, name))? else {
            return Ok(None);
        };
        let (nonce, body) = split_sealed(bytes.as_slice())?;
        let ciphertext = self.unwrap(user_id, body)?;
        let aad = associated_data(user_id, name);
        Aes256Gcm::new(&(*key).into())
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map(Some)
            .map_err(|_| SecretStoreError::undecryptable())
    }

    fn get_wrapped(
        &self,
        user_id: &str,
        name: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
        let Some(bytes) = read_optional(&self.path(user_id, name))? else {
            return Ok(None);
        };
        self.unwrap(user_id, bytes.as_slice()).map(Some)
    }

    fn put_sealed(&self, user_id: &str, name: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        let key = self.key_for(user_id)?;
        let mut nonce = [0_u8; NONCE_LEN];
        SysRng.try_fill_bytes(&mut nonce).map_err(rng_error)?;
        let aad = associated_data(user_id, name);
        let ciphertext = Aes256Gcm::new(&(*key).into())
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| SecretStoreError::other("AES-GCM refused the secret"))?;
        let body = self.wrap(user_id, &ciphertext)?;
        let mut bytes = Vec::with_capacity(HEADER_LEN + body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&body);
        self.write_file(&self.path(user_id, name), &bytes)
    }

    fn put_wrapped(
        &self,
        user_id: &str,
        name: &str,
        secret: &[u8],
    ) -> Result<(), SecretStoreError> {
        let body = self.wrap(user_id, secret)?;
        self.write_file(&self.path(user_id, name), &body)
    }

    fn wrap(&self, user_id: &str, data: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        match &self.wrapper {
            Some(wrapper) => wrapper.wrap(user_id, data),
            None => Ok(data.to_vec()),
        }
    }

    fn unwrap(&self, user_id: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
        match &self.wrapper {
            Some(wrapper) => wrapper.unwrap(user_id, blob),
            None => Ok(Zeroizing::new(blob.to_vec())),
        }
    }

    fn write_file(&self, path: &Path, bytes: &[u8]) -> Result<(), SecretStoreError> {
        (self.atomic_write)(path, bytes).map_err(|error| SecretStoreError::other(error.to_string()))
    }
}

impl SecretStore for SealedFileStore {
    fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
        let (user_id, name) = parse_key(key)?;
        match name {
            SecretName::Refresh => self.get_sealed(user_id, name.file()),
            SecretName::Remember => self.get_wrapped(user_id, name.file()),
        }
    }

    fn set(&self, key: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        let (user_id, name) = parse_key(key)?;
        match name {
            SecretName::Refresh => self.put_sealed(user_id, name.file(), secret),
            SecretName::Remember => self.put_wrapped(user_id, name.file(), secret),
        }
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        let (user_id, name) = parse_key(key)?;
        match fs::remove_file(self.path(user_id, name.file())) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                Err(SecretStoreError::other(error.to_string()))
            }
            _ => Ok(()),
        }
    }

    fn delete_all_for(&self, user_id: &str) -> Result<usize, SecretStoreError> {
        if !valid_user_id(user_id) {
            return Err(refused(user_id));
        }
        let mut removed = 0;
        for name in [SecretName::Refresh, SecretName::Remember] {
            match fs::remove_file(self.path(user_id, name.file())) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(SecretStoreError::other(error.to_string())),
            }
        }
        Ok(removed)
    }

    fn provide_key(&self, user_id: &str, user_key: &[u8]) -> Result<(), SecretStoreError> {
        Self::provide_key(self, user_id, user_key)
    }

    fn forget_key(&self, user_id: &str) {
        Self::forget_key(self, user_id);
    }
}

#[derive(Clone, Copy)]
enum SecretName {
    Refresh,
    Remember,
}

impl SecretName {
    const fn file(self) -> &'static str {
        match self {
            Self::Refresh => REFRESH_TOKEN,
            Self::Remember => REMEMBER_TOKEN,
        }
    }
}

fn parse_key(key: &str) -> Result<(&str, SecretName), SecretStoreError> {
    let (user_id, name) = key.split_once('.').ok_or_else(|| refused(key))?;
    if !valid_user_id(user_id) {
        return Err(refused(key));
    }
    let name = if name == REFRESH_TOKEN {
        SecretName::Refresh
    } else if name == REMEMBER_TOKEN {
        SecretName::Remember
    } else {
        return Err(refused(key));
    };
    Ok((user_id, name))
}

fn valid_user_id(user_id: &str) -> bool {
    !user_id.is_empty()
        && user_id.len() <= MAX_USER_ID_LEN
        && user_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn refused(key: &str) -> SecretStoreError {
    SecretStoreError::other(format!("unexpected secret name {key:?}"))
}

fn seal_key(user_id: &str, user_key: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let salt = Sha256::digest(user_id.as_bytes());
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(&salt[..]), user_key)
        .expand(KDF_INFO, key.as_mut_slice())
        .expect("32 bytes is within the HKDF-SHA256 output limit");
    key
}

fn associated_data(user_id: &str, name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + 1 + name.len() + user_id.len());
    aad.extend_from_slice(MAGIC);
    aad.push(VERSION);
    aad.extend_from_slice(name.as_bytes());
    aad.extend_from_slice(user_id.as_bytes());
    aad
}

fn split_sealed(bytes: &[u8]) -> Result<([u8; NONCE_LEN], &[u8]), SecretStoreError> {
    if bytes.len() < HEADER_LEN + TAG_LEN
        || !bytes.starts_with(MAGIC)
        || bytes.get(MAGIC.len()) != Some(&VERSION)
    {
        return Err(SecretStoreError::undecryptable());
    }
    let nonce = bytes[MAGIC.len() + 1..HEADER_LEN]
        .try_into()
        .map_err(|_| SecretStoreError::undecryptable())?;
    Ok((nonce, &bytes[HEADER_LEN..]))
}

fn read_optional(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SecretStoreError::other(error.to_string())),
    }
}

fn rng_error(error: rand::rngs::SysError) -> SecretStoreError {
    SecretStoreError::other(format!("the OS random number generator failed: {error}"))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::secrets::SecretStoreErrorKind;

    const USER: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";
    const OTHER: &str = "9d1c3e2a-0000-4000-8000-000000000001";
    const USER_KEY: [u8; 64] = [0x5a; 64];

    struct XorWrapper;

    impl BlobWrapper for XorWrapper {
        fn wrap(&self, _user_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
            Ok(plaintext.iter().map(|byte| byte ^ 0x5a).collect())
        }

        fn unwrap(
            &self,
            _user_id: &str,
            blob: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
            Ok(Zeroizing::new(
                blob.iter().map(|byte| byte ^ 0x5a).collect(),
            ))
        }
    }

    fn refresh(user: &str) -> String {
        format!("{user}.refresh_token")
    }

    fn remember(user: &str) -> String {
        format!("{user}.two_factor_remember")
    }

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("vk-sealed-{}", uuid::Uuid::new_v4().simple()))
    }

    fn new_store() -> (PathBuf, SealedFileStore) {
        let root = temp_root();
        for user in [USER, OTHER] {
            fs::create_dir_all(root.join(ACCOUNTS_DIR).join(user)).unwrap();
        }
        let store = SealedFileStore::new(root.clone(), crate::store::write_atomic);
        (root, store)
    }

    fn wrapped_store() -> (PathBuf, SealedFileStore) {
        let (root, store) = new_store();
        (root, store.with_wrapper(Arc::new(XorWrapper)))
    }

    fn value(token: Option<Zeroizing<Vec<u8>>>) -> Option<Vec<u8>> {
        token.map(|token| token.to_vec())
    }

    #[test]
    fn refresh_and_remember_tokens_round_trip() {
        let (root, store) = new_store();
        store.provide_key(USER, &USER_KEY).unwrap();
        store.set(&refresh(USER), b"refresh").unwrap();
        store.set(&remember(USER), b"remember").unwrap();

        assert_eq!(
            value(store.get(&refresh(USER)).unwrap()),
            Some(b"refresh".to_vec())
        );
        assert_eq!(
            value(store.get(&remember(USER)).unwrap()),
            Some(b"remember".to_vec())
        );
        assert!(
            root.join(ACCOUNTS_DIR)
                .join(USER)
                .join("refresh_token.enc")
                .is_file()
        );
        assert!(
            root.join(ACCOUNTS_DIR)
                .join(USER)
                .join("two_factor_remember.enc")
                .is_file()
        );

        store.provide_key(OTHER, &USER_KEY).unwrap();
        assert!(store.get(&refresh(OTHER)).unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_locked_store_reports_locked_not_missing() {
        let (root, store) = new_store();
        store.provide_key(USER, &USER_KEY).unwrap();
        store.set(&refresh(USER), b"refresh").unwrap();
        store.set(&remember(USER), b"remember").unwrap();
        store.forget_key(USER);

        let error = store.get(&refresh(USER)).expect_err("locked");
        assert!(error.is_locked(), "{error:?}");
        let error = store
            .get(&format!("{OTHER}.refresh_token"))
            .expect_err("locked");
        assert!(error.is_locked(), "{error:?}");

        // The key-less token has no key to be locked behind.
        assert_eq!(
            value(store.get(&remember(USER)).unwrap()),
            Some(b"remember".to_vec())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn another_user_key_marks_the_token_undecryptable() {
        let (root, store) = new_store();
        store.provide_key(USER, &USER_KEY).unwrap();
        store.set(&refresh(USER), b"refresh").unwrap();
        store.forget_key(USER);
        store.provide_key(USER, &[0x11; 64]).unwrap();

        let error = store.get(&refresh(USER)).expect_err("rotated key");
        assert!(error.is_undecryptable(), "{error:?}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_tampered_header_is_rejected() {
        let (root, store) = new_store();
        store.provide_key(USER, &USER_KEY).unwrap();
        store.set(&refresh(USER), b"refresh").unwrap();
        let path = root.join(ACCOUNTS_DIR).join(USER).join("refresh_token.enc");
        let original = fs::read(&path).unwrap();
        for offset in [0, MAGIC.len(), MAGIC.len() + 1, original.len() - 1] {
            let mut tampered = original.clone();
            tampered[offset] ^= 0x01;
            fs::write(&path, &tampered).unwrap();
            let error = store.get(&refresh(USER)).expect_err("tampered");
            assert!(error.is_undecryptable(), "offset {offset}: {error:?}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delete_and_delete_all_work_without_a_key() {
        let (root, store) = new_store();
        for user in [USER, OTHER] {
            store.provide_key(user, &USER_KEY).unwrap();
        }
        store.set(&refresh(USER), b"r").unwrap();
        store.set(&remember(USER), b"m").unwrap();
        store.set(&refresh(OTHER), b"other").unwrap();
        store.forget_key(USER);
        store.forget_key(OTHER);

        store.delete(&refresh(USER)).unwrap();
        store.delete(&refresh(USER)).unwrap();
        assert!(
            !root
                .join(ACCOUNTS_DIR)
                .join(USER)
                .join("refresh_token.enc")
                .exists()
        );

        assert_eq!(store.delete_all_for(USER).unwrap(), 1);
        assert!(
            !root
                .join(ACCOUNTS_DIR)
                .join(USER)
                .join("two_factor_remember.enc")
                .exists()
        );
        assert_eq!(store.delete_all_for(USER).unwrap(), 0);
        assert!(
            root.join(ACCOUNTS_DIR)
                .join(OTHER)
                .join("refresh_token.enc")
                .is_file()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn keyless_tokens_are_only_wrapped() {
        let (root, store) = wrapped_store();
        store.set(&remember(USER), b"remember").unwrap();
        let path = root
            .join(ACCOUNTS_DIR)
            .join(USER)
            .join("two_factor_remember.enc");
        let stored = fs::read(&path).unwrap();
        assert!(!stored.starts_with(MAGIC));
        assert_ne!(stored, b"remember");

        assert_eq!(
            value(store.get(&remember(USER)).unwrap()),
            Some(b"remember".to_vec())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrapped_sealed_tokens_keep_the_header_and_round_trip() {
        let (root, store) = wrapped_store();
        store.provide_key(USER, &USER_KEY).unwrap();
        store.set(&refresh(USER), b"refresh").unwrap();
        let path = root.join(ACCOUNTS_DIR).join(USER).join("refresh_token.enc");
        assert!(fs::read(&path).unwrap().starts_with(MAGIC));

        assert_eq!(
            value(store.get(&refresh(USER)).unwrap()),
            Some(b"refresh".to_vec())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn names_other_than_the_two_tokens_are_refused() {
        let (root, store) = new_store();
        store.provide_key(USER, &USER_KEY).unwrap();
        let long = format!("{}.refresh_token", "x".repeat(MAX_USER_ID_LEN + 1));
        for key in [
            "",
            ".",
            "refresh_token",
            "u1",
            "u1.unknown",
            "u1.refresh_token.extra",
            "a/b.refresh_token",
            "a\\b.refresh_token",
            "../etc.refresh_token",
            "a b.refresh_token",
        ] {
            assert!(store.get(key).is_err(), "get {key:?}");
            assert!(store.set(key, b"x").is_err(), "set {key:?}");
            assert!(store.delete(key).is_err(), "delete {key:?}");
        }
        let key = &long;
        assert!(store.get(key).is_err(), "get {key:?}");
        assert!(store.set(key, b"x").is_err(), "set {key:?}");
        assert!(store.delete(key).is_err(), "delete {key:?}");
        assert!(store.delete_all_for("a/b").is_err());
        assert!(store.delete_all_for("").is_err());
        let error = store.provide_key("a/b", &USER_KEY).expect_err("bad id");
        assert_eq!(error.kind(), SecretStoreErrorKind::Other);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_atomic_writer_is_injected_and_its_errors_propagate() {
        let root = temp_root();
        fs::create_dir_all(root.join(ACCOUNTS_DIR).join(USER)).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let store = SealedFileStore::new(root.clone(), move |path, bytes| {
            counter.fetch_add(1, Ordering::SeqCst);
            fs::write(path, bytes)
        });
        store.provide_key(USER, &USER_KEY).unwrap();
        store.set(&refresh(USER), b"r").unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let failing = SealedFileStore::new(root.clone(), |_, _| Err(io::Error::other("disk full")));
        failing.provide_key(USER, &USER_KEY).unwrap();
        let error = failing.set(&refresh(USER), b"r").expect_err("write failed");
        assert_eq!(error.kind(), SecretStoreErrorKind::Other);
        fs::remove_dir_all(root).unwrap();
    }
}
