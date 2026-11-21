//! Keys held while unlocked: the user key and every organization key. All of them zeroize on drop.
//!
//! On Linux they rest encrypted in a `secure_memory` store whose own key lives in `memfd_secret`
//! memory (keyctl or mlock when that is missing), so a memory dump or a same-user `/proc/<pid>/mem`
//! read of the heap finds only ciphertext; each use decrypts a short-lived copy (linux-plan.md,
//! "vault key in memory"). macOS and Windows keep them as plain zeroizing values, as before.

use std::{ops::Deref, str::FromStr};

use vk_api::models::{Cipher, ProfileOrganization};
use vk_crypto::{EncString, PrivateKey, SymmetricKey};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub(crate) struct KeyRing {
    slots: Slots,
}

const USER_SLOT: &str = "user";

fn org_slot(id: &str) -> String {
    format!("org:{id}")
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
struct Slots(std::collections::HashMap<String, SymmetricKey>);

#[cfg(not(target_os = "linux"))]
impl Slots {
    fn put(&mut self, id: String, key: SymmetricKey) {
        self.0.insert(id, key);
    }

    fn get(&self, id: &str) -> Option<CipherKey<'_>> {
        self.0.get(id).map(CipherKey::Shared)
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct Slots(std::sync::Mutex<secure_memory::EncryptedMemoryStore<String>>);

#[cfg(target_os = "linux")]
impl Slots {
    fn put(&mut self, id: String, key: SymmetricKey) {
        use secure_memory::SecureMemoryStore as _;
        let bytes = key.to_bytes();
        // The plain key zeroizes here; only the store's ciphertext stays.
        drop(key);
        self.0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .put(id, &bytes);
    }

    fn get(&self, id: &str) -> Option<CipherKey<'_>> {
        use secure_memory::SecureMemoryStore as _;
        let bytes = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id.to_owned())
            .unwrap_or_else(|error| fail_closed(&format!("tampered: {error:?}")))
            .map(Zeroizing::new)?;
        let key = SymmetricKey::from_bytes(&bytes)
            .unwrap_or_else(|error| fail_closed(&format!("a stored key does not parse: {error}")));
        Some(CipherKey::Own(key))
    }
}

/// A key ring that cannot hand out its keys must not carry on: without them the vault would look
/// logged out or empty, and a tampered store may be an attack in progress.
fn fail_closed(why: &str) -> ! {
    tracing::error!(why, "the in-memory key ring is unusable; stopping");
    std::process::abort()
}

/// The key a cipher's fields are encrypted with: its own per-item key, or the user/org key for
/// legacy items without one.
pub(crate) enum CipherKey<'a> {
    // Linux hands out decrypted copies only (see `Slots`).
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Shared(&'a SymmetricKey),
    Own(SymmetricKey),
}

impl Deref for CipherKey<'_> {
    type Target = SymmetricKey;

    fn deref(&self) -> &SymmetricKey {
        match self {
            Self::Shared(key) => key,
            Self::Own(key) => key,
        }
    }
}

impl KeyRing {
    /// Decrypts the RSA private key (if any) with the user key and unwraps each org key with it.
    /// Org keys already present in `previous` are copied instead of paying for RSA again.
    pub(crate) fn build(
        user: SymmetricKey,
        private_key: Option<&str>,
        orgs: &[ProfileOrganization],
        previous: Option<&Self>,
    ) -> Result<Self> {
        let mut ring = Self {
            slots: Slots::default(),
        };
        ring.slots.put(USER_SLOT.to_owned(), user);
        let mut rsa: Option<PrivateKey> = None;
        for org in orgs {
            if let Some(key) = previous.and_then(|old| old.org(&org.id)) {
                ring.slots.put(org_slot(&org.id), copy_key(&key)?);
                continue;
            }
            let Some(wrapped) = org.key.as_deref() else {
                continue;
            };
            if rsa.is_none() {
                let Some(private_key) = private_key else {
                    tracing::warn!("organization key present but the account has no private key");
                    break;
                };
                rsa = Some(decrypt_private_key(private_key, &ring.user())?);
            }
            if let Some(rsa) = &rsa {
                match unwrap_org_key(wrapped, rsa) {
                    Ok(key) => ring.slots.put(org_slot(&org.id), key),
                    Err(error) => tracing::warn!(%error, "could not decrypt an organization key"),
                }
            }
        }
        Ok(ring)
    }

    /// Always present: `build` stores it first.
    pub(crate) fn user(&self) -> CipherKey<'_> {
        self.slots
            .get(USER_SLOT)
            .unwrap_or_else(|| fail_closed("the user key is missing"))
    }

    pub(crate) fn org(&self, id: &str) -> Option<CipherKey<'_>> {
        self.slots.get(&org_slot(id))
    }

    /// The user key for personal items, the org key for org items.
    pub(crate) fn base_key(&self, organization_id: Option<&str>) -> Result<CipherKey<'_>> {
        match organization_id {
            None => Ok(self.user()),
            Some(id) => self.org(id).ok_or(Error::Crypto(vk_crypto::Error::Decrypt)),
        }
    }

    pub(crate) fn cipher_key(&self, cipher: &Cipher) -> Result<CipherKey<'_>> {
        let base = self.base_key(cipher.organization_id.as_deref())?;
        match cipher.key.as_deref() {
            Some(wrapped) if !wrapped.is_empty() => {
                let bytes = parse(wrapped)?.decrypt(&base)?;
                Ok(CipherKey::Own(SymmetricKey::from_bytes(&bytes)?))
            }
            _ => Ok(base),
        }
    }

    pub(crate) fn user_key_copy(&self) -> Result<SymmetricKey> {
        copy_key(&self.user())
    }
}

pub(crate) fn copy_key(key: &SymmetricKey) -> Result<SymmetricKey> {
    Ok(SymmetricKey::from_bytes(&key.to_bytes())?)
}

pub(crate) fn decrypt_private_key(protected: &str, user: &SymmetricKey) -> Result<PrivateKey> {
    let der = parse(protected)?.decrypt(user)?;
    Ok(PrivateKey::from_pkcs8_der(&der)?)
}

fn unwrap_org_key(wrapped: &str, rsa: &PrivateKey) -> Result<SymmetricKey> {
    let bytes = parse(wrapped)?.decrypt_with_private_key(rsa)?;
    Ok(SymmetricKey::from_bytes(&bytes)?)
}

pub(crate) fn parse(text: &str) -> Result<EncString> {
    Ok(EncString::from_str(text)?)
}

/// Decrypts an optional EncString field; a missing or empty field is the empty string.
pub(crate) fn decrypt_text(field: Option<&str>, key: &SymmetricKey) -> Result<Zeroizing<String>> {
    match field {
        Some(text) if !text.is_empty() => Ok(parse(text)?.decrypt_string(key)?),
        _ => Ok(Zeroizing::new(String::new())),
    }
}

/// Encrypts a field, leaving empty values unset like the official clients do.
pub(crate) fn encrypt_opt(plain: &str, key: &SymmetricKey) -> Result<Option<String>> {
    if plain.is_empty() {
        return Ok(None);
    }
    Ok(Some(EncString::encrypt(plain.as_bytes(), key)?.to_string()))
}

pub(crate) fn encrypt_text(plain: &str, key: &SymmetricKey) -> Result<String> {
    Ok(EncString::encrypt(plain.as_bytes(), key)?.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const RSA_PRIVATE_DER: &[u8] = include_bytes!("../tests/fixtures/rsa_private.der");
    pub(crate) const ORG_KEY: &[u8] = include_bytes!("../tests/fixtures/org_key.bin");
    /// `ORG_KEY` wrapped with OpenSSL (`pkeyutl -encrypt`, OAEP, SHA-1) under the fixture key.
    pub(crate) const ORG_KEY_RSA: &str = include_str!("../tests/fixtures/org_key_rsa.txt");

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_hands_out_decrypted_copies_of_the_stored_key() {
        let ring = crate::testutil::ring();
        let first = ring.user();
        assert!(
            matches!(first, CipherKey::Own(_)),
            "no plain key stays resident"
        );
        assert_eq!(first.to_bytes(), ring.user().to_bytes());
        assert_eq!(ring.user_key_copy().unwrap().to_bytes(), first.to_bytes());
    }

    fn org(id: &str, key: Option<&str>) -> ProfileOrganization {
        ProfileOrganization {
            id: id.into(),
            name: "Org".into(),
            key: key.map(str::to_owned),
        }
    }

    #[test]
    fn org_keys_are_unwrapped_with_the_rsa_key_produced_by_openssl() {
        let user = SymmetricKey::generate();
        let private_key = EncString::encrypt(RSA_PRIVATE_DER, &user)
            .unwrap()
            .to_string();
        let ring = KeyRing::build(
            user,
            Some(&private_key),
            &[org("o1", Some(ORG_KEY_RSA.trim())), org("o2", None)],
            None,
        )
        .unwrap();
        assert_eq!(&*ring.org("o1").unwrap().to_bytes(), ORG_KEY);
        assert!(ring.org("o2").is_none());
        assert!(ring.base_key(Some("o2")).is_err());

        let rebuilt = KeyRing::build(
            ring.user_key_copy().unwrap(),
            None,
            &[org("o1", Some(ORG_KEY_RSA.trim()))],
            Some(&ring),
        )
        .unwrap();
        assert_eq!(&*rebuilt.org("o1").unwrap().to_bytes(), ORG_KEY);
    }

    #[test]
    fn private_key_under_another_user_key_fails_the_mac() {
        let private_key = EncString::encrypt(RSA_PRIVATE_DER, &SymmetricKey::generate())
            .unwrap()
            .to_string();
        let error = KeyRing::build(
            SymmetricKey::generate(),
            Some(&private_key),
            &[org("o1", Some(ORG_KEY_RSA.trim()))],
            None,
        )
        .err();
        assert!(matches!(
            error,
            Some(Error::Crypto(vk_crypto::Error::MacMismatch))
        ));
    }

    #[test]
    fn cipher_key_prefers_the_item_key() {
        let ring = KeyRing::build(SymmetricKey::generate(), None, &[], None).unwrap();
        let item = SymmetricKey::generate();
        let wrapped = EncString::encrypt(&item.to_bytes(), &ring.user())
            .unwrap()
            .to_string();
        let with_key = Cipher {
            key: Some(wrapped),
            ..Cipher::default()
        };
        assert_eq!(
            ring.cipher_key(&with_key).unwrap().to_bytes(),
            item.to_bytes()
        );

        let legacy = Cipher::default();
        assert_eq!(
            ring.cipher_key(&legacy).unwrap().to_bytes(),
            ring.user().to_bytes()
        );
    }

    #[test]
    fn optional_fields_round_trip_and_empty_means_unset() {
        let key = SymmetricKey::generate();
        assert_eq!(encrypt_opt("", &key).unwrap(), None);
        let enc = encrypt_opt("hunter2", &key).unwrap();
        assert_eq!(&*decrypt_text(enc.as_deref(), &key).unwrap(), "hunter2");
        assert_eq!(&*decrypt_text(None, &key).unwrap(), "");
        assert_eq!(&*decrypt_text(Some(""), &key).unwrap(), "");
        assert!(decrypt_text(Some("garbage"), &key).is_err());
    }
}
