//! Keys held while unlocked: the user key and every organization key. All of them zeroize on drop.

use std::{collections::HashMap, ops::Deref, str::FromStr};

use bwl_api::models::{Cipher, ProfileOrganization};
use bwl_crypto::{EncString, PrivateKey, SymmetricKey};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub(crate) struct KeyRing {
    user: SymmetricKey,
    orgs: HashMap<String, SymmetricKey>,
}

/// The key a cipher's fields are encrypted with: its own per-item key, or the user/org key for
/// legacy items without one.
pub(crate) enum CipherKey<'a> {
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
            user,
            orgs: HashMap::with_capacity(orgs.len()),
        };
        let mut rsa: Option<PrivateKey> = None;
        for org in orgs {
            if let Some(key) = previous.and_then(|old| old.orgs.get(&org.id)) {
                ring.orgs.insert(org.id.clone(), copy_key(key)?);
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
                rsa = Some(decrypt_private_key(private_key, &ring.user)?);
            }
            if let Some(rsa) = &rsa {
                match unwrap_org_key(wrapped, rsa) {
                    Ok(key) => {
                        ring.orgs.insert(org.id.clone(), key);
                    }
                    Err(error) => tracing::warn!(%error, "could not decrypt an organization key"),
                }
            }
        }
        Ok(ring)
    }

    pub(crate) fn user(&self) -> &SymmetricKey {
        &self.user
    }

    pub(crate) fn org(&self, id: &str) -> Option<&SymmetricKey> {
        self.orgs.get(id)
    }

    /// The user key for personal items, the org key for org items.
    pub(crate) fn base_key(&self, organization_id: Option<&str>) -> Result<&SymmetricKey> {
        match organization_id {
            None => Ok(&self.user),
            Some(id) => self
                .orgs
                .get(id)
                .ok_or(Error::Crypto(bwl_crypto::Error::Decrypt)),
        }
    }

    pub(crate) fn cipher_key(&self, cipher: &Cipher) -> Result<CipherKey<'_>> {
        let base = self.base_key(cipher.organization_id.as_deref())?;
        match cipher.key.as_deref() {
            Some(wrapped) if !wrapped.is_empty() => {
                let bytes = parse(wrapped)?.decrypt(base)?;
                Ok(CipherKey::Own(SymmetricKey::from_bytes(&bytes)?))
            }
            _ => Ok(CipherKey::Shared(base)),
        }
    }

    pub(crate) fn user_key_copy(&self) -> Result<SymmetricKey> {
        copy_key(&self.user)
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
            Some(Error::Crypto(bwl_crypto::Error::MacMismatch))
        ));
    }

    #[test]
    fn cipher_key_prefers_the_item_key() {
        let ring = KeyRing::build(SymmetricKey::generate(), None, &[], None).unwrap();
        let item = SymmetricKey::generate();
        let wrapped = EncString::encrypt(&item.to_bytes(), ring.user())
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
