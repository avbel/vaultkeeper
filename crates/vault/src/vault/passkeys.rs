//! Passkeys stored on logins (`login.fido2Credentials`) in the Bitwarden clients' format: every
//! string an EncString under the item key, `creationDate` in clear, the credential id a GUID
//! string (or `b64.` + base64url for an id another authenticator chose). A login holds one
//! passkey, as in the Bitwarden clients; saving another replaces it.

use std::sync::Arc;

use base64::{
    Engine as _, alphabet,
    engine::{
        GeneralPurpose,
        general_purpose::{NO_PAD_INDIFFERENT, URL_SAFE_NO_PAD},
    },
};
use serde_json::{Map, Value};
use uuid::Uuid;
use vk_api::models::Cipher;
use vk_crypto::SymmetricKey;
use zeroize::Zeroizing;

use super::{Inner, Vault};
use crate::{
    Error, Result, encrypt,
    keys::{decrypt_text, encrypt_text},
    model::{ItemData, ItemDraft, ItemId, ItemSummary},
    reveal,
    util::now_rfc3339,
    vault::BrowserSnapshot,
};

const URL_SAFE_LENIENT: GeneralPurpose =
    GeneralPurpose::new(&alphabet::URL_SAFE, NO_PAD_INDIFFERENT);
const FOREIGN_ID_PREFIX: &str = "b64.";

/// A stored passkey for the relying party a site asked for.
#[derive(Debug, Clone)]
pub struct PasskeyMatch {
    pub summary: ItemSummary,
    pub credential_id: Vec<u8>,
    pub user_name: String,
    pub discoverable: bool,
}

/// What signing with a stored passkey needs.
pub struct PasskeySecret {
    /// PKCS#8 DER of the P-256 key.
    pub key_pkcs8: Zeroizing<Vec<u8>>,
    pub counter: u32,
    pub user_handle: Option<Vec<u8>>,
}

pub enum PasskeyTarget {
    Existing(ItemId),
    New {
        name: String,
        username: String,
        uri: String,
    },
}

pub struct NewPasskey {
    pub credential_id: Vec<u8>,
    pub key_pkcs8: Zeroizing<Vec<u8>>,
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub discoverable: bool,
}

/// The stored text of a credential id: a GUID for the 16-byte ids passkeys made here get, as
/// the Bitwarden clients write theirs.
#[must_use]
pub fn credential_id_text(raw: &[u8]) -> String {
    match <[u8; 16]>::try_from(raw) {
        Ok(bytes) => Uuid::from_bytes(bytes).hyphenated().to_string(),
        Err(_) => format!("{FOREIGN_ID_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw)),
    }
}

fn credential_id_bytes(text: &str) -> Option<Vec<u8>> {
    if let Some(encoded) = text.strip_prefix(FOREIGN_ID_PREFIX) {
        return URL_SAFE_LENIENT.decode(encoded).ok();
    }
    Uuid::try_parse(text)
        .ok()
        .map(|uuid| uuid.as_bytes().to_vec())
}

fn decrypt_field(
    passkey: &Map<String, Value>,
    name: &str,
    key: &SymmetricKey,
) -> Option<Zeroizing<String>> {
    let text = passkey.get(name)?.as_str()?;
    decrypt_text(Some(text), key).ok()
}

/// One stored passkey of `cipher`, decrypted as far as matching needs.
struct Stored<'a> {
    fields: &'a Map<String, Value>,
    credential_id: Vec<u8>,
    rp_id: Zeroizing<String>,
}

fn stored<'a>(cipher: &'a Cipher, key: &SymmetricKey) -> Vec<Stored<'a>> {
    let Some(Value::Array(passkeys)) = cipher
        .login
        .as_ref()
        .and_then(|login| login.extra.get(encrypt::PASSKEYS))
    else {
        return Vec::new();
    };
    passkeys
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|fields| {
            Some(Stored {
                credential_id: credential_id_bytes(&decrypt_field(fields, "credentialId", key)?)?,
                rp_id: decrypt_field(fields, "rpId", key)?,
                fields,
            })
        })
        .collect()
}

impl Vault {
    /// Non-deleted logins holding a passkey for `rp_id`.
    pub fn passkeys_for(&self, rp_id: &str) -> Result<Vec<PasskeyMatch>> {
        self.inner.read_unlocked(|_, unlocked| {
            let mut found = Vec::new();
            for entry in unlocked.data.login_entries() {
                let Ok(key) = unlocked.keys.cipher_key(&entry.cipher) else {
                    continue;
                };
                for passkey in stored(&entry.cipher, &key) {
                    if passkey.rp_id.as_str() != rp_id {
                        continue;
                    }
                    found.push(PasskeyMatch {
                        summary: entry.summary.clone(),
                        credential_id: passkey.credential_id,
                        user_name: decrypt_field(passkey.fields, "userName", &key)
                            .map(|name| name.to_string())
                            .unwrap_or_default(),
                        discoverable: decrypt_field(passkey.fields, "discoverable", &key)
                            .is_some_and(|value| value.as_str() == "true"),
                    });
                }
            }
            Ok(found)
        })
    }

    /// The key of `item`'s passkey `credential_id` for `rp_id`, under the session and index
    /// version of `snapshot` (taken before the prompt).
    pub fn passkey_secret(
        &self,
        snapshot: BrowserSnapshot,
        item: &ItemId,
        credential_id: &[u8],
        rp_id: &str,
    ) -> Result<PasskeySecret> {
        let state = self.inner.read_state();
        let active = state.active.as_ref().ok_or(Error::LoggedOut)?;
        let unlocked = active.unlocked.as_ref().ok_or(Error::Locked)?;
        if !snapshot.current(state.epoch, unlocked.revision) {
            return Err(Error::Conflict);
        }
        let entry = unlocked
            .data
            .login_entries()
            .find(|entry| entry.summary.id == *item)
            .ok_or(Error::NotFound)?;
        let key = unlocked.keys.cipher_key(&entry.cipher)?;
        let passkey = stored(&entry.cipher, &key)
            .into_iter()
            .find(|passkey| {
                passkey.credential_id == credential_id && passkey.rp_id.as_str() == rp_id
            })
            .ok_or(Error::NotFound)?;
        let key_value = decrypt_field(passkey.fields, "keyValue", &key).ok_or(Error::NotFound)?;
        let key_pkcs8 = Zeroizing::new(
            URL_SAFE_LENIENT
                .decode(key_value.as_bytes())
                .map_err(|_| Error::unsupported("The passkey's key is unreadable"))?,
        );
        Ok(PasskeySecret {
            key_pkcs8,
            counter: decrypt_field(passkey.fields, "counter", &key)
                .and_then(|counter| counter.parse().ok())
                .unwrap_or(0),
            user_handle: decrypt_field(passkey.fields, "userHandle", &key)
                .and_then(|handle| URL_SAFE_LENIENT.decode(handle.as_bytes()).ok()),
        })
    }

    /// Stores `passkey` on an existing login, replacing the one it held, or on a new login.
    pub async fn save_passkey(&self, target: PasskeyTarget, passkey: NewPasskey) -> Result<ItemId> {
        let created = now_rfc3339();
        self.inner
            .edit_passkeys(target, move |key, passkeys| {
                passkeys.clear();
                passkeys.push(encrypt_passkey(&passkey, &created, key)?);
                Ok(())
            })
            .await
    }

    /// Records the signature counter of an imported passkey that counts (ours stay at 0).
    pub async fn set_passkey_counter(
        &self,
        item: &ItemId,
        credential_id: &[u8],
        counter: u32,
    ) -> Result<()> {
        let credential_id = credential_id.to_vec();
        self.inner
            .edit_passkeys(
                PasskeyTarget::Existing(item.clone()),
                move |key, passkeys| {
                    let passkey = passkeys
                        .iter_mut()
                        .filter_map(Value::as_object_mut)
                        .find(|fields| {
                            decrypt_field(fields, "credentialId", key)
                                .and_then(|text| credential_id_bytes(&text))
                                .is_some_and(|id| id == credential_id)
                        })
                        .ok_or(Error::NotFound)?;
                    passkey.insert(
                        "counter".to_owned(),
                        Value::String(encrypt_text(&counter.to_string(), key)?),
                    );
                    Ok(())
                },
            )
            .await
            .map(drop)
    }
}

fn encrypt_passkey(passkey: &NewPasskey, created: &str, key: &SymmetricKey) -> Result<Value> {
    let key_value = Zeroizing::new(URL_SAFE_NO_PAD.encode(passkey.key_pkcs8.as_slice()));
    let fields = [
        ("credentialId", credential_id_text(&passkey.credential_id)),
        ("keyType", "public-key".to_owned()),
        ("keyAlgorithm", "ECDSA".to_owned()),
        ("keyCurve", "P-256".to_owned()),
        ("rpId", passkey.rp_id.clone()),
        ("userHandle", URL_SAFE_NO_PAD.encode(&passkey.user_handle)),
        ("userName", passkey.user_name.clone()),
        ("counter", "0".to_owned()),
        ("rpName", passkey.rp_name.clone()),
        ("userDisplayName", passkey.user_display_name.clone()),
        ("discoverable", passkey.discoverable.to_string()),
    ];
    let mut object = Map::new();
    for (name, plain) in fields {
        object.insert(name.to_owned(), Value::String(encrypt_text(&plain, key)?));
    }
    object.insert(
        "keyValue".to_owned(),
        Value::String(encrypt_text(&key_value, key)?),
    );
    object.insert("creationDate".to_owned(), Value::String(created.to_owned()));
    Ok(Value::Object(object))
}

impl Inner {
    /// Saves the target login with its passkey list changed by `edit`, which runs under the key
    /// the saved item uses.
    async fn edit_passkeys(
        self: &Arc<Self>,
        target: PasskeyTarget,
        edit: impl FnOnce(&SymmetricKey, &mut Vec<Value>) -> Result<()>,
    ) -> Result<ItemId> {
        let ctx = self.writable_ctx()?;
        let id = match &target {
            PasskeyTarget::Existing(id) => {
                self.ensure_complete_ciphers().await?;
                Some(id.clone())
            }
            PasskeyTarget::New { .. } => None,
        };
        let prepared = self.read_unlocked(|_, unlocked| match &target {
            PasskeyTarget::Existing(id) => {
                let entry = unlocked.data.entry(&id.0).ok_or(Error::NotFound)?;
                if !entry.cipher.edit {
                    return Err(Error::ReadOnly);
                }
                let draft = reveal::draft(&entry.cipher, &unlocked.keys)?;
                encrypt::prepare_with_passkeys(&draft, Some(&entry.cipher), &unlocked.keys, edit)
            }
            PasskeyTarget::New {
                name,
                username,
                uri,
            } => {
                let draft = ItemDraft {
                    name: name.clone(),
                    notes: Zeroizing::default(),
                    folder_id: None,
                    organization_id: None,
                    collection_ids: Vec::new(),
                    favorite: false,
                    reprompt: false,
                    fields: Vec::new(),
                    data: ItemData::Login {
                        username: username.clone(),
                        password: Zeroizing::default(),
                        totp: Zeroizing::default(),
                        uris: vec![uri.clone()],
                    },
                    revision_date: None,
                };
                encrypt::prepare_with_passkeys(&draft, None, &unlocked.keys, edit)
            }
        })?;
        self.send_prepared(&ctx, id, &prepared).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_ids_round_trip_as_guid_or_prefixed_base64url() {
        let ours = [0x5a; 16];
        let text = credential_id_text(&ours);
        assert_eq!(text, "5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a5a");
        assert_eq!(credential_id_bytes(&text).expect("guid"), ours);
        let foreign = [1_u8, 2, 3];
        assert_eq!(credential_id_text(&foreign), "b64.AQID");
        assert_eq!(credential_id_bytes("b64.AQID").expect("b64"), foreign);
        assert_eq!(credential_id_bytes("not an id"), None);
    }

    #[test]
    fn a_new_passkey_encrypts_every_field_but_the_creation_date() {
        let key = SymmetricKey::generate();
        let passkey = NewPasskey {
            credential_id: vec![7; 16],
            key_pkcs8: Zeroizing::new(vec![1, 2, 3]),
            rp_id: "example.com".to_owned(),
            rp_name: "Example".to_owned(),
            user_handle: vec![9, 9],
            user_name: "anne".to_owned(),
            user_display_name: "Anne".to_owned(),
            discoverable: true,
        };
        let Value::Object(fields) =
            encrypt_passkey(&passkey, "2026-11-12T10:00:00.000Z", &key).expect("encrypted")
        else {
            panic!("an object");
        };
        let plain = |name: &str| decrypt_field(&fields, name, &key).expect(name).to_string();
        assert_eq!(
            plain("credentialId"),
            "07070707-0707-0707-0707-070707070707"
        );
        assert_eq!(plain("keyType"), "public-key");
        assert_eq!(plain("keyAlgorithm"), "ECDSA");
        assert_eq!(plain("keyCurve"), "P-256");
        assert_eq!(plain("keyValue"), "AQID");
        assert_eq!(plain("rpId"), "example.com");
        assert_eq!(plain("userHandle"), "CQk");
        assert_eq!(plain("userName"), "anne");
        assert_eq!(plain("counter"), "0");
        assert_eq!(plain("rpName"), "Example");
        assert_eq!(plain("userDisplayName"), "Anne");
        assert_eq!(plain("discoverable"), "true");
        assert_eq!(fields["creationDate"], "2026-11-12T10:00:00.000Z");
        assert_eq!(fields.len(), 13);
    }
}
