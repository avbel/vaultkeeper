//! Draft → encrypted [`CipherRequest`]. New items get their own random 64-byte item key, wrapped
//! by the user or org key; every field is encrypted with the item key.
//!
//! An update starts from the stored cipher: what the draft edits is replaced, everything else
//! (passkeys, `archivedDate`, properties this client doesn't model) is carried over through
//! [`crate::passthrough`], re-encrypted when the item key changes.

use bwl_api::models::{
    Card, Cipher, CipherRequest, Extra, Field, Identity, Login, LoginUri, PasswordHistory,
    SecureNote, SshKey, cipher_type,
};
use bwl_crypto::SymmetricKey;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    keys::{KeyRing, copy_key, decrypt_text, encrypt_opt, encrypt_text},
    model::{CustomField, IdentityData, ItemData, ItemDraft},
    passthrough::{Rekey, carry, uri_checksum},
    util::now_rfc3339,
};

const PASSWORD_HISTORY_LIMIT: usize = 5;
const FIELD_TEXT: u8 = 0;
const FIELD_HIDDEN: u8 = 1;
const FIELD_BOOLEAN: u8 = 2;
const FIELD_LINKED: u8 = 3;
/// Typed on the request; a copy from the stored cipher would be serialized after, and win over,
/// the typed value.
const REQUEST_OWNED: [&str; 2] = ["lastKnownRevisionDate", "encryptedFor"];
/// Vaultwarden rewrites `login.uri` from `uris[0]` on every read and official clients send none;
/// a carried copy would be a stale URI.
const LEGACY_LOGIN_URI: &str = "uri";

pub(crate) struct Prepared {
    pub request: CipherRequest,
    pub collection_ids: Vec<String>,
}

const fn type_of(data: &ItemData) -> u8 {
    match data {
        ItemData::Login { .. } => cipher_type::LOGIN,
        ItemData::SecureNote => cipher_type::SECURE_NOTE,
        ItemData::Card { .. } => cipher_type::CARD,
        ItemData::Identity(_) => cipher_type::IDENTITY,
        ItemData::SshKey { .. } => cipher_type::SSH_KEY,
    }
}

/// The keys an update re-encrypts with, and the ones the old ciphertext used.
struct ItemKeys {
    key: SymmetricKey,
    wrapped: Option<String>,
    old: Option<SymmetricKey>,
    /// `old` differs from `key`, so everything carried over must be re-encrypted.
    rekeyed: bool,
}

impl ItemKeys {
    fn new_item(base_key: &SymmetricKey) -> Result<Self> {
        let key = SymmetricKey::generate();
        let wrapped = encrypt_text_bytes(&key.to_bytes(), base_key)?;
        Ok(Self {
            key,
            wrapped: Some(wrapped),
            old: None,
            rekeyed: false,
        })
    }

    /// Keeps an existing item key. A legacy item (no item key) is upgraded to one, unless it has
    /// attachments or a hidden password: their keys / ciphertext are bound to the old key.
    fn for_update(base: &Cipher, keys: &KeyRing, base_key: &SymmetricKey) -> Result<Self> {
        let old = copy_key(&*keys.cipher_key(base)?)?;
        let has_key = base.key.as_deref().is_some_and(|key| !key.is_empty());
        let has_attachments = base
            .attachments
            .as_ref()
            .is_some_and(|list| !list.is_empty());
        if has_key || has_attachments || !base.view_password {
            return Ok(Self {
                key: copy_key(&old)?,
                wrapped: base.key.clone().filter(|key| !key.is_empty()),
                old: Some(old),
                rekeyed: false,
            });
        }
        let upgraded = Self::new_item(base_key)?;
        Ok(Self {
            old: Some(old),
            rekeyed: true,
            ..upgraded
        })
    }

    fn rekey(&self) -> Option<Rekey<'_>> {
        match &self.old {
            Some(old) if self.rekeyed => Some(Rekey {
                old,
                new: &self.key,
            }),
            _ => None,
        }
    }

    /// The stored cipher's unmodelled properties at one level, ready for the request.
    fn carry(&self, extra: Option<&Extra>) -> Result<Extra> {
        carry(extra, self.rekey())
    }
}

fn encrypt_text_bytes(bytes: &[u8], key: &SymmetricKey) -> Result<String> {
    Ok(bwl_crypto::EncString::encrypt(bytes, key)?.to_string())
}

fn check_update(draft: &ItemDraft, base: &Cipher, kind: u8) -> Result<()> {
    if !base.edit {
        return Err(Error::ReadOnly);
    }
    // Re-reading the moved base instead would mix its new fields with the draft's stale ones.
    if draft.revision_date.as_deref() != Some(base.revision_date.as_str()) {
        return Err(Error::Conflict);
    }
    let organization_id = draft.organization_id.as_deref();
    if base.organization_id.as_deref() != organization_id {
        return Err(Error::unsupported(
            "Moving items between the personal vault and an organization is not supported",
        ));
    }
    if base.r#type != kind {
        return Err(Error::unsupported(
            "Changing an item's type is not supported",
        ));
    }
    Ok(())
}

pub(crate) fn prepare(
    draft: &ItemDraft,
    base: Option<&Cipher>,
    keys: &KeyRing,
) -> Result<Prepared> {
    let kind = type_of(&draft.data);
    let organization_id = draft.organization_id.as_deref();
    if let Some(base) = base {
        check_update(draft, base, kind)?;
    }
    let base_key = keys.base_key(organization_id)?;
    let item = match base {
        Some(base) => ItemKeys::for_update(base, keys, base_key)?,
        None => ItemKeys::new_item(base_key)?,
    };
    let key = &item.key;

    let mut request = CipherRequest {
        r#type: kind,
        organization_id: organization_id.map(str::to_owned),
        folder_id: draft.folder_id.as_deref().map(str::to_owned),
        name: encrypt_text(&draft.name, key)?,
        notes: encrypt_opt(&draft.notes, key)?,
        favorite: draft.favorite,
        reprompt: u8::from(draft.reprompt),
        key: item.wrapped.clone(),
        fields: fields(&draft.fields, base, &item)?,
        last_known_revision_date: base.and(draft.revision_date.as_deref().map(str::to_owned)),
        extra: top_level_extra(base, &item)?,
        ..CipherRequest::default()
    };
    fill_type_data(&mut request, &draft.data, base, &item)?;
    if request.password_history.is_none() {
        request.password_history = carried_history(base, &item)?;
    }
    Ok(Prepared {
        request,
        collection_ids: draft
            .collection_ids
            .iter()
            .map(ToString::to_string)
            .collect(),
    })
}

fn top_level_extra(base: Option<&Cipher>, item: &ItemKeys) -> Result<Extra> {
    let mut extra = item.carry(base.map(|base| &base.extra))?;
    for name in REQUEST_OWNED {
        extra.remove(name);
    }
    Ok(extra)
}

fn fill_type_data(
    request: &mut CipherRequest,
    data: &ItemData,
    base: Option<&Cipher>,
    item: &ItemKeys,
) -> Result<()> {
    let key = &item.key;
    match data {
        ItemData::Login {
            username,
            password,
            totp,
            uris,
        } => {
            let login = LoginParts {
                username,
                password,
                totp,
                uris,
            };
            request.login = Some(login_request(&login, base, item)?);
            request.password_history = password_history(password, base, item)?;
        }
        ItemData::SecureNote => {
            let stored = base.and_then(|base| base.secure_note.as_ref());
            request.secure_note = Some(SecureNote {
                r#type: stored.map_or(0, |note| note.r#type),
                extra: item.carry(stored.map(|note| &note.extra))?,
            });
        }
        ItemData::Card {
            cardholder_name,
            brand,
            number,
            exp_month,
            exp_year,
            code,
        } => {
            let stored = base.and_then(|base| base.card.as_ref());
            request.card = Some(Card {
                cardholder_name: encrypt_opt(cardholder_name, key)?,
                brand: encrypt_opt(brand, key)?,
                number: encrypt_opt(number, key)?,
                exp_month: encrypt_opt(exp_month, key)?,
                exp_year: encrypt_opt(exp_year, key)?,
                code: encrypt_opt(code, key)?,
                extra: item.carry(stored.map(|card| &card.extra))?,
            });
        }
        ItemData::Identity(identity) => {
            let stored = base.and_then(|base| base.identity.as_ref());
            let extra = item.carry(stored.map(|identity| &identity.extra))?;
            request.identity = Some(identity_request(identity, key, extra)?);
        }
        ItemData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => {
            let stored = base.and_then(|base| base.ssh_key.as_ref());
            request.ssh_key = Some(SshKey {
                private_key: encrypt_opt(private_key, key)?,
                public_key: encrypt_opt(public_key, key)?,
                key_fingerprint: encrypt_opt(fingerprint, key)?,
                extra: item.carry(stored.map(|ssh| &ssh.extra))?,
            });
        }
    }
    Ok(())
}

struct LoginParts<'a> {
    username: &'a str,
    password: &'a Zeroizing<String>,
    totp: &'a Zeroizing<String>,
    uris: &'a [String],
}

fn login_request(login: &LoginParts<'_>, base: Option<&Cipher>, item: &ItemKeys) -> Result<Login> {
    let key = &item.key;
    let base_login = base.and_then(|base| base.login.as_ref());
    let hidden = base.is_some_and(|base| !base.view_password);
    let (password, revision) = if hidden {
        // The user never saw it, so the draft carries no password: keep the stored one.
        (
            base_login.and_then(|login| login.password.clone()),
            base_login.and_then(|login| login.password_revision_date.clone()),
        )
    } else {
        let old = old_password(base, item)?;
        let changed = old
            .as_ref()
            .is_some_and(|old| !old.is_empty() && **old != **login.password);
        let revision = if changed {
            Some(now_rfc3339())
        } else {
            base_login.and_then(|login| login.password_revision_date.clone())
        };
        (encrypt_opt(login.password, key)?, revision)
    };

    let mut extra = item.carry(base_login.map(|login| &login.extra))?;
    extra.remove(LEGACY_LOGIN_URI);
    Ok(Login {
        username: encrypt_opt(login.username, key)?,
        password,
        password_revision_date: revision,
        totp: encrypt_opt(login.totp, key)?,
        uris: Some(login_uris(login.uris, base_login, item)?),
        extra,
    })
}

/// Blank URIs are dropped after pairing, so URI `i` keeps the match rule and extras of stored
/// URI `i` even when an earlier one was cleared. Each gets a fresh checksum, as the official
/// clients write one on every save.
fn login_uris(
    uris: &[String],
    base_login: Option<&Login>,
    item: &ItemKeys,
) -> Result<Vec<LoginUri>> {
    let key = &item.key;
    let base_uris = base_login
        .and_then(|login| login.uris.as_deref())
        .unwrap_or_default();
    uris.iter()
        .map(|uri| uri.trim())
        .enumerate()
        .filter(|(_, uri)| !uri.is_empty())
        .map(|(index, uri)| {
            let known = base_uris.get(index);
            Ok(LoginUri {
                uri: Some(encrypt_text(uri, key)?),
                r#match: known.and_then(|known| known.r#match),
                uri_checksum: Some(uri_checksum(uri, key)?),
                extra: item.carry(known.map(|known| &known.extra))?,
            })
        })
        .collect()
}

fn old_password(base: Option<&Cipher>, item: &ItemKeys) -> Result<Option<Zeroizing<String>>> {
    let (Some(login), Some(old_key)) = (base.and_then(|base| base.login.as_ref()), &item.old)
    else {
        return Ok(None);
    };
    decrypt_text(login.password.as_deref(), old_key).map(Some)
}

/// The stored history, re-encrypted when the item key changed, plus the replaced password.
fn password_history(
    new_password: &str,
    base: Option<&Cipher>,
    item: &ItemKeys,
) -> Result<Option<Vec<PasswordHistory>>> {
    let mut history = carried_history(base, item)?.unwrap_or_default();
    if base.is_some_and(|base| base.view_password)
        && let Some(old) = old_password(base, item)?
        && !old.is_empty()
        && *old != new_password
    {
        history.insert(
            0,
            PasswordHistory {
                password: encrypt_text(&old, &item.key)?,
                last_used_date: now_rfc3339(),
                extra: Extra::new(),
            },
        );
        history.truncate(PASSWORD_HISTORY_LIMIT);
    }
    Ok((!history.is_empty()).then_some(history))
}

fn carried_history(base: Option<&Cipher>, item: &ItemKeys) -> Result<Option<Vec<PasswordHistory>>> {
    let Some(stored) = base.and_then(|base| base.password_history.as_ref()) else {
        return Ok(None);
    };
    let Some(rekey) = item.rekey() else {
        return Ok(Some(stored.clone()));
    };
    stored
        .iter()
        .map(|entry| {
            let plain = decrypt_text(Some(&entry.password), rekey.old)?;
            Ok(PasswordHistory {
                password: encrypt_text(&plain, rekey.new)?,
                last_used_date: entry.last_used_date.clone(),
                extra: carry(Some(&entry.extra), Some(rekey))?,
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn fields(
    fields: &[CustomField],
    base: Option<&Cipher>,
    item: &ItemKeys,
) -> Result<Option<Vec<Field>>> {
    if fields.is_empty() {
        return Ok(None);
    }
    let key = &item.key;
    let base_fields = base
        .and_then(|base| base.fields.as_deref())
        .unwrap_or_default();
    let masked = base.is_some_and(|base| !base.view_password);
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let known = base_fields.get(index);
            if masked
                && field.hidden
                && field.value.is_empty()
                && let Some(stored) = stored_hidden_field(field, index, base_fields, item)?
            {
                return Ok(Field {
                    name: encrypt_opt(&field.name, key)?,
                    extra: item.carry(Some(&stored.extra))?,
                    ..stored.clone()
                });
            }
            if masked
                && field.value.is_empty()
                && known.is_some_and(|known| known.r#type == FIELD_HIDDEN)
            {
                // A renamed or un-hidden field whose value the user may not see: saving the blank
                // draft would erase it. Upstream disables these fields for such members.
                return Err(Error::ReadOnly);
            }
            let kept = known.filter(|known| matches!(known.r#type, FIELD_BOOLEAN | FIELD_LINKED));
            let r#type = match (field.hidden, kept) {
                (true, _) => FIELD_HIDDEN,
                (false, Some(known)) => known.r#type,
                (false, None) => FIELD_TEXT,
            };
            Ok(Field {
                r#type,
                name: encrypt_opt(&field.name, key)?,
                value: encrypt_opt(&field.value, key)?,
                linked_id: kept.and_then(|known| known.linked_id),
                extra: item.carry(known.map(|known| &known.extra))?,
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// The draft of a cipher with `viewPassword: false` carries hidden fields without their value
/// (the user may not see it), so the stored ciphertext is kept. Matched by name rather than only by
/// position, so deleting an earlier field cannot hand one secret to another field.
fn stored_hidden_field<'a>(
    field: &CustomField,
    index: usize,
    base_fields: &'a [Field],
    item: &ItemKeys,
) -> Result<Option<&'a Field>> {
    let same = |known: &Field| -> Result<bool> {
        Ok(known.r#type == FIELD_HIDDEN
            && *decrypt_text(known.name.as_deref(), &item.key)? == *field.name)
    };
    if let Some(known) = base_fields.get(index)
        && same(known)?
    {
        return Ok(Some(known));
    }
    for known in base_fields {
        if same(known)? {
            return Ok(Some(known));
        }
    }
    Ok(None)
}

fn identity_request(identity: &IdentityData, key: &SymmetricKey, extra: Extra) -> Result<Identity> {
    let enc = |plain: &str| encrypt_opt(plain, key);
    Ok(Identity {
        title: enc(&identity.title)?,
        first_name: enc(&identity.first_name)?,
        middle_name: enc(&identity.middle_name)?,
        last_name: enc(&identity.last_name)?,
        address1: enc(&identity.address1)?,
        address2: enc(&identity.address2)?,
        address3: enc(&identity.address3)?,
        city: enc(&identity.city)?,
        state: enc(&identity.state)?,
        postal_code: enc(&identity.postal_code)?,
        country: enc(&identity.country)?,
        company: enc(&identity.company)?,
        email: enc(&identity.email)?,
        phone: enc(&identity.phone)?,
        ssn: enc(&identity.ssn)?,
        username: enc(&identity.username)?,
        passport_number: enc(&identity.passport_number)?,
        license_number: enc(&identity.license_number)?,
        extra,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bwl_api::models::Cipher;

    use super::*;
    use crate::{
        reveal,
        testutil::{self, attachment, legacy_login, login, ring},
    };

    /// What the server would answer: the request's fields on the base cipher.
    fn stored(request: &CipherRequest, id: &str) -> Cipher {
        Cipher {
            id: id.into(),
            organization_id: request.organization_id.clone(),
            folder_id: request.folder_id.clone(),
            r#type: request.r#type,
            name: Some(request.name.clone()),
            notes: request.notes.clone(),
            favorite: request.favorite,
            edit: true,
            view_password: true,
            reprompt: request.reprompt,
            key: request.key.clone(),
            login: request.login.clone(),
            card: request.card.clone(),
            identity: request.identity.clone(),
            secure_note: request.secure_note.clone(),
            ssh_key: request.ssh_key.clone(),
            fields: request.fields.clone(),
            password_history: request.password_history.clone(),
            revision_date: "2026-11-08T18:00:00.000Z".into(),
            ..Cipher::default()
        }
    }

    fn sample_draft() -> ItemDraft {
        ItemDraft {
            name: "New login".into(),
            notes: Zeroizing::new("n".into()),
            folder_id: Some(Arc::from("f1")),
            organization_id: None,
            collection_ids: Vec::new(),
            favorite: true,
            reprompt: true,
            fields: vec![CustomField {
                name: "pin".into(),
                value: Zeroizing::new("1".into()),
                hidden: true,
            }],
            data: ItemData::Login {
                username: "me".into(),
                password: Zeroizing::new("first".into()),
                totp: Zeroizing::default(),
                uris: vec!["https://a.example".into(), "  ".into()],
            },
            revision_date: None,
        }
    }

    fn set_password(draft: &mut ItemDraft, value: &str) {
        if let ItemData::Login { password, .. } = &mut draft.data {
            *password = Zeroizing::new(value.into());
        }
    }

    #[test]
    fn new_items_get_their_own_key_and_round_trip() {
        let keys = ring();
        let draft = sample_draft();
        let prepared = prepare(&draft, None, &keys).unwrap();
        let request = &prepared.request;
        assert_eq!(request.r#type, 1);
        assert_eq!(request.reprompt, 1);
        assert!(request.last_known_revision_date.is_none());
        let wrapped = request.key.as_deref().unwrap();
        let item = SymmetricKey::from_bytes(
            &crate::keys::parse(wrapped)
                .unwrap()
                .decrypt(keys.user())
                .unwrap(),
        )
        .unwrap();
        assert_ne!(item.to_bytes(), keys.user().to_bytes());
        // Fields are under the item key, not the user key.
        assert!(decrypt_text(Some(&request.name), keys.user()).is_err());
        assert_eq!(
            &*decrypt_text(Some(&request.name), &item).unwrap(),
            "New login"
        );
        let login = request.login.as_ref().unwrap();
        assert!(login.totp.is_none(), "empty fields stay unset");
        assert_eq!(
            login.uris.as_ref().unwrap().len(),
            1,
            "blank URIs are dropped"
        );
        // printf 'https://a.example' | openssl dgst -sha256 -binary | base64
        assert_eq!(
            &*decrypt_text(
                login.uris.as_ref().unwrap()[0].uri_checksum.as_deref(),
                &item
            )
            .unwrap(),
            "OGEsllqcTDXXE0OZGYBK2WDrVNCtQbQ2L/2FND1Lu08="
        );
        assert!(request.extra.is_empty() && login.extra.is_empty());

        let back = reveal::draft(&stored(request, "id1"), &keys).unwrap();
        let mut expected = draft;
        if let ItemData::Login { uris, .. } = &mut expected.data {
            uris.truncate(1);
        }
        expected.revision_date = Some(Arc::from("2026-11-08T18:00:00.000Z"));
        assert!(back == expected);
    }

    #[test]
    fn updates_keep_the_item_key_and_record_the_replaced_password() {
        let keys = ring();
        let base = login("l1", "GitHub", "octocat", "old-pass", &keys);
        let mut draft = reveal::draft(&base, &keys).unwrap();
        set_password(&mut draft, "new-pass");
        let request = prepare(&draft, Some(&base), &keys).unwrap().request;
        assert_eq!(request.key, base.key);
        assert_eq!(
            request.last_known_revision_date.as_deref(),
            Some(base.revision_date.as_str())
        );
        let item = keys.cipher_key(&base).unwrap();
        let history = request.password_history.as_deref().unwrap();
        let olds: Vec<_> = history
            .iter()
            .map(|entry| {
                decrypt_text(Some(&entry.password), &item)
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(olds, ["old-pass", "older"]);
        let login = request.login.as_ref().unwrap();
        assert!(login.password_revision_date.is_some());
        // The custom field kept its boolean type and the first URI its match rule.
        assert_eq!(request.fields.as_ref().unwrap()[1].r#type, FIELD_BOOLEAN);
        assert_eq!(login.uris.as_ref().unwrap()[0].r#match, Some(3));

        let unchanged = prepare(&reveal::draft(&base, &keys).unwrap(), Some(&base), &keys).unwrap();
        assert_eq!(
            unchanged.request.password_history.as_ref().unwrap().len(),
            1
        );
        assert!(
            unchanged
                .request
                .login
                .unwrap()
                .password_revision_date
                .is_none()
        );
    }

    #[test]
    fn history_is_capped_at_five() {
        let keys = ring();
        let mut base = login("l1", "GitHub", "u", "p0", &keys);
        for round in 1..=7 {
            let mut draft = reveal::draft(&base, &keys).unwrap();
            set_password(&mut draft, &format!("p{round}"));
            let request = prepare(&draft, Some(&base), &keys).unwrap().request;
            base = stored(&request, "l1");
        }
        let item = keys.cipher_key(&base).unwrap();
        let history: Vec<_> = base
            .password_history
            .as_deref()
            .unwrap()
            .iter()
            .map(|entry| {
                decrypt_text(Some(&entry.password), &item)
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(history, ["p6", "p5", "p4", "p3", "p2"]);
    }

    #[test]
    fn legacy_items_are_upgraded_unless_attachments_depend_on_the_old_key() {
        let keys = ring();
        let mut base = legacy_login("l1", "Old", "pw", &keys);
        base.password_history = Some(vec![PasswordHistory {
            password: testutil::enc("ancient", keys.user()).unwrap(),
            last_used_date: "2025-01-01T00:00:00.000Z".into(),
            ..PasswordHistory::default()
        }]);
        let draft = reveal::draft(&base, &keys).unwrap();
        let upgraded = prepare(&draft, Some(&base), &keys).unwrap().request;
        assert!(upgraded.key.is_some());
        let after = stored(&upgraded, "l1");
        let expected = ItemDraft {
            revision_date: Some(Arc::from(after.revision_date.as_str())),
            ..draft.clone()
        };
        assert!(reveal::draft(&after, &keys).unwrap() == expected);
        let item = keys.cipher_key(&after).unwrap();
        let history = upgraded.password_history.as_deref().unwrap();
        assert_eq!(
            &*decrypt_text(Some(&history[0].password), &item).unwrap(),
            "ancient"
        );

        base.attachments = Some(vec![attachment("a1", "file.txt", keys.user())]);
        let kept = prepare(&draft, Some(&base), &keys).unwrap().request;
        assert!(
            kept.key.is_none(),
            "attachment keys are wrapped by the user key"
        );
        assert_eq!(
            &*decrypt_text(Some(&kept.name), keys.user()).unwrap(),
            "Old"
        );
    }

    #[test]
    fn hidden_custom_fields_of_masked_items_keep_the_stored_value() {
        let keys = ring();
        let mut base = legacy_login("l1", "Shared", "secret", &keys);
        base.view_password = false;
        base.fields = Some(vec![
            Field {
                r#type: FIELD_HIDDEN,
                name: crate::testutil::enc("first", keys.user()),
                value: crate::testutil::enc("first secret", keys.user()),
                ..Field::default()
            },
            Field {
                r#type: FIELD_HIDDEN,
                name: crate::testutil::enc("second", keys.user()),
                value: crate::testutil::enc("second secret", keys.user()),
                ..Field::default()
            },
        ]);
        let mut draft = reveal::draft(&base, &keys).unwrap();
        assert!(draft.fields.iter().all(|field| field.value.is_empty()));
        draft.fields.remove(0);
        let request = prepare(&draft, Some(&base), &keys).unwrap().request;
        let saved = request.fields.unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].r#type, FIELD_HIDDEN);
        assert_eq!(
            &*decrypt_text(saved[0].value.as_deref(), keys.user()).unwrap(),
            "second secret"
        );

        let renamed = {
            let mut draft = reveal::draft(&base, &keys).unwrap();
            draft.fields[0].name = "renamed".into();
            draft
        };
        assert!(matches!(
            prepare(&renamed, Some(&base), &keys),
            Err(Error::ReadOnly)
        ));
        let unhidden = {
            let mut draft = reveal::draft(&base, &keys).unwrap();
            draft.fields[1].hidden = false;
            draft
        };
        assert!(matches!(
            prepare(&unhidden, Some(&base), &keys),
            Err(Error::ReadOnly)
        ));
    }

    #[test]
    fn hidden_passwords_are_kept_as_stored() {
        let keys = ring();
        let mut base = legacy_login("l1", "Shared", "secret", &keys);
        base.view_password = false;
        let draft = reveal::draft(&base, &keys).unwrap();
        let request = prepare(&draft, Some(&base), &keys).unwrap().request;
        assert!(request.key.is_none());
        assert_eq!(
            request.login.unwrap().password,
            base.login.unwrap().password
        );
    }

    #[test]
    fn a_cleared_uri_does_not_hand_its_match_rule_to_the_next_one() {
        let keys = ring();
        let mut base = login("l1", "GitHub", "u", "p", &keys);
        let stored_uris = base.login.as_mut().unwrap().uris.as_mut().unwrap();
        stored_uris[0]
            .extra
            .insert("futureUri".into(), serde_json::json!("first only"));
        stored_uris[1].r#match = Some(1);
        let mut draft = reveal::draft(&base, &keys).unwrap();
        if let ItemData::Login { uris, .. } = &mut draft.data {
            uris[0] = String::new();
        }
        let request = prepare(&draft, Some(&base), &keys).unwrap().request;
        let saved = request.login.unwrap().uris.unwrap();
        assert_eq!(saved.len(), 1);
        let item = keys.cipher_key(&base).unwrap();
        assert_eq!(
            &*decrypt_text(saved[0].uri.as_deref(), &item).unwrap(),
            "https://second.example.org"
        );
        assert_eq!(saved[0].r#match, Some(1), "the second URI's own rule");
        assert!(saved[0].extra.is_empty(), "{:?}", saved[0].extra);
    }

    #[test]
    fn an_update_from_a_draft_of_another_revision_is_a_conflict() {
        let keys = ring();
        let base = login("l1", "GitHub", "u", "p", &keys);
        let draft = reveal::draft(&base, &keys).unwrap();
        let moved = Cipher {
            revision_date: "2026-11-09T09:00:00.000Z".into(),
            ..base.clone()
        };
        assert!(matches!(
            prepare(&draft, Some(&moved), &keys),
            Err(Error::Conflict)
        ));
        let unknown = ItemDraft {
            revision_date: None,
            ..draft
        };
        assert!(matches!(
            prepare(&unknown, Some(&base), &keys),
            Err(Error::Conflict)
        ));
    }

    #[test]
    fn refused_updates() {
        let keys = ring();
        let base = login("l1", "GitHub", "u", "p", &keys);
        let draft = reveal::draft(&base, &keys).unwrap();

        let read_only = Cipher {
            edit: false,
            ..base.clone()
        };
        assert!(matches!(
            prepare(&draft, Some(&read_only), &keys),
            Err(Error::ReadOnly)
        ));

        let mut to_org = draft.clone();
        to_org.organization_id = Some(Arc::from("o1"));
        assert!(matches!(
            prepare(&to_org, Some(&base), &keys),
            Err(Error::Api(_))
        ));

        let mut retyped = draft;
        retyped.data = ItemData::SecureNote;
        assert!(matches!(
            prepare(&retyped, Some(&base), &keys),
            Err(Error::Api(_))
        ));

        let mut unknown_org = sample_draft();
        unknown_org.organization_id = Some(Arc::from("o1"));
        assert!(matches!(
            prepare(&unknown_org, None, &keys),
            Err(Error::Crypto(_))
        ));
    }
}
