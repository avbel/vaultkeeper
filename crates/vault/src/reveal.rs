//! Decrypt-on-demand: single fields for copy buttons, TOTP codes and the full draft.

use std::sync::Arc;

use vk_api::models::{Cipher, cipher_type};
use vk_crypto::SymmetricKey;
use vk_gen::totp::{Totp, TotpCode};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    keys::{KeyRing, decrypt_text},
    model::{CopyField, CustomField, IdentityData, ItemData, ItemDraft},
};

const FIELD_HIDDEN: u8 = 1;

pub(crate) fn reveal(
    cipher: &Cipher,
    keys: &KeyRing,
    field: CopyField,
    unix_time: u64,
) -> Result<Zeroizing<String>> {
    let key = keys.cipher_key(cipher)?;
    let value = match field {
        CopyField::Totp => return totp_code(cipher, &key, unix_time).map(|code| code.code),
        CopyField::Notes => decrypt_text(cipher.notes.as_deref(), &key)?,
        CopyField::Custom(index) => {
            let field = cipher
                .fields
                .as_deref()
                .and_then(|fields| fields.get(index))
                .ok_or(Error::NoSuchField)?;
            if field.r#type == FIELD_HIDDEN && !cipher.view_password {
                return Err(Error::NoSuchField);
            }
            decrypt_text(field.value.as_deref(), &key)?
        }
        CopyField::Username => match cipher.r#type {
            cipher_type::LOGIN => login_field(cipher, &key, |login| login.username.as_deref())?,
            cipher_type::IDENTITY => {
                identity_field(cipher, &key, |identity| identity.username.as_deref())?
            }
            _ => return Err(Error::NoSuchField),
        },
        CopyField::Password => {
            if !cipher.view_password {
                return Err(Error::NoSuchField);
            }
            login_field(cipher, &key, |login| login.password.as_deref())?
        }
        CopyField::Uri => {
            let login = cipher.login.as_ref().ok_or(Error::NoSuchField)?;
            let first = login
                .uris
                .as_deref()
                .and_then(|uris| uris.first())
                .ok_or(Error::NoSuchField)?;
            decrypt_text(first.uri.as_deref(), &key)?
        }
        CopyField::CardNumber => card_field(cipher, &key, |card| card.number.as_deref())?,
        CopyField::CardCode => card_field(cipher, &key, |card| card.code.as_deref())?,
        CopyField::Email => identity_field(cipher, &key, |identity| identity.email.as_deref())?,
        CopyField::Phone => identity_field(cipher, &key, |identity| identity.phone.as_deref())?,
        CopyField::SshPublicKey => ssh_field(cipher, &key, |ssh| ssh.public_key.as_deref())?,
        CopyField::SshPrivateKey => ssh_field(cipher, &key, |ssh| ssh.private_key.as_deref())?,
    };
    if value.is_empty() {
        return Err(Error::NoSuchField);
    }
    Ok(value)
}

pub(crate) fn totp(cipher: &Cipher, keys: &KeyRing, unix_time: u64) -> Result<TotpCode> {
    let key = keys.cipher_key(cipher)?;
    totp_code(cipher, &key, unix_time)
}

fn totp_code(cipher: &Cipher, key: &SymmetricKey, unix_time: u64) -> Result<TotpCode> {
    let secret = login_field(cipher, key, |login| login.totp.as_deref())?;
    if secret.is_empty() {
        return Err(Error::NoSuchField);
    }
    Ok(Totp::parse(&secret)?.generate(unix_time))
}

fn login_field(
    cipher: &Cipher,
    key: &SymmetricKey,
    pick: impl Fn(&vk_api::models::Login) -> Option<&str>,
) -> Result<Zeroizing<String>> {
    let login = cipher.login.as_ref().ok_or(Error::NoSuchField)?;
    decrypt_text(pick(login), key)
}

fn card_field(
    cipher: &Cipher,
    key: &SymmetricKey,
    pick: impl Fn(&vk_api::models::Card) -> Option<&str>,
) -> Result<Zeroizing<String>> {
    let card = cipher.card.as_ref().ok_or(Error::NoSuchField)?;
    decrypt_text(pick(card), key)
}

fn identity_field(
    cipher: &Cipher,
    key: &SymmetricKey,
    pick: impl Fn(&vk_api::models::Identity) -> Option<&str>,
) -> Result<Zeroizing<String>> {
    let identity = cipher.identity.as_ref().ok_or(Error::NoSuchField)?;
    decrypt_text(pick(identity), key)
}

fn ssh_field(
    cipher: &Cipher,
    key: &SymmetricKey,
    pick: impl Fn(&vk_api::models::SshKey) -> Option<&str>,
) -> Result<Zeroizing<String>> {
    let ssh = cipher.ssh_key.as_ref().ok_or(Error::NoSuchField)?;
    decrypt_text(pick(ssh), key)
}

/// Plain `String` for fields the draft model keeps unprotected (names, usernames, URIs).
fn plain(field: Option<&str>, key: &SymmetricKey) -> Result<String> {
    Ok(decrypt_text(field, key)?.as_str().to_owned())
}

pub(crate) fn draft(cipher: &Cipher, keys: &KeyRing) -> Result<ItemDraft> {
    let key = keys.cipher_key(cipher)?;
    let data = match cipher.r#type {
        cipher_type::LOGIN => login_data(cipher, &key)?,
        cipher_type::SECURE_NOTE => ItemData::SecureNote,
        cipher_type::CARD => card_data(cipher, &key)?,
        cipher_type::IDENTITY => ItemData::Identity(Box::new(identity_data(cipher, &key)?)),
        cipher_type::SSH_KEY => ssh_data(cipher, &key)?,
        _ => return Err(Error::ReadOnly),
    };
    let fields = cipher
        .fields
        .as_deref()
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let hidden = field.r#type == FIELD_HIDDEN;
            // Like the password: "can edit, except passwords" members never see hidden values;
            // `encrypt` keeps the stored ciphertext for them.
            let value = if hidden && !cipher.view_password {
                Zeroizing::default()
            } else {
                decrypt_text(field.value.as_deref(), &key)?
            };
            Ok(CustomField {
                name: plain(field.name.as_deref(), &key)?,
                value,
                hidden,
                field_type: field.r#type,
                source_index: Some(index),
                withheld: hidden && !cipher.view_password,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ItemDraft {
        name: plain(cipher.name.as_deref(), &key)?,
        notes: decrypt_text(cipher.notes.as_deref(), &key)?,
        folder_id: cipher.folder_id.as_deref().map(Arc::from),
        organization_id: cipher.organization_id.as_deref().map(Arc::from),
        collection_ids: cipher
            .collection_ids
            .iter()
            .map(|id| Arc::from(id.as_str()))
            .collect(),
        favorite: cipher.favorite,
        reprompt: cipher.reprompt == 1,
        fields,
        data,
        revision_date: Some(Arc::from(cipher.revision_date.as_str())),
    })
}

fn login_data(cipher: &Cipher, key: &SymmetricKey) -> Result<ItemData> {
    let Some(login) = &cipher.login else {
        return Ok(ItemData::Login {
            username: String::new(),
            password: Zeroizing::default(),
            totp: Zeroizing::default(),
            uris: Vec::new(),
        });
    };
    let uris = login
        .uris
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|uri| plain(uri.uri.as_deref(), key))
        .collect::<Result<Vec<_>>>()?;
    let password = if cipher.view_password {
        decrypt_text(login.password.as_deref(), key)?
    } else {
        Zeroizing::default()
    };
    Ok(ItemData::Login {
        username: plain(login.username.as_deref(), key)?,
        password,
        totp: decrypt_text(login.totp.as_deref(), key)?,
        uris,
    })
}

fn card_data(cipher: &Cipher, key: &SymmetricKey) -> Result<ItemData> {
    let card = cipher.card.clone().unwrap_or_default();
    Ok(ItemData::Card {
        cardholder_name: plain(card.cardholder_name.as_deref(), key)?,
        brand: plain(card.brand.as_deref(), key)?,
        number: decrypt_text(card.number.as_deref(), key)?,
        exp_month: plain(card.exp_month.as_deref(), key)?,
        exp_year: plain(card.exp_year.as_deref(), key)?,
        code: decrypt_text(card.code.as_deref(), key)?,
    })
}

fn identity_data(cipher: &Cipher, key: &SymmetricKey) -> Result<IdentityData> {
    let Some(identity) = &cipher.identity else {
        return Ok(IdentityData::default());
    };
    let text = |field: &Option<String>| plain(field.as_deref(), key);
    let secret = |field: &Option<String>| decrypt_text(field.as_deref(), key);
    Ok(IdentityData {
        title: text(&identity.title)?,
        first_name: text(&identity.first_name)?,
        middle_name: text(&identity.middle_name)?,
        last_name: text(&identity.last_name)?,
        address1: text(&identity.address1)?,
        address2: text(&identity.address2)?,
        address3: text(&identity.address3)?,
        city: text(&identity.city)?,
        state: text(&identity.state)?,
        postal_code: text(&identity.postal_code)?,
        country: text(&identity.country)?,
        company: text(&identity.company)?,
        email: text(&identity.email)?,
        phone: text(&identity.phone)?,
        ssn: secret(&identity.ssn)?,
        username: text(&identity.username)?,
        passport_number: secret(&identity.passport_number)?,
        license_number: secret(&identity.license_number)?,
    })
}

fn ssh_data(cipher: &Cipher, key: &SymmetricKey) -> Result<ItemData> {
    let ssh = cipher.ssh_key.clone().unwrap_or_default();
    Ok(ItemData::SshKey {
        private_key: decrypt_text(ssh.private_key.as_deref(), key)?,
        public_key: plain(ssh.public_key.as_deref(), key)?,
        fingerprint: plain(ssh.key_fingerprint.as_deref(), key)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{card, identity, legacy_login, login, note, ring, ssh};

    #[test]
    fn copy_fields_decrypt_one_value_each() {
        let keys = ring();
        let github = login("l1", "GitHub", "octocat", "hunter2", &keys);
        let get = |cipher: &Cipher, field| {
            reveal(cipher, &keys, field, 59).map(|value| value.to_string())
        };
        assert_eq!(get(&github, CopyField::Username).unwrap(), "octocat");
        assert_eq!(get(&github, CopyField::Password).unwrap(), "hunter2");
        assert_eq!(
            get(&github, CopyField::Uri).unwrap(),
            "https://Example.com/login"
        );
        assert_eq!(get(&github, CopyField::Notes).unwrap(), "login notes");
        assert_eq!(get(&github, CopyField::Custom(0)).unwrap(), "4321");
        // RFC 6238 appendix B, SHA-1 at T = 59 s, last 6 digits.
        assert_eq!(get(&github, CopyField::Totp).unwrap(), "287082");
        assert!(matches!(
            get(&github, CopyField::Custom(5)),
            Err(Error::NoSuchField)
        ));
        assert!(matches!(
            get(&github, CopyField::CardNumber),
            Err(Error::NoSuchField)
        ));

        let visa = card("c1", "Visa", &keys);
        assert_eq!(
            get(&visa, CopyField::CardNumber).unwrap(),
            "4111111111114242"
        );
        assert_eq!(get(&visa, CopyField::CardCode).unwrap(), "123");
        assert!(matches!(
            get(&visa, CopyField::Username),
            Err(Error::NoSuchField)
        ));

        let me = identity("i1", "Me", "ada@example.com", &keys);
        assert_eq!(get(&me, CopyField::Email).unwrap(), "ada@example.com");
        assert_eq!(get(&me, CopyField::Phone).unwrap(), "+44 20 7946 0000");
        assert_eq!(get(&me, CopyField::Username).unwrap(), "ada.l");

        let key = ssh("s1", "Key", &keys);
        assert_eq!(
            get(&key, CopyField::SshPublicKey).unwrap(),
            "ssh-ed25519 AAAAC3Nza test@example"
        );
        assert!(
            get(&key, CopyField::SshPrivateKey)
                .unwrap()
                .starts_with("-----BEGIN OPENSSH")
        );

        let empty = note("n1", "Note", &keys);
        assert!(matches!(
            get(&empty, CopyField::Totp),
            Err(Error::NoSuchField)
        ));
        assert_eq!(get(&empty, CopyField::Notes).unwrap(), "note body");
        assert_eq!(
            get(&legacy_login("l2", "Old", "pw", &keys), CopyField::Password).unwrap(),
            "pw"
        );
    }

    #[test]
    fn hidden_passwords_are_not_revealed() {
        let keys = ring();
        let mut cipher = login("l1", "Shared", "u", "secret", &keys);
        cipher.view_password = false;
        assert!(matches!(
            reveal(&cipher, &keys, CopyField::Password, 0),
            Err(Error::NoSuchField)
        ));
        let Ok(ItemDraft {
            data: ItemData::Login { password, .. },
            ..
        }) = draft(&cipher, &keys)
        else {
            panic!("login draft");
        };
        assert!(password.is_empty());
    }

    #[test]
    fn hidden_custom_fields_follow_view_password() {
        let keys = ring();
        let mut cipher = login("l1", "Shared", "u", "secret", &keys);
        cipher.view_password = false;
        // Field 0 of the fixture is hidden ("pin" = "4321"), field 1 a boolean ("flag" = "true").
        assert!(matches!(
            reveal(&cipher, &keys, CopyField::Custom(0), 0),
            Err(Error::NoSuchField)
        ));
        assert_eq!(
            &*reveal(&cipher, &keys, CopyField::Custom(1), 0).unwrap(),
            "true"
        );
        let fields = draft(&cipher, &keys).unwrap().fields;
        assert!(fields[0].hidden && fields[0].value.is_empty());
        assert_eq!(fields[0].name, "pin");
        assert_eq!(&*fields[1].value, "true");
    }

    #[test]
    fn totp_reports_the_period_and_rejects_bad_secrets() {
        let keys = ring();
        let github = login("l1", "GitHub", "u", "p", &keys);
        let code = totp(&github, &keys, 59).unwrap();
        assert_eq!(&*code.code, "287082");
        assert_eq!(code.period, 30);
        assert_eq!(code.remaining, 1);

        let (mut bad, item) = crate::testutil::keyed("l2", 1, "Bad", &keys);
        bad.login = Some(vk_api::models::Login {
            totp: crate::testutil::enc("not base32 !", &item),
            ..vk_api::models::Login::default()
        });
        assert!(matches!(totp(&bad, &keys, 59), Err(Error::Gen(_))));
    }

    #[test]
    fn drafts_decrypt_every_field() {
        let keys = ring();
        let github = draft(&login("l1", "GitHub", "octocat", "hunter2", &keys), &keys).unwrap();
        assert_eq!(github.name, "GitHub");
        assert_eq!(&*github.notes, "login notes");
        assert_eq!(github.fields.len(), 2);
        assert!(github.fields[0].hidden && !github.fields[1].hidden);
        assert_eq!(&*github.fields[1].value, "true");
        let ItemData::Login {
            username,
            password,
            totp,
            uris,
        } = &github.data
        else {
            panic!("login");
        };
        assert_eq!(username, "octocat");
        assert_eq!(&**password, "hunter2");
        assert_eq!(&**totp, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(
            uris,
            &["https://Example.com/login", "https://second.example.org"]
        );

        let ItemData::Card {
            number,
            brand,
            exp_year,
            ..
        } = draft(&card("c1", "Visa", &keys), &keys).unwrap().data
        else {
            panic!("card");
        };
        assert_eq!(
            (number.as_str(), brand.as_str(), exp_year.as_str()),
            ("4111111111114242", "Visa", "2031")
        );

        let ItemData::Identity(me) = draft(&identity("i1", "Me", "a@b.c", &keys), &keys)
            .unwrap()
            .data
        else {
            panic!("identity");
        };
        assert_eq!(
            (me.first_name.as_str(), me.ssn.as_str()),
            ("Ada", "078-05-1120")
        );

        let ItemData::SshKey { fingerprint, .. } =
            draft(&ssh("s1", "Key", &keys), &keys).unwrap().data
        else {
            panic!("ssh");
        };
        assert_eq!(fingerprint, "SHA256:fingerprint");
        assert!(draft(&note("n1", "N", &keys), &keys).unwrap().data == ItemData::SecureNote);

        let unsupported = Cipher {
            r#type: 7,
            ..note("x", "Passkey", &keys)
        };
        assert!(matches!(draft(&unsupported, &keys), Err(Error::ReadOnly)));
    }
}
