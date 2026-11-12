use std::sync::Arc;

use vk_api::models::{Cipher, cipher_type};
use zeroize::Zeroizing;

use super::Vault;
use crate::{
    Error, Result,
    keys::{CipherKey, KeyRing, decrypt_text},
    model::{BOOLEAN_FIELD, CLI_ACCESS_FIELD, CliLoginField, CliLoginKey},
};

impl Vault {
    /// Only explicitly shared logins in the current unlocked account.
    pub fn cli_login_keys(&self) -> Result<Vec<CliLoginKey>> {
        self.inner.read_unlocked(|_, unlocked| {
            Ok(unlocked
                .data
                .login_entries()
                .filter(|entry| allowed_key(&entry.cipher, &unlocked.keys).is_some())
                .map(|entry| CliLoginKey {
                    key: Arc::clone(&entry.summary.id.0),
                    title: Arc::clone(&entry.summary.name),
                })
                .collect())
        })
    }

    pub fn cli_login_fields(&self, id: &str) -> Result<Vec<CliLoginField>> {
        self.inner.read_unlocked(|_, unlocked| {
            let entry = unlocked.data.entry(id).ok_or(Error::NotFound)?;
            let key = allowed_key(&entry.cipher, &unlocked.keys).ok_or(Error::NotFound)?;
            Ok(login_fields(&entry.cipher, &key)
                .filter(|(_, encrypted)| {
                    decrypt_text(Some(encrypted), &key).is_ok_and(|value| !value.is_empty())
                })
                .map(|(field, _)| field)
                .collect())
        })
    }

    /// Returns `None` when the selected field requires explicit private access.
    pub fn cli_login_value(
        &self,
        id: &str,
        field: &str,
        allow_private: bool,
    ) -> Result<Option<Zeroizing<String>>> {
        self.inner.read_unlocked(|_, unlocked| {
            let entry = unlocked.data.entry(id).ok_or(Error::NotFound)?;
            let key = allowed_key(&entry.cipher, &unlocked.keys).ok_or(Error::NotFound)?;
            let (field, encrypted) = login_fields(&entry.cipher, &key)
                .find(|(candidate, _)| candidate.field == field)
                .ok_or(Error::NoSuchField)?;
            if field.private && !allow_private {
                return Ok(None);
            }
            let value = decrypt_text(Some(encrypted), &key)?;
            if value.is_empty() {
                return Err(Error::NoSuchField);
            }
            Ok(Some(value))
        })
    }
}

fn login_fields<'a>(
    cipher: &'a Cipher,
    key: &'a CipherKey<'_>,
) -> impl Iterator<Item = (CliLoginField, &'a str)> {
    let builtins = cipher.login.iter().flat_map(|login| {
        [
            ("title", "Title", false, cipher.name.as_deref()),
            ("username", "Username", false, login.username.as_deref()),
            ("password", "Password", true, login.password.as_deref()),
            ("totp", "TOTP seed", true, login.totp.as_deref()),
            ("notes", "Notes", false, cipher.notes.as_deref()),
        ]
        .into_iter()
        .filter_map(|(field, label, private, encrypted)| {
            let encrypted = encrypted?;
            Some((
                CliLoginField {
                    field: field.into(),
                    label: label.into(),
                    private,
                },
                encrypted,
            ))
        })
    });
    let uris = cipher
        .login
        .as_ref()
        .and_then(|login| login.uris.as_deref())
        .unwrap_or_default()
        .iter()
        .enumerate()
        .filter_map(|(index, uri)| {
            let encrypted = uri.uri.as_deref()?;
            let number = index + 1;
            Some((
                CliLoginField {
                    field: format!("uri:{number}"),
                    label: format!("URI {number}"),
                    private: false,
                },
                encrypted,
            ))
        });
    let custom = cipher
        .fields
        .as_deref()
        .unwrap_or_default()
        .iter()
        .enumerate()
        .filter_map(|(index, field)| {
            let encrypted = field.value.as_deref()?;
            let name = decrypt_text(field.name.as_deref(), key).ok()?;
            if name.as_str() == CLI_ACCESS_FIELD {
                return None;
            }
            Some((
                CliLoginField {
                    field: format!("custom:{}", index + 1),
                    label: name.to_string(),
                    private: !matches!(field.r#type, 0 | BOOLEAN_FIELD),
                },
                encrypted,
            ))
        });
    builtins.chain(uris).chain(custom)
}

fn allowed_key<'a>(cipher: &Cipher, keys: &'a KeyRing) -> Option<CipherKey<'a>> {
    if cipher.r#type != cipher_type::LOGIN
        || cipher.login.is_none()
        || cipher.deleted_date.is_some()
        || !cipher.view_password
        || cipher.reprompt != 0
    {
        return None;
    }
    let fields = cipher
        .fields
        .as_deref()
        .filter(|fields| !fields.is_empty())?;
    let key = keys.cipher_key(cipher).ok()?;
    let mut permission = None;
    for field in fields {
        if decrypt_text(field.name.as_deref(), &key).ok()?.as_str() == CLI_ACCESS_FIELD
            && (field.r#type != BOOLEAN_FIELD || permission.replace(field).is_some())
        {
            return None;
        }
    }
    let permission = permission?;
    (decrypt_text(permission.value.as_deref(), &key)
        .ok()?
        .as_str()
        == "true")
        .then_some(key)
}

#[cfg(test)]
mod tests {
    use vk_api::models::Field;

    use super::*;
    use crate::testutil::{enc, login, ring};

    #[test]
    fn an_exact_unambiguous_boolean_is_required() {
        let keys = ring();
        let mut cipher = login("a", "Login", "name", "password", &keys);
        assert!(allowed_key(&cipher, &keys).is_none());
        let key = keys.cipher_key(&cipher).expect("item key");
        let marker = |kind, value| Field {
            r#type: kind,
            name: enc(CLI_ACCESS_FIELD, &key),
            value: enc(value, &key),
            ..Field::default()
        };
        for (field, allowed) in [
            (marker(BOOLEAN_FIELD, "true"), true),
            (marker(BOOLEAN_FIELD, "false"), false),
            (marker(BOOLEAN_FIELD, "TRUE"), false),
            (marker(0, "true"), false),
            (
                Field {
                    value: None,
                    ..marker(BOOLEAN_FIELD, "true")
                },
                false,
            ),
        ] {
            cipher.fields = Some(vec![field]);
            assert_eq!(allowed_key(&cipher, &keys).is_some(), allowed);
        }
        cipher.fields = Some(vec![marker(BOOLEAN_FIELD, "true"), marker(0, "false")]);
        assert!(allowed_key(&cipher, &keys).is_none());
        cipher.fields = Some(vec![marker(BOOLEAN_FIELD, "true")]);
        assert!(allowed_key(&cipher, &keys).is_some());

        cipher.view_password = false;
        assert!(allowed_key(&cipher, &keys).is_none());
        cipher.view_password = true;
        cipher.reprompt = 1;
        assert!(allowed_key(&cipher, &keys).is_none());
        cipher.reprompt = 0;
        cipher.deleted_date = Some("deleted".into());
        assert!(allowed_key(&cipher, &keys).is_none());
        cipher.deleted_date = None;
        cipher.r#type = cipher_type::SECURE_NOTE;
        assert!(allowed_key(&cipher, &keys).is_none());
    }
}
