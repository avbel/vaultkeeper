//! Edit form: one generic field list per item kind, mapped back onto the draft on save.

use vk_vault::model::{IdentityData, ItemData, ItemDraft, ItemKind};
use zeroize::Zeroizing;

use crate::ui::EditField;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EditError {
    #[error("Name is required")]
    NameRequired,
    #[error("Unsupported items cannot be edited")]
    Unsupported,
}

#[derive(Clone, Copy)]
struct Spec {
    secret: bool,
    multiline: bool,
    mono: bool,
    generate: bool,
}

const TEXT: Spec = Spec {
    secret: false,
    multiline: false,
    mono: false,
    generate: false,
};
const SECRET: Spec = Spec {
    secret: true,
    mono: true,
    ..TEXT
};
const MONO: Spec = Spec { mono: true, ..TEXT };
const MULTILINE: Spec = Spec {
    multiline: true,
    ..TEXT
};

fn field(key: &str, label: &str, value: &str, spec: Spec) -> EditField {
    EditField {
        key: key.into(),
        label: label.into(),
        value: value.into(),
        secret: spec.secret,
        multiline: spec.multiline,
        mono: spec.mono,
        generate: spec.generate,
    }
}

const IDENTITY_KEYS: [(&str, &str); 18] = [
    ("title", "Title"),
    ("first_name", "First name"),
    ("middle_name", "Middle name"),
    ("last_name", "Last name"),
    ("company", "Company"),
    ("email", "Email"),
    ("phone", "Phone"),
    ("address1", "Address 1"),
    ("address2", "Address 2"),
    ("address3", "Address 3"),
    ("city", "City"),
    ("state", "State"),
    ("postal_code", "Postal code"),
    ("country", "Country"),
    ("username", "Username"),
    ("ssn", "SSN"),
    ("passport_number", "Passport number"),
    ("license_number", "License number"),
];

fn identity_value<'a>(identity: &'a IdentityData, key: &str) -> &'a str {
    match key {
        "title" => &identity.title,
        "first_name" => &identity.first_name,
        "middle_name" => &identity.middle_name,
        "last_name" => &identity.last_name,
        "company" => &identity.company,
        "email" => &identity.email,
        "phone" => &identity.phone,
        "address1" => &identity.address1,
        "address2" => &identity.address2,
        "address3" => &identity.address3,
        "city" => &identity.city,
        "state" => &identity.state,
        "postal_code" => &identity.postal_code,
        "country" => &identity.country,
        "username" => &identity.username,
        "ssn" => &identity.ssn,
        "passport_number" => &identity.passport_number,
        "license_number" => &identity.license_number,
        _ => "",
    }
}

fn set_identity(identity: &mut IdentityData, key: &str, value: &str) {
    let target = match key {
        "title" => &mut identity.title,
        "first_name" => &mut identity.first_name,
        "middle_name" => &mut identity.middle_name,
        "last_name" => &mut identity.last_name,
        "company" => &mut identity.company,
        "email" => &mut identity.email,
        "phone" => &mut identity.phone,
        "address1" => &mut identity.address1,
        "address2" => &mut identity.address2,
        "address3" => &mut identity.address3,
        "city" => &mut identity.city,
        "state" => &mut identity.state,
        "postal_code" => &mut identity.postal_code,
        "country" => &mut identity.country,
        "username" => &mut identity.username,
        "ssn" => {
            identity.ssn = Zeroizing::new(value.to_owned());
            return;
        }
        "passport_number" => {
            identity.passport_number = Zeroizing::new(value.to_owned());
            return;
        }
        "license_number" => {
            identity.license_number = Zeroizing::new(value.to_owned());
            return;
        }
        _ => return,
    };
    value.clone_into(target);
}

fn data_fields(data: &ItemData, out: &mut Vec<EditField>) {
    match data {
        ItemData::Login {
            username,
            password,
            totp,
            uris,
        } => {
            out.push(field("username", "Username", username, TEXT));
            let generate = Spec {
                generate: true,
                ..SECRET
            };
            out.push(field("password", "Password", password, generate));
            out.push(field("totp", "Authenticator key (TOTP)", totp, SECRET));
            let uris = if uris.is_empty() {
                &[String::new()][..]
            } else {
                uris
            };
            for (index, uri) in uris.iter().enumerate() {
                out.push(field(
                    &format!("uri:{index}"),
                    &format!("URI {}", index + 1),
                    uri,
                    TEXT,
                ));
            }
        }
        ItemData::Card {
            cardholder_name,
            brand,
            number,
            exp_month,
            exp_year,
            code,
        } => {
            out.push(field(
                "cardholder",
                "Cardholder name",
                cardholder_name,
                TEXT,
            ));
            out.push(field("brand", "Brand", brand, TEXT));
            out.push(field("number", "Number", number, SECRET));
            out.push(field("exp_month", "Expiration month", exp_month, TEXT));
            out.push(field("exp_year", "Expiration year", exp_year, TEXT));
            out.push(field("code", "Security code", code, SECRET));
        }
        ItemData::Identity(identity) => {
            for (key, label) in IDENTITY_KEYS {
                let spec = if matches!(key, "ssn" | "passport_number" | "license_number") {
                    SECRET
                } else {
                    TEXT
                };
                out.push(field(key, label, identity_value(identity, key), spec));
            }
        }
        ItemData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => {
            let private = Spec {
                multiline: true,
                ..SECRET
            };
            out.push(field("private_key", "Private key", private_key, private));
            let wrapped = Spec {
                multiline: true,
                ..MONO
            };
            out.push(field("public_key", "Public key", public_key, wrapped));
            out.push(field("fingerprint", "Fingerprint", fingerprint, MONO));
        }
        ItemData::SecureNote => {}
    }
}

#[must_use]
pub fn edit_fields(draft: &ItemDraft) -> Vec<EditField> {
    let mut out = vec![field("name", "Name", &draft.name, TEXT)];
    data_fields(&draft.data, &mut out);
    for (index, custom) in draft.fields.iter().enumerate() {
        let spec = if custom.hidden { SECRET } else { TEXT };
        out.push(field(
            &format!("custom:{index}"),
            &custom.name,
            &custom.value,
            spec,
        ));
    }
    out.push(field("notes", "Notes", &draft.notes, MULTILINE));
    out
}

/// The next empty URI field for "+ Add URI".
#[must_use]
pub fn uri_field(index: usize) -> EditField {
    field(
        &format!("uri:{index}"),
        &format!("URI {}", index + 1),
        "",
        TEXT,
    )
}

fn indexed(key: &str, prefix: &str) -> Option<usize> {
    key.strip_prefix(prefix)?.parse().ok()
}

fn apply_data(data: &mut ItemData, key: &str, value: &str) {
    match data {
        ItemData::Login {
            username,
            password,
            totp,
            uris,
        } => match key {
            "username" => value.clone_into(username),
            "password" => *password = Zeroizing::new(value.to_owned()),
            "totp" => *totp = Zeroizing::new(value.trim().to_owned()),
            _ => {
                if let Some(index) = indexed(key, "uri:") {
                    if uris.len() <= index {
                        uris.resize(index + 1, String::new());
                    }
                    value.trim().clone_into(&mut uris[index]);
                }
            }
        },
        ItemData::Card {
            cardholder_name,
            brand,
            number,
            exp_month,
            exp_year,
            code,
        } => match key {
            "cardholder" => value.clone_into(cardholder_name),
            "brand" => value.clone_into(brand),
            "number" => *number = Zeroizing::new(value.to_owned()),
            "exp_month" => value.trim().clone_into(exp_month),
            "exp_year" => value.trim().clone_into(exp_year),
            "code" => *code = Zeroizing::new(value.to_owned()),
            _ => {}
        },
        ItemData::Identity(identity) => set_identity(identity, key, value),
        ItemData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => match key {
            "private_key" => *private_key = Zeroizing::new(value.to_owned()),
            "public_key" => value.trim().clone_into(public_key),
            "fingerprint" => value.trim().clone_into(fingerprint),
            _ => {}
        },
        ItemData::SecureNote => {}
    }
}

/// Applies the form's `(key, value)` pairs to `draft`. A cleared URI row stays as a blank entry
/// so every URI keeps its position, and with it its stored match rule; the vault drops blanks.
pub fn apply<'a>(
    mut draft: ItemDraft,
    values: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<ItemDraft, EditError> {
    for (key, value) in values {
        match key {
            "name" => value.trim().clone_into(&mut draft.name),
            "notes" => draft.notes = Zeroizing::new(value.to_owned()),
            _ => {
                if let Some(index) = indexed(key, "custom:")
                    && let Some(custom) = draft.fields.get_mut(index)
                {
                    custom.value = Zeroizing::new(value.to_owned());
                } else {
                    apply_data(&mut draft.data, key, value);
                }
            }
        }
    }
    if draft.name.is_empty() {
        return Err(EditError::NameRequired);
    }
    Ok(draft)
}

/// An empty draft for "+ New".
pub fn new_draft(
    kind: ItemKind,
    folder_id: Option<std::sync::Arc<str>>,
) -> Result<ItemDraft, EditError> {
    let data = match kind {
        ItemKind::Login => ItemData::Login {
            username: String::new(),
            password: Zeroizing::new(String::new()),
            totp: Zeroizing::new(String::new()),
            uris: Vec::new(),
        },
        ItemKind::SecureNote => ItemData::SecureNote,
        ItemKind::Card => ItemData::Card {
            cardholder_name: String::new(),
            brand: String::new(),
            number: Zeroizing::new(String::new()),
            exp_month: String::new(),
            exp_year: String::new(),
            code: Zeroizing::new(String::new()),
        },
        ItemKind::Identity => ItemData::Identity(Box::default()),
        ItemKind::SshKey => ItemData::SshKey {
            private_key: Zeroizing::new(String::new()),
            public_key: String::new(),
            fingerprint: String::new(),
        },
        ItemKind::Unsupported(_) => return Err(EditError::Unsupported),
    };
    Ok(ItemDraft {
        name: String::new(),
        notes: Zeroizing::new(String::new()),
        folder_id,
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: false,
        reprompt: false,
        fields: Vec::new(),
        data,
        revision_date: None,
    })
}

#[cfg(test)]
mod tests {
    use vk_vault::model::CustomField;

    use super::*;

    fn login() -> ItemDraft {
        let mut draft = new_draft(ItemKind::Login, None).expect("draft");
        draft.name = "GitHub".to_owned();
        draft.data = ItemData::Login {
            username: "octocat".to_owned(),
            password: Zeroizing::new("hunter2".to_owned()),
            totp: Zeroizing::new(String::new()),
            uris: vec!["https://github.com".to_owned()],
        };
        draft.fields = vec![CustomField {
            name: "PIN".to_owned(),
            value: Zeroizing::new("1234".to_owned()),
            hidden: true,
        }];
        draft
    }

    fn values(fields: &[EditField]) -> Vec<(String, String)> {
        fields
            .iter()
            .map(|field| (field.key.to_string(), field.value.to_string()))
            .collect()
    }

    fn apply_owned(draft: ItemDraft, pairs: &[(String, String)]) -> Result<ItemDraft, EditError> {
        apply(
            draft,
            pairs
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )
    }

    #[test]
    fn login_form_lists_fields_in_order() {
        let fields = edit_fields(&login());
        let keys: Vec<String> = fields.iter().map(|field| field.key.to_string()).collect();
        assert_eq!(
            keys,
            [
                "name", "username", "password", "totp", "uri:0", "custom:0", "notes"
            ]
        );
        let password = &fields[2];
        assert!(password.secret && password.generate && password.mono);
        assert_eq!(password.value, "hunter2");
        assert!(fields[6].multiline);
    }

    #[test]
    fn unchanged_form_round_trips() {
        let draft = login();
        let pairs = values(&edit_fields(&draft));
        let applied = apply_owned(draft.clone(), &pairs).expect("apply");
        assert!(applied == draft);
    }

    #[test]
    fn edits_are_applied_and_cleared_uris_keep_their_position() {
        let mut pairs = values(&edit_fields(&login()));
        for (key, value) in &mut pairs {
            match key.as_str() {
                "name" => *value = "  GitHub (work) ".to_owned(),
                "password" => *value = "correct horse".to_owned(),
                "custom:0" => *value = "9999".to_owned(),
                _ => {}
            }
        }
        pairs.push(("uri:1".to_owned(), String::new()));
        pairs.push(("uri:2".to_owned(), "https://gist.github.com".to_owned()));
        let applied = apply_owned(login(), &pairs).expect("apply");
        assert_eq!(applied.name, "GitHub (work)");
        assert_eq!(applied.fields[0].value.as_str(), "9999");
        let ItemData::Login { password, uris, .. } = &applied.data else {
            panic!("login expected");
        };
        assert_eq!(password.as_str(), "correct horse");
        assert_eq!(uris, &["https://github.com", "", "https://gist.github.com"]);

        let cleared = vec![("uri:0".to_owned(), "  ".to_owned())];
        let applied = apply_owned(applied, &cleared).expect("apply");
        let ItemData::Login { uris, .. } = &applied.data else {
            panic!("login expected");
        };
        assert_eq!(uris, &["", "", "https://gist.github.com"]);
    }

    #[test]
    fn name_is_required() {
        let pairs = vec![("name".to_owned(), "   ".to_owned())];
        assert_eq!(
            apply_owned(login(), &pairs).err(),
            Some(EditError::NameRequired)
        );
    }

    #[test]
    fn every_kind_has_a_form_that_round_trips() {
        for kind in [
            ItemKind::Login,
            ItemKind::SecureNote,
            ItemKind::Card,
            ItemKind::Identity,
            ItemKind::SshKey,
        ] {
            let mut draft = new_draft(kind, Some(std::sync::Arc::from("f"))).expect("draft");
            draft.name = "x".to_owned();
            let mut pairs = values(&edit_fields(&draft));
            for (key, value) in &mut pairs {
                if key != "name" && !key.starts_with("uri:") {
                    *value = format!("v-{key}");
                }
            }
            let applied = apply_owned(draft, &pairs).expect("apply");
            let reread = values(&edit_fields(&applied));
            let expected: Vec<(String, String)> = pairs
                .into_iter()
                .filter(|(key, _)| !key.starts_with("uri:"))
                .collect();
            let reread: Vec<(String, String)> = reread
                .into_iter()
                .filter(|(key, _)| !key.starts_with("uri:"))
                .collect();
            assert_eq!(reread, expected, "{kind:?}");
            assert_eq!(applied.folder_id.as_deref(), Some("f"));
        }
        assert_eq!(
            new_draft(ItemKind::Unsupported(9), None).err(),
            Some(EditError::Unsupported)
        );
    }

    #[test]
    fn uri_field_is_numbered_from_one() {
        let uri = uri_field(2);
        assert_eq!((uri.key.as_str(), uri.label.as_str()), ("uri:2", "URI 3"));
    }

    #[test]
    fn the_ssh_private_key_field_is_a_masked_multiline_secret() {
        let draft = new_draft(ItemKind::SshKey, None).expect("draft");
        let fields = edit_fields(&draft);
        let private = fields
            .iter()
            .find(|field| field.key == "private_key")
            .expect("private key field");
        assert!(private.secret && private.multiline && private.mono);
    }
}
