//! Detail pane: which fields an item shows, masked until revealed.

use vk_vault::model::{CopyField, IdentityData, ItemData, ItemDraft};

use crate::{ui::DetailField, viewmodel::copy_code};

pub const MASK: &str = "••••••••";
/// Stands in for the code of an item whose master password re-prompt is not cleared yet.
pub const TOTP_MASK: &str = "••• •••";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Uri,
    Totp,
    Multiline,
}

impl FieldKind {
    const fn code(self) -> i32 {
        match self {
            Self::Text => 0,
            Self::Uri => 1,
            Self::Totp => 2,
            Self::Multiline => 3,
        }
    }
}

/// Where a masked value lives in the draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secret {
    Password,
    CardNumber,
    CardCode,
    Ssn,
    Passport,
    License,
    PrivateKey,
    /// Notes of an item that asks for the master password.
    Notes,
    Custom(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSpec {
    pub label: String,
    pub kind: FieldKind,
    pub mono: bool,
    /// Copy through `VaultService::reveal` (records MRU); `None` copies `value` itself.
    pub copy: Option<CopyField>,
    pub secret: Option<Secret>,
    /// Plain value, or the masked form for secrets.
    pub value: String,
    pub copyable: bool,
}

impl FieldSpec {
    fn plain(label: &str, value: &str, copy: Option<CopyField>) -> Self {
        Self {
            label: label.to_owned(),
            kind: FieldKind::Text,
            mono: false,
            copy,
            secret: None,
            value: value.to_owned(),
            copyable: true,
        }
    }

    fn secret(label: &str, secret: Secret, copy: Option<CopyField>, masked: String) -> Self {
        Self {
            mono: true,
            secret: Some(secret),
            value: masked,
            ..Self::plain(label, "", copy)
        }
    }

    const fn with_kind(mut self, kind: FieldKind) -> Self {
        self.kind = kind;
        self
    }

    const fn mono(mut self) -> Self {
        self.mono = true;
        self
    }

    #[must_use]
    pub fn to_ui(&self, revealed: Option<&str>) -> DetailField {
        DetailField {
            label: self.label.as_str().into(),
            value: revealed.unwrap_or(&self.value).into(),
            mono: self.mono,
            secret: self.secret.is_some(),
            revealed: revealed.is_some(),
            copy: if self.copyable {
                self.copy.map_or(99, copy_code)
            } else {
                -1
            },
            kind: self.kind.code(),
        }
    }
}

#[must_use]
pub fn secret_value(draft: &ItemDraft, secret: Secret) -> Option<&str> {
    let value = match (&draft.data, secret) {
        (ItemData::Login { password, .. }, Secret::Password) => password.as_str(),
        (ItemData::Card { number, .. }, Secret::CardNumber) => number.as_str(),
        (ItemData::Card { code, .. }, Secret::CardCode) => code.as_str(),
        (ItemData::Identity(identity), Secret::Ssn) => identity.ssn.as_str(),
        (ItemData::Identity(identity), Secret::Passport) => identity.passport_number.as_str(),
        (ItemData::Identity(identity), Secret::License) => identity.license_number.as_str(),
        (ItemData::SshKey { private_key, .. }, Secret::PrivateKey) => private_key.as_str(),
        (_, Secret::Notes) => draft.notes.as_str(),
        (_, Secret::Custom(index)) => draft.fields.get(index)?.value.as_str(),
        _ => return None,
    };
    Some(value)
}

fn masked_card(number: &str) -> String {
    let digits: Vec<char> = number.chars().filter(char::is_ascii_digit).collect();
    let last4: String = digits[digits.len().saturating_sub(4)..].iter().collect();
    format!("•••• {last4}")
}

fn push_plain(out: &mut Vec<FieldSpec>, label: &str, value: &str, copy: Option<CopyField>) {
    if !value.is_empty() {
        out.push(FieldSpec::plain(label, value, copy));
    }
}

fn push_secret(
    out: &mut Vec<FieldSpec>,
    label: &str,
    value: &str,
    secret: Secret,
    copy: Option<CopyField>,
) {
    if !value.is_empty() {
        out.push(FieldSpec::secret(label, secret, copy, MASK.to_owned()));
    }
}

fn join_nonempty(parts: &[&str], separator: &str) -> String {
    parts
        .iter()
        .filter(|part| !part.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(separator)
}

fn identity_fields(out: &mut Vec<FieldSpec>, identity: &IdentityData) {
    let name = join_nonempty(
        &[
            &identity.title,
            &identity.first_name,
            &identity.middle_name,
            &identity.last_name,
        ],
        " ",
    );
    push_plain(out, "Name", &name, None);
    push_plain(out, "Company", &identity.company, None);
    push_plain(out, "Email", &identity.email, Some(CopyField::Email));
    push_plain(out, "Phone", &identity.phone, Some(CopyField::Phone));
    let city_line = join_nonempty(
        &[&identity.city, &identity.state, &identity.postal_code],
        " ",
    );
    let address = join_nonempty(
        &[
            &identity.address1,
            &identity.address2,
            &identity.address3,
            &city_line,
            &identity.country,
        ],
        "\n",
    );
    if !address.is_empty() {
        out.push(FieldSpec::plain("Address", &address, None).with_kind(FieldKind::Multiline));
    }
    push_plain(out, "Username", &identity.username, None);
    push_secret(out, "SSN", &identity.ssn, Secret::Ssn, None);
    push_secret(
        out,
        "Passport",
        &identity.passport_number,
        Secret::Passport,
        None,
    );
    push_secret(
        out,
        "License",
        &identity.license_number,
        Secret::License,
        None,
    );
}

fn data_fields(out: &mut Vec<FieldSpec>, data: &ItemData) {
    match data {
        ItemData::Login {
            username,
            password,
            totp,
            uris,
        } => {
            push_plain(out, "Username", username, Some(CopyField::Username));
            push_secret(
                out,
                "Password",
                password,
                Secret::Password,
                Some(CopyField::Password),
            );
            if !totp.is_empty() {
                out.push(
                    FieldSpec::plain("TOTP", "", Some(CopyField::Totp)).with_kind(FieldKind::Totp),
                );
            }
            for (index, uri) in uris.iter().enumerate().filter(|(_, uri)| !uri.is_empty()) {
                let copy = (index == 0).then_some(CopyField::Uri);
                out.push(FieldSpec::plain("URI", uri, copy).with_kind(FieldKind::Uri));
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
            push_plain(out, "Cardholder", cardholder_name, None);
            push_plain(out, "Brand", brand, None);
            if !number.is_empty() {
                let masked = masked_card(number);
                out.push(FieldSpec::secret(
                    "Number",
                    Secret::CardNumber,
                    Some(CopyField::CardNumber),
                    masked,
                ));
            }
            let expiry = join_nonempty(&[exp_month, exp_year], " / ");
            push_plain(out, "Expires", &expiry, None);
            push_secret(
                out,
                "Security code",
                code,
                Secret::CardCode,
                Some(CopyField::CardCode),
            );
        }
        ItemData::Identity(identity) => identity_fields(out, identity),
        ItemData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => {
            if !public_key.is_empty() {
                out.push(
                    FieldSpec::plain("Public key", public_key, Some(CopyField::SshPublicKey))
                        .mono(),
                );
            }
            if !fingerprint.is_empty() {
                out.push(FieldSpec::plain("Fingerprint", fingerprint, None).mono());
            }
            push_secret(
                out,
                "Private key",
                private_key,
                Secret::PrivateKey,
                Some(CopyField::SshPrivateKey),
            );
        }
        ItemData::SecureNote => {}
    }
}

fn locked(label: &str) -> FieldSpec {
    FieldSpec {
        copyable: false,
        ..FieldSpec::plain(label, "", None)
    }
}

#[must_use]
pub fn fields(draft: &ItemDraft) -> Vec<FieldSpec> {
    let mut out = Vec::new();
    data_fields(&mut out, &draft.data);
    if !draft.notes.is_empty() {
        let notes = if draft.reprompt {
            FieldSpec::secret(
                "Notes",
                Secret::Notes,
                Some(CopyField::Notes),
                MASK.to_owned(),
            )
        } else {
            FieldSpec::plain("Notes", &draft.notes, Some(CopyField::Notes))
        };
        out.push(notes.with_kind(FieldKind::Multiline));
    }
    for (index, field) in draft.fields.iter().enumerate() {
        let copy = Some(CopyField::Custom(index));
        if field.hidden && field.withheld {
            // The vault withholds hidden values from members without viewPassword (it returns
            // them empty, and `reveal` refuses), so there is nothing to reveal or copy.
            out.push(locked(&field.name));
        } else if field.hidden {
            out.push(
                FieldSpec::secret(&field.name, Secret::Custom(index), copy, MASK.to_owned())
                    .with_kind(FieldKind::Multiline),
            );
        } else if field.field_type == 2 {
            let mut checkbox = FieldSpec::plain(
                &field.name,
                if field.value.as_str() == "true" {
                    "Checked"
                } else {
                    "Unchecked"
                },
                None,
            );
            checkbox.copyable = false;
            out.push(checkbox);
        } else {
            out.push(
                FieldSpec::plain(&field.name, &field.value, copy).with_kind(FieldKind::Multiline),
            );
        }
    }
    out
}

/// `Work/Infra` → `Work › Infra`, prefixed with the organization when there is one.
#[must_use]
pub fn location(folder: Option<&str>, organization: Option<&str>) -> String {
    let folder = folder.map(|name| name.split('/').collect::<Vec<_>>().join(" › "));
    match (organization, folder) {
        (Some(org), Some(folder)) => format!("{org} · {folder}"),
        (Some(org), None) => org.to_owned(),
        (None, Some(folder)) => folder,
        (None, None) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use vk_vault::model::CustomField;
    use zeroize::Zeroizing;

    use super::*;

    fn draft(data: ItemData) -> ItemDraft {
        ItemDraft {
            name: "GitHub".to_owned(),
            notes: Zeroizing::new(String::new()),
            folder_id: None,
            organization_id: None,
            collection_ids: Vec::new(),
            favorite: false,
            reprompt: false,
            fields: Vec::new(),
            data,
            revision_date: None,
        }
    }

    fn login() -> ItemDraft {
        draft(ItemData::Login {
            username: "octocat".to_owned(),
            password: Zeroizing::new("hunter2".to_owned()),
            totp: Zeroizing::new("JBSWY3DPEHPK3PXP".to_owned()),
            uris: vec![
                "https://github.com".to_owned(),
                "https://gist.github.com".to_owned(),
            ],
        })
    }

    #[test]
    fn login_fields_mask_the_password() {
        let specs = fields(&login());
        let labels: Vec<&str> = specs.iter().map(|spec| spec.label.as_str()).collect();
        assert_eq!(labels, ["Username", "Password", "TOTP", "URI", "URI"]);
        assert_eq!(specs[1].value, MASK);
        assert_eq!(specs[1].secret, Some(Secret::Password));
        assert_eq!(specs[2].kind, FieldKind::Totp);
        assert_eq!(specs[3].copy, Some(CopyField::Uri));
        assert_eq!(
            specs[4].copy, None,
            "only the primary URI maps to CopyField::Uri"
        );
        let ui = specs[1].to_ui(None);
        assert_eq!(
            (ui.value.as_str(), ui.secret, ui.revealed, ui.copy),
            (MASK, true, false, 1)
        );
        let ui = specs[1].to_ui(Some("hunter2"));
        assert_eq!((ui.value.as_str(), ui.revealed), ("hunter2", true));
        assert_eq!(specs[4].to_ui(None).copy, 99, "copied from the shown value");
    }

    #[test]
    fn secret_values_come_from_the_draft() {
        let item = login();
        assert_eq!(secret_value(&item, Secret::Password), Some("hunter2"));
        assert_eq!(secret_value(&item, Secret::CardCode), None);
        let card = draft(ItemData::Card {
            cardholder_name: "Alice".to_owned(),
            brand: "Visa".to_owned(),
            number: Zeroizing::new("4242 4242 4242 4242".to_owned()),
            exp_month: "12".to_owned(),
            exp_year: "2027".to_owned(),
            code: Zeroizing::new("123".to_owned()),
        });
        let specs = fields(&card);
        let number = specs
            .iter()
            .find(|spec| spec.label == "Number")
            .expect("number");
        assert_eq!(number.value, "•••• 4242");
        assert_eq!(
            secret_value(&card, Secret::CardNumber),
            Some("4242 4242 4242 4242")
        );
        let expires = specs
            .iter()
            .find(|spec| spec.label == "Expires")
            .expect("expires");
        assert_eq!(expires.value, "12 / 2027");
    }

    #[test]
    fn notes_and_custom_fields() {
        let mut item = draft(ItemData::SecureNote);
        item.notes = Zeroizing::new("line one\nline two".to_owned());
        item.fields = vec![
            CustomField {
                name: "PIN".to_owned(),
                value: Zeroizing::new("0000".to_owned()),
                hidden: true,
                field_type: 1,
                source_index: None,
                withheld: false,
            },
            CustomField {
                name: "Region".to_owned(),
                value: Zeroizing::new("eu-west-1".to_owned()),
                hidden: false,
                field_type: 0,
                source_index: None,
                withheld: false,
            },
        ];
        let specs = fields(&item);
        assert_eq!(specs[0].kind, FieldKind::Multiline);
        assert_eq!(specs[0].copy, Some(CopyField::Notes));
        assert_eq!(
            (specs[1].value.as_str(), specs[1].secret),
            (MASK, Some(Secret::Custom(0)))
        );
        assert_eq!(secret_value(&item, Secret::Custom(0)), Some("0000"));
        assert_eq!(specs[2].value, "eu-west-1");
        assert_eq!(specs[2].copy, Some(CopyField::Custom(1)));
    }

    #[test]
    fn a_hidden_field_without_a_value_offers_no_reveal_or_copy() {
        let mut item = draft(ItemData::SecureNote);
        item.fields = vec![
            CustomField {
                name: "PIN".to_owned(),
                value: Zeroizing::new(String::new()),
                hidden: true,
                field_type: 1,
                source_index: None,
                withheld: true,
            },
            CustomField {
                name: "Token".to_owned(),
                value: Zeroizing::new("abc".to_owned()),
                hidden: true,
                field_type: 1,
                source_index: None,
                withheld: false,
            },
        ];
        let specs = fields(&item);
        let ui = specs[0].to_ui(None);
        assert_eq!(
            (ui.label.as_str(), ui.value.as_str(), ui.secret, ui.copy),
            ("PIN", "", false, -1)
        );
        assert_eq!(specs[0].secret, None);
        assert_eq!(
            specs[1].secret,
            Some(Secret::Custom(1)),
            "others stay masked"
        );
    }

    #[test]
    fn identity_and_ssh_fields() {
        let identity = draft(ItemData::Identity(Box::new(IdentityData {
            first_name: "Alice".to_owned(),
            last_name: "Smith".to_owned(),
            email: "alice@example.com".to_owned(),
            city: "Berlin".to_owned(),
            postal_code: "10115".to_owned(),
            ssn: Zeroizing::new("123-45-6789".to_owned()),
            ..IdentityData::default()
        })));
        let specs = fields(&identity);
        let labels: Vec<&str> = specs.iter().map(|spec| spec.label.as_str()).collect();
        assert_eq!(labels, ["Name", "Email", "Address", "SSN"]);
        assert_eq!(specs[0].value, "Alice Smith");
        assert_eq!(specs[2].value, "Berlin 10115");
        let ssh = draft(ItemData::SshKey {
            private_key: Zeroizing::new("-----BEGIN OPENSSH PRIVATE KEY-----".to_owned()),
            public_key: "ssh-ed25519 AAAA".to_owned(),
            fingerprint: "SHA256:abc".to_owned(),
        });
        let specs = fields(&ssh);
        assert_eq!(specs.len(), 3);
        assert!(specs.iter().all(|spec| spec.mono));
        assert_eq!(specs[2].secret, Some(Secret::PrivateKey));
    }

    #[test]
    fn locations() {
        assert_eq!(location(Some("Work/Infra"), None), "Work › Infra");
        assert_eq!(location(Some("Work"), Some("Acme")), "Acme · Work");
        assert_eq!(location(None, Some("Acme")), "Acme");
        assert_eq!(location(None, None), "");
    }

    #[test]
    fn notes_are_masked_only_for_reprompt_items() {
        let mut item = draft(ItemData::SecureNote);
        item.notes = Zeroizing::new("door code 4711".to_owned());
        let plain = fields(&item);
        assert_eq!(plain[0].value, "door code 4711");
        assert_eq!(plain[0].secret, None);

        item.reprompt = true;
        let gated = fields(&item);
        assert_eq!(gated[0].value, MASK);
        assert_eq!(gated[0].secret, Some(Secret::Notes));
        assert_eq!(gated[0].kind, FieldKind::Multiline);
        assert_eq!(gated[0].copy, Some(CopyField::Notes));
        assert_eq!(secret_value(&item, Secret::Notes), Some("door code 4711"));
    }
}
