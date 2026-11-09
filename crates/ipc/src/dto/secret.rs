//! Wire mirrors of the secret-bearing vault types.
//!
//! None of these derive `Debug`. Draft DTOs wipe every field (names and usernames included) on
//! drop; the others keep their secrets in `Zeroizing` fields. Converting a draft DTO into the
//! model moves the fields out with `mem::take`, so nothing is copied.

use std::{mem, sync::Arc};

use serde::{Deserialize, Serialize};
use url::Url;
use vk_vault::{
    TotpCode,
    model::{
        CustomField, IdentityData, ItemData, ItemDraft, LoginRequest, SshKeyMaterial,
        TwoFactorAnswer,
    },
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{ConvertError, dto::view::provider_from_id};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ItemDraftDto {
    pub name: String,
    pub notes: Zeroizing<String>,
    #[zeroize(skip)]
    pub folder_id: Option<Arc<str>>,
    #[zeroize(skip)]
    pub organization_id: Option<Arc<str>>,
    #[zeroize(skip)]
    pub collection_ids: Vec<Arc<str>>,
    pub favorite: bool,
    pub reprompt: bool,
    pub fields: Vec<CustomFieldDto>,
    pub data: ItemDataDto,
    #[zeroize(skip)]
    pub revision_date: Option<Arc<str>>,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CustomFieldDto {
    pub name: String,
    pub value: Zeroizing<String>,
    pub hidden: bool,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub enum ItemDataDto {
    Login {
        username: String,
        password: Zeroizing<String>,
        totp: Zeroizing<String>,
        uris: Vec<String>,
    },
    #[default]
    SecureNote,
    Card {
        cardholder_name: String,
        brand: String,
        number: Zeroizing<String>,
        exp_month: String,
        exp_year: String,
        code: Zeroizing<String>,
    },
    // zeroize has no impl for `Box<T>`; the boxed DTO wipes itself when the box drops.
    Identity(#[zeroize(skip)] Box<IdentityDto>),
    SshKey {
        private_key: Zeroizing<String>,
        public_key: String,
        fingerprint: String,
    },
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentityDto {
    pub title: String,
    pub first_name: String,
    pub middle_name: String,
    pub last_name: String,
    pub address1: String,
    pub address2: String,
    pub address3: String,
    pub city: String,
    pub state: String,
    pub postal_code: String,
    pub country: String,
    pub company: String,
    pub email: String,
    pub phone: String,
    pub ssn: Zeroizing<String>,
    pub username: String,
    pub passport_number: Zeroizing<String>,
    pub license_number: Zeroizing<String>,
}

impl From<ItemDraft> for ItemDraftDto {
    fn from(draft: ItemDraft) -> Self {
        Self {
            name: draft.name,
            notes: draft.notes,
            folder_id: draft.folder_id,
            organization_id: draft.organization_id,
            collection_ids: draft.collection_ids,
            favorite: draft.favorite,
            reprompt: draft.reprompt,
            fields: draft.fields.into_iter().map(CustomFieldDto::from).collect(),
            data: draft.data.into(),
            revision_date: draft.revision_date,
        }
    }
}

impl From<ItemDraftDto> for ItemDraft {
    fn from(mut draft: ItemDraftDto) -> Self {
        Self {
            name: mem::take(&mut draft.name),
            notes: mem::take(&mut draft.notes),
            folder_id: draft.folder_id.take(),
            organization_id: draft.organization_id.take(),
            collection_ids: mem::take(&mut draft.collection_ids),
            favorite: draft.favorite,
            reprompt: draft.reprompt,
            fields: mem::take(&mut draft.fields)
                .into_iter()
                .map(CustomField::from)
                .collect(),
            data: mem::take(&mut draft.data).into(),
            revision_date: draft.revision_date.take(),
        }
    }
}

impl From<CustomField> for CustomFieldDto {
    fn from(field: CustomField) -> Self {
        Self {
            name: field.name,
            value: field.value,
            hidden: field.hidden,
        }
    }
}

impl From<CustomFieldDto> for CustomField {
    fn from(mut field: CustomFieldDto) -> Self {
        Self {
            name: mem::take(&mut field.name),
            value: mem::take(&mut field.value),
            hidden: field.hidden,
        }
    }
}

impl From<ItemData> for ItemDataDto {
    fn from(data: ItemData) -> Self {
        match data {
            ItemData::Login {
                username,
                password,
                totp,
                uris,
            } => Self::Login {
                username,
                password,
                totp,
                uris,
            },
            ItemData::SecureNote => Self::SecureNote,
            ItemData::Card {
                cardholder_name,
                brand,
                number,
                exp_month,
                exp_year,
                code,
            } => Self::Card {
                cardholder_name,
                brand,
                number,
                exp_month,
                exp_year,
                code,
            },
            ItemData::Identity(identity) => Self::Identity(Box::new((*identity).into())),
            ItemData::SshKey {
                private_key,
                public_key,
                fingerprint,
            } => Self::SshKey {
                private_key,
                public_key,
                fingerprint,
            },
        }
    }
}

impl From<ItemDataDto> for ItemData {
    fn from(mut data: ItemDataDto) -> Self {
        match &mut data {
            ItemDataDto::Login {
                username,
                password,
                totp,
                uris,
            } => Self::Login {
                username: mem::take(username),
                password: mem::take(password),
                totp: mem::take(totp),
                uris: mem::take(uris),
            },
            ItemDataDto::SecureNote => Self::SecureNote,
            ItemDataDto::Card {
                cardholder_name,
                brand,
                number,
                exp_month,
                exp_year,
                code,
            } => Self::Card {
                cardholder_name: mem::take(cardholder_name),
                brand: mem::take(brand),
                number: mem::take(number),
                exp_month: mem::take(exp_month),
                exp_year: mem::take(exp_year),
                code: mem::take(code),
            },
            ItemDataDto::Identity(identity) => {
                Self::Identity(Box::new(mem::take(identity.as_mut()).into()))
            }
            ItemDataDto::SshKey {
                private_key,
                public_key,
                fingerprint,
            } => Self::SshKey {
                private_key: mem::take(private_key),
                public_key: mem::take(public_key),
                fingerprint: mem::take(fingerprint),
            },
        }
    }
}

impl From<IdentityData> for IdentityDto {
    fn from(identity: IdentityData) -> Self {
        Self {
            title: identity.title,
            first_name: identity.first_name,
            middle_name: identity.middle_name,
            last_name: identity.last_name,
            address1: identity.address1,
            address2: identity.address2,
            address3: identity.address3,
            city: identity.city,
            state: identity.state,
            postal_code: identity.postal_code,
            country: identity.country,
            company: identity.company,
            email: identity.email,
            phone: identity.phone,
            ssn: identity.ssn,
            username: identity.username,
            passport_number: identity.passport_number,
            license_number: identity.license_number,
        }
    }
}

impl From<IdentityDto> for IdentityData {
    fn from(mut identity: IdentityDto) -> Self {
        Self {
            title: mem::take(&mut identity.title),
            first_name: mem::take(&mut identity.first_name),
            middle_name: mem::take(&mut identity.middle_name),
            last_name: mem::take(&mut identity.last_name),
            address1: mem::take(&mut identity.address1),
            address2: mem::take(&mut identity.address2),
            address3: mem::take(&mut identity.address3),
            city: mem::take(&mut identity.city),
            state: mem::take(&mut identity.state),
            postal_code: mem::take(&mut identity.postal_code),
            country: mem::take(&mut identity.country),
            company: mem::take(&mut identity.company),
            email: mem::take(&mut identity.email),
            phone: mem::take(&mut identity.phone),
            ssn: mem::take(&mut identity.ssn),
            username: mem::take(&mut identity.username),
            passport_number: mem::take(&mut identity.passport_number),
            license_number: mem::take(&mut identity.license_number),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpCodeDto {
    pub code: Zeroizing<String>,
    pub period: u32,
    pub remaining: u32,
}

impl From<TotpCode> for TotpCodeDto {
    fn from(code: TotpCode) -> Self {
        Self {
            code: code.code,
            period: code.period,
            remaining: code.remaining,
        }
    }
}

impl From<TotpCodeDto> for TotpCode {
    fn from(code: TotpCodeDto) -> Self {
        Self {
            code: code.code,
            period: code.period,
            remaining: code.remaining,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequestDto {
    pub server: String,
    pub email: String,
    pub password: Zeroizing<String>,
}

impl From<LoginRequest> for LoginRequestDto {
    fn from(request: LoginRequest) -> Self {
        Self {
            server: request.server.into(),
            email: request.email,
            password: request.password,
        }
    }
}

impl TryFrom<LoginRequestDto> for LoginRequest {
    type Error = ConvertError;

    fn try_from(request: LoginRequestDto) -> Result<Self, ConvertError> {
        Ok(Self {
            server: Url::parse(&request.server)?,
            email: request.email,
            password: request.password,
        })
    }
}

/// The code is a one-time value and the model keeps it as a plain `String`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoFactorAnswerDto {
    pub provider: u8,
    pub code: String,
    pub remember: bool,
}

impl From<TwoFactorAnswer> for TwoFactorAnswerDto {
    fn from(answer: TwoFactorAnswer) -> Self {
        Self {
            provider: answer.provider.id(),
            code: answer.code,
            remember: answer.remember,
        }
    }
}

impl TryFrom<TwoFactorAnswerDto> for TwoFactorAnswer {
    type Error = ConvertError;

    fn try_from(answer: TwoFactorAnswerDto) -> Result<Self, ConvertError> {
        Ok(Self {
            provider: provider_from_id(answer.provider)?,
            code: answer.code,
            remember: answer.remember,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKeyDto {
    pub cipher_id: Arc<str>,
    pub name: String,
    pub private_key: Zeroizing<String>,
}

impl From<SshKeyMaterial> for SshKeyDto {
    fn from(key: SshKeyMaterial) -> Self {
        Self {
            cipher_id: key.cipher_id.0,
            name: key.name,
            private_key: key.private_key,
        }
    }
}

impl From<SshKeyDto> for SshKeyMaterial {
    fn from(key: SshKeyDto) -> Self {
        Self {
            cipher_id: vk_vault::model::ItemId(key.cipher_id),
            name: key.name,
            private_key: key.private_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::de::DeserializeOwned;
    use vk_vault::TwoFactorProvider;

    use super::*;
    use crate::frame::{HEADER_LEN, decode, encode};

    fn over_the_wire<T: Serialize + DeserializeOwned>(dto: &T) -> T {
        let frame = encode(dto).expect("encode");
        decode(&frame[HEADER_LEN..]).expect("decode")
    }

    fn secret(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_owned())
    }

    fn draft_with(data: ItemData) -> ItemDraft {
        ItemDraft {
            name: "Bank".to_owned(),
            notes: secret("PIN is 1234"),
            folder_id: Some("f1".into()),
            organization_id: Some("o1".into()),
            collection_ids: vec!["c1".into(), "c2".into()],
            favorite: true,
            reprompt: true,
            fields: vec![
                CustomField {
                    name: "recovery".to_owned(),
                    value: secret("alpha-beta"),
                    hidden: true,
                },
                CustomField {
                    name: "branch".to_owned(),
                    value: secret("Main St"),
                    hidden: false,
                },
            ],
            data,
            revision_date: Some("2026-11-08T17:00:59.321Z".into()),
        }
    }

    fn identity() -> IdentityData {
        IdentityData {
            title: "Dr".to_owned(),
            first_name: "Ada".to_owned(),
            middle_name: "M".to_owned(),
            last_name: "Lovelace".to_owned(),
            address1: "1 Analytical Way".to_owned(),
            address2: "Floor 2".to_owned(),
            address3: "Desk 3".to_owned(),
            city: "London".to_owned(),
            state: "Greater London".to_owned(),
            postal_code: "N1 9GU".to_owned(),
            country: "GB".to_owned(),
            company: "Engines Ltd".to_owned(),
            email: "ada@example.com".to_owned(),
            phone: "+44 20 7946 0000".to_owned(),
            ssn: secret("123-45-6789"),
            username: "ada".to_owned(),
            passport_number: secret("P1234567"),
            license_number: secret("LOVEL812345AA9XY"),
        }
    }

    fn every_item_data() -> Vec<ItemData> {
        vec![
            ItemData::Login {
                username: "alice".to_owned(),
                password: secret("hunter2"),
                totp: secret("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
                uris: vec!["https://a.example".to_owned(), "androidapp://x".to_owned()],
            },
            ItemData::SecureNote,
            ItemData::Card {
                cardholder_name: "Alice A".to_owned(),
                brand: "Visa".to_owned(),
                number: secret("4242424242424242"),
                exp_month: "12".to_owned(),
                exp_year: "2030".to_owned(),
                code: secret("123"),
            },
            ItemData::Identity(Box::new(identity())),
            ItemData::SshKey {
                private_key: secret("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n"),
                public_key: "ssh-ed25519 AAAAC3Nza alice".to_owned(),
                fingerprint: "SHA256:abc".to_owned(),
            },
        ]
    }

    #[test]
    fn drafts_of_every_item_type_round_trip() {
        for data in every_item_data() {
            let draft = draft_with(data);
            let back = ItemDraft::from(over_the_wire(&ItemDraftDto::from(draft.clone())));
            assert!(back == draft, "draft changed over the wire");
        }
    }

    #[test]
    fn sparse_draft_round_trips() {
        let draft = ItemDraft {
            name: String::new(),
            notes: secret(""),
            folder_id: None,
            organization_id: None,
            collection_ids: Vec::new(),
            favorite: false,
            reprompt: false,
            fields: Vec::new(),
            data: ItemData::SecureNote,
            revision_date: None,
        };
        let back = ItemDraft::from(over_the_wire(&ItemDraftDto::from(draft.clone())));
        assert!(back == draft);
    }

    #[test]
    fn zeroize_wipes_every_draft_field() {
        // `ZeroizeOnDrop` runs exactly this `zeroize()` in `Drop`; the freed memory itself is
        // checked by the allocator test in tests/zeroize.rs.
        let mut dto = ItemDraftDto::from(draft_with(ItemData::Login {
            username: "alice".to_owned(),
            password: secret("hunter2"),
            totp: secret("JBSWY3DP"),
            uris: vec!["https://a.example".to_owned()],
        }));
        dto.zeroize();
        assert_eq!(dto.name, "");
        assert_eq!(dto.notes.as_str(), "");
        assert_eq!(dto.fields.len(), 0);
        let ItemDataDto::Login {
            username,
            password,
            totp,
            uris,
        } = &dto.data
        else {
            panic!("variant changed");
        };
        assert!(username.is_empty() && password.is_empty() && totp.is_empty() && uris.is_empty());
    }

    #[test]
    fn zeroize_wipes_identity_fields() {
        let mut identity = IdentityDto::from(identity());
        identity.zeroize();
        assert!(identity == IdentityDto::default());
    }

    #[test]
    fn secret_dtos_are_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ItemDraftDto>();
        assert_zeroize_on_drop::<CustomFieldDto>();
        assert_zeroize_on_drop::<ItemDataDto>();
        assert_zeroize_on_drop::<IdentityDto>();
        assert_zeroize_on_drop::<Zeroizing<String>>();
        assert_zeroize_on_drop::<Zeroizing<Vec<u8>>>();
    }

    #[test]
    fn totp_code_round_trips() {
        let code = TotpCode {
            code: secret("287082"),
            period: 30,
            remaining: 17,
        };
        let back = TotpCode::from(over_the_wire(&TotpCodeDto::from(code.clone())));
        assert_eq!(back, code);
    }

    #[test]
    fn login_request_round_trips_and_rejects_a_bad_url() {
        let request = LoginRequest {
            server: Url::parse("https://vault.example.com/").expect("url"),
            email: "alice@example.com".to_owned(),
            password: secret("correct horse battery staple"),
        };
        let dto = over_the_wire(&LoginRequestDto::from(request));
        assert_eq!(dto.server, "https://vault.example.com/");
        let back = LoginRequest::try_from(dto.clone()).expect("convert");
        assert_eq!(back.server.as_str(), "https://vault.example.com/");
        assert_eq!(back.email, "alice@example.com");
        assert_eq!(back.password.as_str(), "correct horse battery staple");
        let broken = LoginRequestDto {
            server: "vault".to_owned(),
            ..dto
        };
        assert!(matches!(
            LoginRequest::try_from(broken),
            Err(ConvertError::Url(_))
        ));
    }

    #[test]
    fn two_factor_answer_round_trips_and_rejects_unknown_providers() {
        let answer = TwoFactorAnswer {
            provider: TwoFactorProvider::Email,
            code: "123456".to_owned(),
            remember: true,
        };
        let dto = over_the_wire(&TwoFactorAnswerDto::from(answer));
        assert_eq!(dto.provider, 1);
        let back = TwoFactorAnswer::try_from(dto.clone()).expect("convert");
        assert_eq!(back.provider, TwoFactorProvider::Email);
        assert_eq!(back.code, "123456");
        assert!(back.remember);
        let unknown = TwoFactorAnswerDto { provider: 4, ..dto };
        assert!(matches!(
            TwoFactorAnswer::try_from(unknown),
            Err(ConvertError::UnknownProvider(4))
        ));
    }

    #[test]
    fn ssh_key_material_round_trips() {
        let key = SshKeyMaterial {
            cipher_id: vk_vault::model::ItemId("k1".into()),
            name: "deploy".to_owned(),
            private_key: secret("-----BEGIN OPENSSH PRIVATE KEY-----\nBBBB\n"),
        };
        let back = SshKeyMaterial::from(over_the_wire(&SshKeyDto::from(key)));
        assert_eq!(back.cipher_id.0.as_ref(), "k1");
        assert_eq!(back.name, "deploy");
        assert_eq!(
            back.private_key.as_str(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nBBBB\n"
        );
    }
}
