//! Wire mirrors of the non-secret vault view types.
//!
//! List DTOs hold the vault's `Arc<str>` fields, so encoding a search result shares strings
//! instead of copying them.

use std::sync::Arc;

use bwl_vault::{
    TwoFactorProvider,
    model::{
        AccountView, AttachmentView, CollectionView, CopyField, Filter, FolderView, ItemKind,
        ItemSummary, LoginStep, OrganizationView, SessionState,
    },
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::ConvertError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemKindDto {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    Unsupported(u8),
}

impl From<ItemKind> for ItemKindDto {
    fn from(kind: ItemKind) -> Self {
        match kind {
            ItemKind::Login => Self::Login,
            ItemKind::SecureNote => Self::SecureNote,
            ItemKind::Card => Self::Card,
            ItemKind::Identity => Self::Identity,
            ItemKind::SshKey => Self::SshKey,
            ItemKind::Unsupported(raw) => Self::Unsupported(raw),
        }
    }
}

impl From<ItemKindDto> for ItemKind {
    fn from(kind: ItemKindDto) -> Self {
        match kind {
            ItemKindDto::Login => Self::Login,
            ItemKindDto::SecureNote => Self::SecureNote,
            ItemKindDto::Card => Self::Card,
            ItemKindDto::Identity => Self::Identity,
            ItemKindDto::SshKey => Self::SshKey,
            ItemKindDto::Unsupported(raw) => Self::Unsupported(raw),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStateDto {
    LoggedOut,
    Locked { server: String, email: String },
    Unlocked { server: String, email: String },
}

impl From<SessionState> for SessionStateDto {
    fn from(state: SessionState) -> Self {
        match state {
            SessionState::LoggedOut => Self::LoggedOut,
            SessionState::Locked { server, email } => Self::Locked {
                server: server.into(),
                email,
            },
            SessionState::Unlocked { server, email } => Self::Unlocked {
                server: server.into(),
                email,
            },
        }
    }
}

impl TryFrom<SessionStateDto> for SessionState {
    type Error = ConvertError;

    fn try_from(state: SessionStateDto) -> Result<Self, ConvertError> {
        Ok(match state {
            SessionStateDto::LoggedOut => Self::LoggedOut,
            SessionStateDto::Locked { server, email } => Self::Locked {
                server: Url::parse(&server)?,
                email,
            },
            SessionStateDto::Unlocked { server, email } => Self::Unlocked {
                server: Url::parse(&server)?,
                email,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDto {
    pub id: Arc<str>,
    pub server: String,
    pub email: Arc<str>,
    pub active: bool,
    pub logged_in: bool,
}

impl From<AccountView> for AccountDto {
    fn from(account: AccountView) -> Self {
        Self {
            id: account.id,
            server: account.server.into(),
            email: account.email,
            active: account.active,
            logged_in: account.logged_in,
        }
    }
}

impl TryFrom<AccountDto> for AccountView {
    type Error = ConvertError;

    fn try_from(account: AccountDto) -> Result<Self, ConvertError> {
        Ok(Self {
            id: account.id,
            server: Url::parse(&account.server)?,
            email: account.email,
            active: account.active,
            logged_in: account.logged_in,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSummaryDto {
    pub id: Arc<str>,
    pub kind: ItemKindDto,
    pub name: Arc<str>,
    pub subtitle: Arc<str>,
    pub favorite: bool,
    pub folder_id: Option<Arc<str>>,
    pub organization_id: Option<Arc<str>>,
    pub primary_uri: Option<Arc<str>>,
    pub has_password: bool,
    pub has_totp: bool,
    pub reprompt: bool,
    pub deleted: bool,
    pub editable: bool,
}

impl From<&ItemSummary> for ItemSummaryDto {
    fn from(item: &ItemSummary) -> Self {
        Self {
            id: Arc::clone(&item.id.0),
            kind: item.kind.into(),
            name: Arc::clone(&item.name),
            subtitle: Arc::clone(&item.subtitle),
            favorite: item.favorite,
            folder_id: item.folder_id.clone(),
            organization_id: item.organization_id.clone(),
            primary_uri: item.primary_uri.clone(),
            has_password: item.has_password,
            has_totp: item.has_totp,
            reprompt: item.reprompt,
            deleted: item.deleted,
            editable: item.editable,
        }
    }
}

impl From<ItemSummaryDto> for ItemSummary {
    fn from(item: ItemSummaryDto) -> Self {
        Self {
            id: bwl_vault::model::ItemId(item.id),
            kind: item.kind.into(),
            name: item.name,
            subtitle: item.subtitle,
            favorite: item.favorite,
            folder_id: item.folder_id,
            organization_id: item.organization_id,
            primary_uri: item.primary_uri,
            has_password: item.has_password,
            has_totp: item.has_totp,
            reprompt: item.reprompt,
            deleted: item.deleted,
            editable: item.editable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CopyFieldDto {
    Username,
    Password,
    Totp,
    Uri,
    Notes,
    CardNumber,
    CardCode,
    Email,
    Phone,
    SshPublicKey,
    SshPrivateKey,
    Custom(u64),
}

impl From<CopyField> for CopyFieldDto {
    fn from(field: CopyField) -> Self {
        match field {
            CopyField::Username => Self::Username,
            CopyField::Password => Self::Password,
            CopyField::Totp => Self::Totp,
            CopyField::Uri => Self::Uri,
            CopyField::Notes => Self::Notes,
            CopyField::CardNumber => Self::CardNumber,
            CopyField::CardCode => Self::CardCode,
            CopyField::Email => Self::Email,
            CopyField::Phone => Self::Phone,
            CopyField::SshPublicKey => Self::SshPublicKey,
            CopyField::SshPrivateKey => Self::SshPrivateKey,
            // usize is at most 64 bits on every supported target.
            CopyField::Custom(index) => Self::Custom(u64::try_from(index).unwrap_or(u64::MAX)),
        }
    }
}

impl TryFrom<CopyFieldDto> for CopyField {
    type Error = ConvertError;

    fn try_from(field: CopyFieldDto) -> Result<Self, ConvertError> {
        Ok(match field {
            CopyFieldDto::Username => Self::Username,
            CopyFieldDto::Password => Self::Password,
            CopyFieldDto::Totp => Self::Totp,
            CopyFieldDto::Uri => Self::Uri,
            CopyFieldDto::Notes => Self::Notes,
            CopyFieldDto::CardNumber => Self::CardNumber,
            CopyFieldDto::CardCode => Self::CardCode,
            CopyFieldDto::Email => Self::Email,
            CopyFieldDto::Phone => Self::Phone,
            CopyFieldDto::SshPublicKey => Self::SshPublicKey,
            CopyFieldDto::SshPrivateKey => Self::SshPrivateKey,
            CopyFieldDto::Custom(index) => {
                Self::Custom(usize::try_from(index).map_err(|_| ConvertError::FieldIndex(index))?)
            }
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterDto {
    pub kind: Option<ItemKindDto>,
    pub folder: Option<Option<Arc<str>>>,
    pub organization: Option<Option<Arc<str>>>,
    pub favorites_only: bool,
    pub trash: bool,
}

impl From<&Filter> for FilterDto {
    fn from(filter: &Filter) -> Self {
        Self {
            kind: filter.kind.map(Into::into),
            folder: filter.folder.clone(),
            organization: filter.organization.clone(),
            favorites_only: filter.favorites_only,
            trash: filter.trash,
        }
    }
}

impl From<FilterDto> for Filter {
    fn from(filter: FilterDto) -> Self {
        Self {
            kind: filter.kind.map(Into::into),
            folder: filter.folder,
            organization: filter.organization,
            favorites_only: filter.favorites_only,
            trash: filter.trash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderDto {
    pub id: Arc<str>,
    pub name: Arc<str>,
}

impl From<FolderView> for FolderDto {
    fn from(folder: FolderView) -> Self {
        Self {
            id: folder.id,
            name: folder.name,
        }
    }
}

impl From<FolderDto> for FolderView {
    fn from(folder: FolderDto) -> Self {
        Self {
            id: folder.id,
            name: folder.name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationDto {
    pub id: Arc<str>,
    pub name: Arc<str>,
}

impl From<OrganizationView> for OrganizationDto {
    fn from(organization: OrganizationView) -> Self {
        Self {
            id: organization.id,
            name: organization.name,
        }
    }
}

impl From<OrganizationDto> for OrganizationView {
    fn from(organization: OrganizationDto) -> Self {
        Self {
            id: organization.id,
            name: organization.name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionDto {
    pub id: Arc<str>,
    pub organization_id: Arc<str>,
    pub name: Arc<str>,
    pub read_only: bool,
}

impl From<CollectionView> for CollectionDto {
    fn from(collection: CollectionView) -> Self {
        Self {
            id: collection.id,
            organization_id: collection.organization_id,
            name: collection.name,
            read_only: collection.read_only,
        }
    }
}

impl From<CollectionDto> for CollectionView {
    fn from(collection: CollectionDto) -> Self {
        Self {
            id: collection.id,
            organization_id: collection.organization_id,
            name: collection.name,
            read_only: collection.read_only,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentDto {
    pub id: Arc<str>,
    pub file_name: Arc<str>,
    pub size_bytes: u64,
}

impl From<AttachmentView> for AttachmentDto {
    fn from(attachment: AttachmentView) -> Self {
        Self {
            id: attachment.id,
            file_name: attachment.file_name,
            size_bytes: attachment.size_bytes,
        }
    }
}

impl From<AttachmentDto> for AttachmentView {
    fn from(attachment: AttachmentDto) -> Self {
        Self {
            id: attachment.id,
            file_name: attachment.file_name,
            size_bytes: attachment.size_bytes,
        }
    }
}

/// Two-factor providers travel as their server wire ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginStepDto {
    Done,
    TwoFactorRequired(Vec<u8>),
    NewDeviceOtpRequired,
}

impl From<LoginStep> for LoginStepDto {
    fn from(step: LoginStep) -> Self {
        match step {
            LoginStep::Done => Self::Done,
            LoginStep::TwoFactorRequired(providers) => {
                Self::TwoFactorRequired(providers.into_iter().map(TwoFactorProvider::id).collect())
            }
            LoginStep::NewDeviceOtpRequired => Self::NewDeviceOtpRequired,
        }
    }
}

impl TryFrom<LoginStepDto> for LoginStep {
    type Error = ConvertError;

    fn try_from(step: LoginStepDto) -> Result<Self, ConvertError> {
        Ok(match step {
            LoginStepDto::Done => Self::Done,
            LoginStepDto::TwoFactorRequired(ids) => Self::TwoFactorRequired(
                ids.into_iter()
                    .map(provider_from_id)
                    .collect::<Result<_, _>>()?,
            ),
            LoginStepDto::NewDeviceOtpRequired => Self::NewDeviceOtpRequired,
        })
    }
}

pub(crate) fn provider_from_id(id: u8) -> Result<TwoFactorProvider, ConvertError> {
    TwoFactorProvider::from_id(id).ok_or(ConvertError::UnknownProvider(id))
}

#[cfg(test)]
mod tests {
    use serde::de::DeserializeOwned;

    use super::*;
    use crate::frame::{decode, encode};

    /// Model -> DTO -> wire bytes -> DTO, as one direction of an IPC hop does.
    fn over_the_wire<T: Serialize + DeserializeOwned>(dto: &T) -> T {
        let frame = encode(dto).expect("encode");
        decode(&frame[crate::frame::HEADER_LEN..]).expect("decode")
    }

    fn url(text: &str) -> Url {
        Url::parse(text).expect("valid URL")
    }

    #[test]
    fn every_item_kind_round_trips() {
        let kinds = [
            ItemKind::Login,
            ItemKind::SecureNote,
            ItemKind::Card,
            ItemKind::Identity,
            ItemKind::SshKey,
            ItemKind::Unsupported(7),
        ];
        for kind in kinds {
            let back = ItemKind::from(over_the_wire(&ItemKindDto::from(kind)));
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn every_session_state_round_trips() {
        let states = [
            SessionState::LoggedOut,
            SessionState::Locked {
                server: url("https://vault.example.com/"),
                email: "alice@example.com".to_owned(),
            },
            SessionState::Unlocked {
                server: url("https://vw.lan:8443/sub/"),
                email: "bob@example.com".to_owned(),
            },
        ];
        for state in states {
            let dto = over_the_wire(&SessionStateDto::from(state.clone()));
            assert_eq!(SessionState::try_from(dto).expect("convert"), state);
        }
    }

    #[test]
    fn session_state_with_a_bad_url_is_rejected() {
        let dto = SessionStateDto::Locked {
            server: "not a url".to_owned(),
            email: "a@b.c".to_owned(),
        };
        assert_eq!(
            SessionState::try_from(dto),
            Err(ConvertError::Url(url::ParseError::RelativeUrlWithoutBase))
        );
    }

    #[test]
    fn account_round_trips_and_rejects_a_bad_url() {
        let account = AccountView {
            id: "user-1".into(),
            server: url("https://vault.example.com/"),
            email: "alice@example.com".into(),
            active: true,
            logged_in: false,
        };
        let dto = over_the_wire(&AccountDto::from(account.clone()));
        assert_eq!(
            AccountView::try_from(dto.clone()).expect("convert"),
            account
        );
        let broken = AccountDto {
            server: "https://".to_owned(),
            ..dto
        };
        assert_eq!(
            AccountView::try_from(broken),
            Err(ConvertError::Url(url::ParseError::EmptyHost))
        );
    }

    #[test]
    fn item_summary_round_trips_with_every_field_set() {
        let item = ItemSummary {
            id: bwl_vault::model::ItemId("c1".into()),
            kind: ItemKind::Card,
            name: "Visa".into(),
            subtitle: "Visa, *4242".into(),
            favorite: true,
            folder_id: Some("f1".into()),
            organization_id: Some("o1".into()),
            primary_uri: Some("https://bank.example".into()),
            has_password: false,
            has_totp: true,
            reprompt: true,
            deleted: true,
            editable: false,
        };
        let back = ItemSummary::from(over_the_wire(&ItemSummaryDto::from(&item)));
        assert_eq!(back, item);
        let sparse = ItemSummary {
            folder_id: None,
            organization_id: None,
            primary_uri: None,
            ..item
        };
        let back = ItemSummary::from(over_the_wire(&ItemSummaryDto::from(&sparse)));
        assert_eq!(back, sparse);
    }

    #[test]
    fn every_copy_field_round_trips() {
        let fields = [
            CopyField::Username,
            CopyField::Password,
            CopyField::Totp,
            CopyField::Uri,
            CopyField::Notes,
            CopyField::CardNumber,
            CopyField::CardCode,
            CopyField::Email,
            CopyField::Phone,
            CopyField::SshPublicKey,
            CopyField::SshPrivateKey,
            CopyField::Custom(0),
            CopyField::Custom(41),
        ];
        for field in fields {
            let dto = over_the_wire(&CopyFieldDto::from(field));
            assert_eq!(CopyField::try_from(dto).expect("convert"), field);
        }
    }

    #[test]
    fn filter_keeps_the_difference_between_any_and_none() {
        let filters = [
            Filter::default(),
            Filter {
                kind: Some(ItemKind::SshKey),
                folder: Some(None),
                organization: Some(Some("o1".into())),
                favorites_only: true,
                trash: true,
            },
            Filter {
                folder: Some(Some("f1".into())),
                organization: Some(None),
                ..Filter::default()
            },
        ];
        for filter in filters {
            let back = Filter::from(over_the_wire(&FilterDto::from(&filter)));
            assert_eq!(back, filter);
        }
    }

    #[test]
    fn folder_organization_collection_and_attachment_round_trip() {
        let folder = FolderView {
            id: "f1".into(),
            name: "Work".into(),
        };
        assert_eq!(
            FolderView::from(over_the_wire(&FolderDto::from(folder.clone()))),
            folder
        );
        let organization = OrganizationView {
            id: "o1".into(),
            name: "Family".into(),
        };
        assert_eq!(
            OrganizationView::from(over_the_wire(&OrganizationDto::from(organization.clone()))),
            organization
        );
        let collection = CollectionView {
            id: "c1".into(),
            organization_id: "o1".into(),
            name: "Shared".into(),
            read_only: true,
        };
        assert_eq!(
            CollectionView::from(over_the_wire(&CollectionDto::from(collection.clone()))),
            collection
        );
        let attachment = AttachmentView {
            id: "a1".into(),
            file_name: "scan.pdf".into(),
            size_bytes: 5_000_000_000,
        };
        assert_eq!(
            AttachmentView::from(over_the_wire(&AttachmentDto::from(attachment.clone()))),
            attachment
        );
    }

    #[test]
    fn login_steps_round_trip_with_provider_ids() {
        let steps = [
            LoginStep::Done,
            LoginStep::NewDeviceOtpRequired,
            LoginStep::TwoFactorRequired(vec![
                TwoFactorProvider::Authenticator,
                TwoFactorProvider::Email,
                TwoFactorProvider::RecoveryCode,
            ]),
        ];
        for step in steps {
            let dto = over_the_wire(&LoginStepDto::from(step.clone()));
            assert_eq!(LoginStep::try_from(dto).expect("convert"), step);
        }
        assert_eq!(
            LoginStepDto::from(LoginStep::TwoFactorRequired(vec![
                TwoFactorProvider::Email,
                TwoFactorProvider::RecoveryCode
            ])),
            LoginStepDto::TwoFactorRequired(vec![1, 8])
        );
    }

    #[test]
    fn unknown_provider_id_is_rejected() {
        // 4 is the retired U2F provider.
        assert_eq!(
            LoginStep::try_from(LoginStepDto::TwoFactorRequired(vec![1, 4])),
            Err(ConvertError::UnknownProvider(4))
        );
    }
}
