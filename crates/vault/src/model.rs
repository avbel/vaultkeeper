//! Decrypted view types shared with the UI.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::TwoFactorProvider;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ItemId(pub Arc<str>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemKind {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    Unsupported(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    LoggedOut,
    Locked { server: Url, email: String },
    Unlocked { server: Url, email: String },
}

/// A saved account. Only the active one can be unlocked; the others stay locked or logged out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountView {
    pub id: Arc<str>,
    pub server: Url,
    pub email: Arc<str>,
    pub active: bool,
    pub logged_in: bool,
}

/// One list row. Contains no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    pub id: ItemId,
    pub kind: ItemKind,
    pub name: Arc<str>,
    /// Username, card brand + last 4, identity email, or SSH key fingerprint.
    pub subtitle: Arc<str>,
    pub favorite: bool,
    pub folder_id: Option<Arc<str>>,
    pub organization_id: Option<Arc<str>>,
    pub primary_uri: Option<Arc<str>>,
    pub has_password: bool,
    pub has_totp: bool,
    /// Master password re-prompt requested for this item.
    pub reprompt: bool,
    pub deleted: bool,
    pub editable: bool,
}

/// What a one-click copy button (or a keyboard shortcut) asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CopyField {
    Username,
    Password,
    /// The current TOTP code, not the secret.
    Totp,
    Uri,
    Notes,
    CardNumber,
    CardCode,
    Email,
    Phone,
    SshPublicKey,
    SshPrivateKey,
    /// Index into the item's custom fields.
    Custom(usize),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub kind: Option<ItemKind>,
    /// `Some(None)` = items without a folder.
    pub folder: Option<Option<Arc<str>>>,
    /// `Some(None)` = personal vault only.
    pub organization: Option<Option<Arc<str>>>,
    /// Items assigned to this collection (an organization item can be in several).
    pub collection: Option<Arc<str>>,
    pub favorites_only: bool,
    pub trash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderView {
    pub id: Arc<str>,
    pub name: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationView {
    pub id: Arc<str>,
    pub name: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionView {
    pub id: Arc<str>,
    pub organization_id: Arc<str>,
    pub name: Arc<str>,
    pub read_only: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CustomField {
    pub name: String,
    pub value: Zeroizing<String>,
    pub hidden: bool,
    pub field_type: u8,
    pub source_index: Option<usize>,
    pub withheld: bool,
}

/// Reserved encrypted Bitwarden custom field used by the login editor and CLI access policy.
pub const CLI_ACCESS_FIELD: &str = "vaultkeeper.cli.allow_access";
pub(crate) const BOOLEAN_FIELD: u8 = 2;

#[derive(Serialize, Deserialize)]
pub struct CliLoginKey {
    pub key: Arc<str>,
    pub title: Arc<str>,
}

#[derive(Serialize, Deserialize)]
pub struct CliLoginField {
    pub field: String,
    pub label: String,
    pub private: bool,
}

/// Fully decrypted item for the detail pane and the edit form. Drop it when the pane closes.
#[derive(Clone, PartialEq, Eq)]
pub struct ItemDraft {
    pub name: String,
    pub notes: Zeroizing<String>,
    pub folder_id: Option<Arc<str>>,
    pub organization_id: Option<Arc<str>>,
    pub collection_ids: Vec<Arc<str>>,
    pub favorite: bool,
    pub reprompt: bool,
    pub fields: Vec<CustomField>,
    pub data: ItemData,
    /// `revisionDate` of the stored item this draft was decrypted from; `None` for a new item.
    /// Saving an update whose revision is no longer the cached one is refused with
    /// [`crate::Error::Conflict`], so an edit never silently overwrites a change from elsewhere.
    pub revision_date: Option<Arc<str>>,
}

impl ItemDraft {
    #[must_use]
    pub fn allows_cli_access(&self) -> bool {
        if !matches!(self.data, ItemData::Login { .. }) {
            return false;
        }
        let mut fields = self
            .fields
            .iter()
            .filter(|field| field.name == CLI_ACCESS_FIELD);
        fields.next().is_some_and(|field| {
            field.field_type == BOOLEAN_FIELD && !field.hidden && field.value.as_str() == "true"
        }) && fields.next().is_none()
    }

    pub fn set_allow_cli_access(&mut self, allow: bool) {
        if !matches!(self.data, ItemData::Login { .. }) {
            return;
        }
        let source_index = self
            .fields
            .iter()
            .find(|field| field.name == CLI_ACCESS_FIELD && field.field_type == BOOLEAN_FIELD)
            .and_then(|field| field.source_index);
        self.fields.retain(|field| field.name != CLI_ACCESS_FIELD);
        self.fields.push(CustomField {
            name: CLI_ACCESS_FIELD.to_owned(),
            value: Zeroizing::new(allow.to_string()),
            hidden: false,
            field_type: BOOLEAN_FIELD,
            source_index,
            withheld: false,
        });
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ItemData {
    Login {
        username: String,
        password: Zeroizing<String>,
        totp: Zeroizing<String>,
        /// Index `i` is the stored item's URI `i`, so its match rule and extras stay with it. A
        /// cleared URI stays as a blank entry (dropped on save) instead of shifting the rest.
        uris: Vec<String>,
    },
    SecureNote,
    Card {
        cardholder_name: String,
        brand: String,
        number: Zeroizing<String>,
        exp_month: String,
        exp_year: String,
        code: Zeroizing<String>,
    },
    Identity(Box<IdentityData>),
    SshKey {
        private_key: Zeroizing<String>,
        public_key: String,
        fingerprint: String,
    },
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct IdentityData {
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

pub struct LoginRequest {
    pub server: Url,
    pub email: String,
    pub password: Zeroizing<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginStep {
    Done,
    TwoFactorRequired(Vec<TwoFactorProvider>),
    NewDeviceOtpRequired,
}

/// Second login round: the code the user typed for one of the offered providers.
pub struct TwoFactorAnswer {
    pub provider: TwoFactorProvider,
    pub code: String,
    pub remember: bool,
}

/// File attached to an item. The content is never held decrypted in memory as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentView {
    pub id: Arc<str>,
    pub file_name: Arc<str>,
    pub size_bytes: u64,
}

/// What the login screen shows after the server URL was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerProbe {
    /// The version `/api/version` reports (Vaultwarden's own release, e.g. "1.37.5"); `None` when
    /// the server answers `/alive` but not that endpoint.
    pub version: Option<String>,
}

/// Key material handed to the SSH agent after unlock/sync.
pub struct SshKeyMaterial {
    pub cipher_id: ItemId,
    pub name: String,
    /// OpenSSH PEM.
    pub private_key: Zeroizing<String>,
}
