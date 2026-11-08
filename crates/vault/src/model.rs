//! Decrypted view types shared with the UI.

use std::sync::Arc;

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
}

#[derive(Clone, PartialEq, Eq)]
pub enum ItemData {
    Login {
        username: String,
        password: Zeroizing<String>,
        totp: Zeroizing<String>,
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

/// Key material handed to the SSH agent after unlock/sync.
pub struct SshKeyMaterial {
    pub cipher_id: ItemId,
    pub name: String,
    /// OpenSSH PEM.
    pub private_key: Zeroizing<String>,
}
