//! Wire models (camelCase after key normalization). Strings documented as EncString are encrypted.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: u8,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    /// EncString: user key wrapped by the stretched master key. Absent on refresh.
    #[serde(default)]
    pub key: Option<String>,
    /// EncString: PKCS#8 RSA private key wrapped by the user key.
    #[serde(default, rename = "privateKey")]
    pub private_key: Option<String>,
    /// Remember-device token returned when 2FA "remember" was requested.
    #[serde(default, rename = "twoFactorToken")]
    pub two_factor_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: Profile,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub collections: Vec<Collection>,
    #[serde(default)]
    pub ciphers: Vec<Cipher>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    /// EncString: user key wrapped by the stretched master key.
    pub key: Option<String>,
    /// EncString: RSA private key wrapped by the user key.
    pub private_key: Option<String>,
    #[serde(default)]
    pub organizations: Vec<ProfileOrganization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileOrganization {
    pub id: String,
    pub name: String,
    /// EncString type 4: org key wrapped by the user's RSA public key.
    pub key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    pub id: String,
    /// EncString.
    pub name: String,
    pub revision_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    pub id: String,
    pub organization_id: String,
    /// EncString under the org key.
    pub name: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub hide_passwords: bool,
}

/// Cipher types 1..=5; anything else is kept and shown as unsupported.
pub mod cipher_type {
    pub const LOGIN: u8 = 1;
    pub const SECURE_NOTE: u8 = 2;
    pub const CARD: u8 = 3;
    pub const IDENTITY: u8 = 4;
    pub const SSH_KEY: u8 = 5;
}

/// Cipher as returned by sync. All `Option<String>` text fields except ids/dates are EncStrings,
/// encrypted with `key` (per-item key) when present, otherwise with the user or org key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: String,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub folder_id: Option<String>,
    pub r#type: u8,
    pub name: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default = "default_true")]
    pub edit: bool,
    #[serde(default = "default_true")]
    pub view_password: bool,
    #[serde(default)]
    pub reprompt: u8,
    /// EncString: per-item key wrapped by the user or org key.
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub login: Option<Login>,
    #[serde(default)]
    pub card: Option<Card>,
    #[serde(default)]
    pub identity: Option<Identity>,
    #[serde(default)]
    pub secure_note: Option<SecureNote>,
    #[serde(default)]
    pub ssh_key: Option<SshKey>,
    #[serde(default)]
    pub fields: Option<Vec<Field>>,
    #[serde(default)]
    pub password_history: Option<Vec<PasswordHistory>>,
    #[serde(default)]
    pub collection_ids: Vec<String>,
    pub revision_date: String,
    #[serde(default)]
    pub creation_date: Option<String>,
    #[serde(default)]
    pub deleted_date: Option<String>,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub password_revision_date: Option<String>,
    pub totp: Option<String>,
    #[serde(default)]
    pub uris: Option<Vec<LoginUri>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    pub uri: Option<String>,
    #[serde(default)]
    pub r#match: Option<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssn: Option<String>,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNote {
    #[serde(default)]
    pub r#type: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKey {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    /// 0 text, 1 hidden, 2 boolean, 3 linked.
    pub r#type: u8,
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(default)]
    pub linked_id: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistory {
    pub password: String,
    pub last_used_date: String,
}

/// Body for `POST /api/ciphers` and `PUT /api/ciphers/{id}` (same shape as [`Cipher`], camelCase).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequest {
    pub r#type: u8,
    pub organization_id: Option<String>,
    pub folder_id: Option<String>,
    pub name: String,
    pub notes: Option<String>,
    pub favorite: bool,
    pub reprompt: u8,
    pub key: Option<String>,
    pub login: Option<Login>,
    pub card: Option<Card>,
    pub identity: Option<Identity>,
    pub secure_note: Option<SecureNote>,
    pub ssh_key: Option<SshKey>,
    pub fields: Option<Vec<Field>>,
    pub password_history: Option<Vec<PasswordHistory>>,
    /// Optimistic concurrency on update: the `revisionDate` we last saw.
    pub last_known_revision_date: Option<String>,
}
