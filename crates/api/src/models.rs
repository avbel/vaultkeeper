//! Wire models (camelCase after key normalization). Strings documented as EncString are encrypted.
//!
//! The cipher models are lossless: every property they don't name lands in their `extra` map and is
//! written back when they are serialized. A [`Cipher`] therefore re-serializes to the server JSON it
//! was parsed from, so `vault.json` keeps it whole and an update can start from it instead of
//! dropping what this client doesn't model (passkeys in `login.fido2Credentials`, `archivedDate`,
//! fields a newer server adds).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Properties a model doesn't name, kept verbatim.
pub type Extra = Map<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: u8,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("expires_in", &self.expires_in)
            .field("has_refresh_token", &self.refresh_token.is_some())
            .field("has_key", &self.key.is_some())
            .field("has_private_key", &self.private_key.is_some())
            .field("has_two_factor_token", &self.two_factor_token.is_some())
            .finish_non_exhaustive()
    }
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
    pub attachments: Option<Vec<Attachment>>,
    #[serde(default)]
    pub collection_ids: Vec<String>,
    pub revision_date: String,
    #[serde(default)]
    pub creation_date: Option<String>,
    #[serde(default)]
    pub deleted_date: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
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
    /// Includes `fido2Credentials` (passkeys, every string an EncString) and `autofillOnPageLoad`.
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    pub uri: Option<String>,
    #[serde(default)]
    pub r#match: Option<u8>,
    /// EncString of base64(SHA-256(uri)). Official clients hide a keyed cipher's URIs whose
    /// checksum is missing or wrong. Omitted when absent so a round trip adds no key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_checksum: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
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
    #[serde(flatten)]
    pub extra: Extra,
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
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNote {
    #[serde(default)]
    pub r#type: u8,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKey {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub key_fingerprint: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
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
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistory {
    pub password: String,
    pub last_used_date: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Attachment metadata. The file itself is encrypted client-side with `key`; `file_name` is an EncString.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub id: String,
    /// Absolute download URL carrying a short-lived token in its query; treat it as a secret.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    /// Vaultwarden sends the byte size as a string, other servers as a number.
    #[serde(default, deserialize_with = "string_or_number")]
    pub size: Option<String>,
    #[serde(default)]
    pub size_name: Option<String>,
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("id", &self.id)
            .field("has_url", &self.url.is_some())
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

fn string_or_number<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    match Option::<serde_json::Value>::deserialize(deserializer)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => Ok(Some(text)),
        Some(serde_json::Value::Number(number)) => Ok(Some(number.to_string())),
        Some(other) => Err(D::Error::custom(format!(
            "expected a string or number for size, got {other}"
        ))),
    }
}

/// Answer to `POST /api/ciphers/{id}/attachment/v2`: where to upload the encrypted file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentUpload {
    pub attachment_id: String,
    /// Path relative to `{base}/api` for self-hosted servers.
    pub url: String,
    /// 0 = direct upload to the API (the only mode Vaultwarden offers).
    pub file_upload_type: u8,
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
    /// Top-level properties carried over from the cipher being updated, such as `archivedDate`.
    #[serde(flatten)]
    pub extra: Extra,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ENC: &str = "2.rJFLaQWX2PGFdsSxCzykOw==|UGfhV0b1hjQ4+5lKEy/aVU7cLrrBW6DR|JuVejUpq98hEXS/hpQg3L0y3+tUjJK9LpywQJ9DoMgk=";

    /// A login as Vaultwarden's `Cipher::to_json` writes it, plus a passkey and properties that
    /// no model names, at every level.
    fn passkey_login() -> Value {
        let passkey = json!({
            "credentialId": ENC, "keyType": ENC, "keyAlgorithm": ENC, "keyCurve": ENC,
            "keyValue": ENC, "rpId": ENC, "userHandle": ENC, "userName": ENC, "counter": ENC,
            "rpName": ENC, "userDisplayName": ENC, "discoverable": ENC,
            "creationDate": "2026-11-08T17:00:59.321Z"
        });
        json!({
            "object": "cipherDetails",
            "id": "1b2151b1-7bbd-4057-bb11-f5ae84ef21cd",
            "type": 1,
            "creationDate": "2026-11-08T17:00:59.311257Z",
            "revisionDate": "2026-11-08T17:00:59.323234Z",
            "deletedDate": null,
            "archivedDate": "2026-11-08T18:00:00.000000Z",
            "reprompt": 0,
            "organizationId": null,
            "folderId": null,
            "key": ENC,
            "attachments": null,
            "organizationUseTotp": true,
            "collectionIds": [],
            "name": ENC,
            "notes": null,
            "favorite": true,
            "edit": true,
            "viewPassword": true,
            "permissions": { "delete": true, "restore": true },
            "futureTopLevel": { "nested": [1, "two", null] },
            "fields": [{ "type": 0, "name": ENC, "value": ENC, "linkedId": null, "futureField": 7 }],
            "passwordHistory": [{ "password": ENC, "lastUsedDate": "2026-01-01T00:00:00.000Z", "futureHistory": true }],
            "login": {
                "username": ENC,
                "password": ENC,
                "passwordRevisionDate": null,
                "totp": null,
                "uri": ENC,
                "uris": [
                    { "uri": ENC, "match": null, "uriChecksum": ENC, "futureUri": "x" },
                    { "uri": ENC, "match": 3 }
                ],
                "autofillOnPageLoad": false,
                "fido2Credentials": [passkey]
            },
            "secureNote": null, "card": null, "identity": null, "sshKey": null,
            "bankAccount": null, "driversLicense": null, "passport": null
        })
    }

    #[test]
    fn a_cipher_re_serializes_to_the_server_json_it_came_from() {
        let raw = passkey_login();
        let cipher: Cipher = serde_json::from_value(raw.clone()).unwrap();
        let login = cipher.login.as_ref().unwrap();
        assert!(login.extra.contains_key("fido2Credentials"));
        assert_eq!(
            login.uris.as_ref().unwrap()[0].uri_checksum.as_deref(),
            Some(ENC)
        );
        assert_eq!(cipher.extra["archivedDate"], raw["archivedDate"]);
        assert_eq!(serde_json::to_value(&cipher).unwrap(), raw);
    }

    #[test]
    fn a_uri_without_checksum_gains_no_checksum_key() {
        let uri: LoginUri = serde_json::from_value(json!({ "uri": ENC, "match": 3 })).unwrap();
        assert_eq!(uri.uri_checksum, None);
        assert_eq!(
            serde_json::to_value(&uri).unwrap(),
            json!({ "uri": ENC, "match": 3 })
        );
    }

    #[test]
    fn request_passthrough_sits_beside_the_typed_properties() {
        let request = CipherRequest {
            r#type: 1,
            name: ENC.into(),
            last_known_revision_date: Some("2026-11-08T17:00:59.323234Z".into()),
            extra: Map::from_iter([("archivedDate".to_owned(), json!("2026-11-08T18:00:00Z"))]),
            ..CipherRequest::default()
        };
        let body = serde_json::to_value(&request).unwrap();
        assert_eq!(body["archivedDate"], "2026-11-08T18:00:00Z");
        assert_eq!(body["lastKnownRevisionDate"], "2026-11-08T17:00:59.323234Z");
        assert_eq!(body["name"], ENC);
        assert!(body.get("extra").is_none());
    }
}
