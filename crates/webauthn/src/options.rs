//! `PublicKeyCredentialRequestOptions` / `CreationOptions` in their JSON form (binary fields as
//! base64url), as Vaultwarden sends them and as the browser extension serializes a page's call.
//! Unknown members are ignored, as the WebAuthn spec requires of clients.

use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{Result, b64::Base64Url};

/// COSE algorithm id of ES256, the only algorithm vault passkeys use.
pub const ES256: i64 = -7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerification {
    Required,
    #[default]
    Preferred,
    Discouraged,
}

/// Unknown values fall back to the default instead of failing, as the spec asks.
impl<'de> Deserialize<'de> for UserVerification {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(
            match Option::<String>::deserialize(deserializer)?.as_deref() {
                Some("required") => Self::Required,
                Some("discouraged") => Self::Discouraged,
                _ => Self::Preferred,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type", default = "public_key")]
    pub kind: String,
    pub id: Base64Url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RequestExtensions {
    /// FIDO U2F AppID of keys registered before WebAuthn (Vaultwarden: `{DOMAIN}/app-id.json`).
    #[serde(default)]
    pub appid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestOptions {
    pub challenge: Base64Url,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[serde(default)]
    pub user_verification: UserVerification,
    #[serde(default, deserialize_with = "null_as_default")]
    pub extensions: RequestExtensions,
}

impl RequestOptions {
    /// Accepts the options themselves or wrapped as `{"publicKey": ...}`.
    pub fn from_json(value: &Value) -> Result<Self> {
        unwrap_public_key(value)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelyingParty {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserEntity {
    pub id: Base64Url,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialParameter {
    #[serde(rename = "type", default = "public_key")]
    pub kind: String,
    pub alg: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    #[serde(default)]
    pub authenticator_attachment: Option<String>,
    #[serde(default)]
    pub resident_key: Option<String>,
    #[serde(default)]
    pub require_resident_key: Option<bool>,
    #[serde(default)]
    pub user_verification: UserVerification,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationExtensions {
    #[serde(default)]
    pub cred_props: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationOptions {
    pub rp: RelyingParty,
    pub user: UserEntity,
    pub challenge: Base64Url,
    #[serde(default, deserialize_with = "null_as_default")]
    pub pub_key_cred_params: Vec<CredentialParameter>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub authenticator_selection: AuthenticatorSelection,
    #[serde(default)]
    pub attestation: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub extensions: CreationExtensions,
}

impl CreationOptions {
    /// Accepts the options themselves or wrapped as `{"publicKey": ...}`.
    pub fn from_json(value: &Value) -> Result<Self> {
        unwrap_public_key(value)
    }

    /// An empty list means the WebAuthn defaults, ES256 and RS256.
    #[must_use]
    pub fn accepts_es256(&self) -> bool {
        self.pub_key_cred_params.is_empty()
            || self
                .pub_key_cred_params
                .iter()
                .any(|param| param.kind == "public-key" && param.alg == ES256)
    }

    /// `residentKey` wins over the legacy `requireResidentKey`; "preferred" is honoured because a
    /// vault passkey costs nothing extra to make discoverable.
    #[must_use]
    pub fn wants_discoverable(&self) -> bool {
        let selection = &self.authenticator_selection;
        match selection.resident_key.as_deref() {
            Some("required" | "preferred") => true,
            Some(_) => false,
            None => selection.require_resident_key == Some(true),
        }
    }
}

fn public_key() -> String {
    "public-key".to_owned()
}

fn unwrap_public_key<T: DeserializeOwned>(value: &Value) -> Result<T> {
    let inner = value.get("publicKey").unwrap_or(value);
    Ok(T::deserialize(inner)?)
}

fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// `generate_webauthn_login` in Vaultwarden 1.37 (webauthn-rs 0.5 serialization).
    fn vaultwarden_login_challenge() -> Value {
        json!({
            "challenge": "q6yI3E3c0QkOrnsTTGxlhDBUBm0tX8Az3x9sLfu0TSk",
            "timeout": 60000,
            "rpId": "vault.example.com",
            "allowCredentials": [
                {"type": "public-key", "id": "AAECAwQFBgcICQoLDA0ODw"}
            ],
            "userVerification": "discouraged",
            "extensions": {"appid": "https://vault.example.com/app-id.json"}
        })
    }

    #[test]
    fn parses_the_vaultwarden_login_challenge() {
        let options =
            RequestOptions::from_json(&vaultwarden_login_challenge()).expect("request options");
        assert_eq!(options.rp_id.as_deref(), Some("vault.example.com"));
        assert_eq!(options.timeout, Some(60_000));
        assert_eq!(options.user_verification, UserVerification::Discouraged);
        assert_eq!(
            options.allow_credentials[0].id.0,
            (0..16).collect::<Vec<u8>>()
        );
        assert_eq!(
            options.extensions.appid.as_deref(),
            Some("https://vault.example.com/app-id.json")
        );
        assert_eq!(options.challenge.0.len(), 32);
    }

    #[test]
    fn accepts_a_public_key_wrapper_nulls_and_unknown_values() {
        let options = RequestOptions::from_json(&json!({
            "publicKey": {
                "challenge": "AQID",
                "allowCredentials": null,
                "extensions": null,
                "userVerification": "sometimes",
                "hints": ["security-key"]
            }
        }))
        .expect("request options");
        assert_eq!(options.challenge.0, [1, 2, 3]);
        assert_eq!(options.allow_credentials, []);
        assert_eq!(options.user_verification, UserVerification::Preferred);
    }

    #[test]
    fn creation_options_report_algorithms_and_residency() {
        let mut value = json!({
            "rp": {"id": "example.com", "name": "Example"},
            "user": {"id": "dXNlcg", "name": "anne", "displayName": "Anne"},
            "challenge": "AQID",
            "pubKeyCredParams": [{"type": "public-key", "alg": -257}],
            "authenticatorSelection": {"requireResidentKey": true}
        });
        let options = CreationOptions::from_json(&value).expect("request options");
        assert!(!options.accepts_es256());
        assert!(options.wants_discoverable());
        assert_eq!(options.user.id.0, b"user");

        value["pubKeyCredParams"] = json!([{"type": "public-key", "alg": -7}]);
        value["authenticatorSelection"] =
            json!({"residentKey": "discouraged", "requireResidentKey": true});
        let options = CreationOptions::from_json(&value).expect("creation options");
        assert!(options.accepts_es256());
        assert!(!options.wants_discoverable());
    }
}
