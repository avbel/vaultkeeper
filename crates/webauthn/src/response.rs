//! WebAuthn results shaped for the Bitwarden server API.

use serde_json::{Map, Value, json};

use crate::{Assertion, Registration, b64};

impl Assertion {
    /// The `twoFactorToken` for provider 7, as the web vault's `webauthn-connector` builds it
    /// (apps/web/src/connectors/common-webauthn.ts) and Vaultwarden's `PublicKeyCredentialCopy`
    /// reads it: note `clientDataJson`, not `clientDataJSON`.
    #[must_use]
    pub fn to_two_factor_token(&self) -> String {
        let mut extensions = Map::new();
        if let Some(used) = self.appid_used {
            extensions.insert("appid".to_owned(), Value::Bool(used));
        }
        let mut response = json!({
            "authenticatorData": b64::encode(&self.authenticator_data),
            "clientDataJson": b64::encode(&self.client_data_json),
            "signature": b64::encode(&self.signature),
        });
        if let Some(handle) = &self.user_handle {
            response["userHandle"] = Value::String(b64::encode(handle));
        }
        let id = b64::encode(&self.credential_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "extensions": extensions,
            "response": response,
        })
        .to_string()
    }
}

impl Registration {
    /// The `deviceResponse` of `PUT /api/two-factor/webauthn` (enrolling a 2FA key).
    #[must_use]
    pub fn to_two_factor_device_response(&self) -> Value {
        let id = b64::encode(&self.credential_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "extensions": {},
            "response": {
                "attestationObject": b64::encode(&self.attestation_object),
                "clientDataJson": b64::encode(&self.client_data_json),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_factor_token_uses_the_connector_field_names() {
        let assertion = Assertion {
            credential_id: vec![1],
            authenticator_data: vec![2],
            client_data_json: vec![3],
            signature: vec![4],
            user_handle: None,
            appid_used: Some(true),
        };
        let token: Value =
            serde_json::from_str(&assertion.to_two_factor_token()).expect("JSON token");
        assert_eq!(
            token,
            json!({
                "id": "AQ",
                "rawId": "AQ",
                "type": "public-key",
                "extensions": {"appid": true},
                "response": {"authenticatorData": "Ag", "clientDataJson": "Aw", "signature": "BA"}
            })
        );
    }
}
