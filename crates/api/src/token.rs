use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::de::Error as _;

/// The user id (`sub` claim) of a Vaultwarden/Bitwarden access token. The server requires it as
/// `encryptedFor` on every cipher write, and the token is the only place the client learns it
/// without an extra request. The signature is not checked: the server does that.
pub(crate) fn subject(access_token: &str) -> Result<String, serde_json::Error> {
    #[derive(serde::Deserialize)]
    struct Claims {
        sub: String,
    }

    let payload = access_token
        .split('.')
        .nth(1)
        .ok_or_else(|| serde_json::Error::custom("access token is not a JWT"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| serde_json::Error::custom("access token payload is not base64url"))?;
    let claims: Claims = serde_json::from_slice(&bytes)?;
    Ok(claims.sub)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fake_jwt(sub: &str) -> String {
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{sub}","exp":1}}"#));
        format!("eyJhbGciOiJSUzI1NiJ9.{payload}.sig")
    }

    #[test]
    fn extracts_subject_from_payload() {
        let token = fake_jwt("a8c6b2a0-d019-4511-ad9d-c71f159aadbe");
        assert_eq!(
            subject(&token).unwrap(),
            "a8c6b2a0-d019-4511-ad9d-c71f159aadbe"
        );
    }

    #[test]
    fn extracts_subject_from_a_real_vaultwarden_token() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/token_success.json")).unwrap();
        let token = fixture["access_token"].as_str().unwrap();
        // Profile id of the same user in the captured sync response.
        assert_eq!(
            subject(token).unwrap(),
            "f3d28605-dc9d-4db8-8745-0c28f1483035"
        );
    }

    #[test]
    fn rejects_tokens_without_payload_or_with_garbage() {
        assert!(subject("opaque-token").is_err());
        assert!(subject("a.!!!.c").is_err());
        let no_sub = URL_SAFE_NO_PAD.encode(r#"{"exp":1}"#);
        assert!(subject(&format!("a.{no_sub}.c")).is_err());
    }
}
