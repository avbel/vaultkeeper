use serde_json::Value;

use crate::{
    LoginOutcome, Result, TwoFactorProvider,
    http::{Reply, message_candidates},
    normalize::normalize_keys,
};

const NEW_DEVICE_MESSAGE: &str = "new device verification required";

/// Interprets an HTTP 400 from the token endpoint: a 2FA challenge and the Bitwarden
/// new-device challenge are expected outcomes, everything else is a plain server error.
pub(crate) fn classify_bad_request(reply: &Reply) -> Result<LoginOutcome> {
    let Ok(mut value) = serde_json::from_slice::<Value>(&reply.body) else {
        return Err(reply.error());
    };
    normalize_keys(&mut value);

    if let Some(providers) = two_factor_providers(&value) {
        return Ok(LoginOutcome::TwoFactorRequired {
            webauthn: webauthn_challenge(&value, &providers),
            providers,
        });
    }
    if message_candidates(&value).any(is_new_device_message) {
        return Ok(LoginOutcome::NewDeviceOtpRequired);
    }
    Err(reply.error())
}

/// A refresh token the server no longer accepts is reported as HTTP 400 `invalid_grant`.
pub(crate) fn is_invalid_grant(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .is_ok_and(|value| value.get("error").and_then(Value::as_str) == Some("invalid_grant"))
}

fn is_new_device_message(message: &str) -> bool {
    message.to_ascii_lowercase().contains(NEW_DEVICE_MESSAGE)
}

fn two_factor_providers(value: &Value) -> Option<Vec<TwoFactorProvider>> {
    if let Some(Value::Object(map)) = value.get("twoFactorProviders2") {
        return Some(parse_ids(map.keys().map(|key| key.parse::<u64>().ok())));
    }
    if let Some(Value::Array(items)) = value.get("twoFactorProviders") {
        return Some(parse_ids(items.iter().map(|item| match item {
            Value::String(text) => text.parse::<u64>().ok(),
            other => other.as_u64(),
        })));
    }
    None
}

/// The options object Vaultwarden puts under provider 7 of `TwoFactorProviders2`, kept as JSON
/// text so the UI can hand it to the security key unchanged.
fn webauthn_challenge(value: &Value, providers: &[TwoFactorProvider]) -> Option<String> {
    if !providers.contains(&TwoFactorProvider::WebAuthn) {
        return None;
    }
    let key = TwoFactorProvider::WebAuthn.id().to_string();
    value
        .get("twoFactorProviders2")?
        .get(key)
        .filter(|options| options.is_object())
        .map(Value::to_string)
}

fn parse_ids(ids: impl Iterator<Item = Option<u64>>) -> Vec<TwoFactorProvider> {
    ids.flatten()
        .filter_map(|id| u8::try_from(id).ok())
        .filter_map(TwoFactorProvider::from_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;

    use super::*;
    use crate::Error;

    fn bad_request(body: &str) -> Reply {
        Reply {
            status: StatusCode::BAD_REQUEST,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn two_factor_providers2_keys_are_parsed_and_unknown_ids_dropped() {
        let reply = bad_request(
            r#"{"error":"invalid_grant","TwoFactorProviders2":{"0":null,"1":{"Email":"te***@example.com"},"4":null,"9":null,"5":null}}"#,
        );
        let Ok(LoginOutcome::TwoFactorRequired {
            providers,
            webauthn,
        }) = classify_bad_request(&reply)
        else {
            panic!("expected a two-factor challenge");
        };
        assert_eq!(
            providers,
            vec![
                TwoFactorProvider::Authenticator,
                TwoFactorProvider::Email,
                TwoFactorProvider::Remember
            ]
        );
        assert_eq!(webauthn, None);
    }

    #[test]
    fn legacy_provider_list_is_used_when_providers2_is_absent() {
        let reply = bad_request(r#"{"TwoFactorProviders":["1", 0, "3"]}"#);
        let Ok(LoginOutcome::TwoFactorRequired { providers, .. }) = classify_bad_request(&reply)
        else {
            panic!("expected a two-factor challenge");
        };
        assert_eq!(
            providers,
            vec![
                TwoFactorProvider::Email,
                TwoFactorProvider::Authenticator,
                TwoFactorProvider::YubiKey
            ]
        );
    }

    /// Vaultwarden 1.37 with a security key: the options of `generate_webauthn_login`, in the
    /// PascalCase envelope the identity endpoint uses.
    #[test]
    fn webauthn_challenge_is_kept_as_json_text() {
        let reply = bad_request(
            r#"{"error":"invalid_grant","TwoFactorProviders":["7","0"],"TwoFactorProviders2":{"7":{"challenge":"q6yI","timeout":60000,"rpId":"vault.example.com","allowCredentials":[{"type":"public-key","id":"AAEC"}],"userVerification":"discouraged","extensions":{"appid":"https://vault.example.com/app-id.json"}},"0":null}}"#,
        );
        let Ok(LoginOutcome::TwoFactorRequired {
            providers,
            webauthn: Some(webauthn),
        }) = classify_bad_request(&reply)
        else {
            panic!("expected a security-key challenge");
        };
        assert_eq!(
            providers,
            vec![
                TwoFactorProvider::Authenticator,
                TwoFactorProvider::WebAuthn
            ]
        );
        let options: Value = serde_json::from_str(&webauthn).expect("JSON");
        assert_eq!(options["rpId"], "vault.example.com");
        assert_eq!(options["allowCredentials"][0]["id"], "AAEC");
        assert_eq!(
            options["extensions"]["appid"],
            "https://vault.example.com/app-id.json"
        );
    }

    #[test]
    fn webauthn_without_options_has_no_challenge() {
        let reply = bad_request(r#"{"TwoFactorProviders2":{"7":null}}"#);
        let Ok(LoginOutcome::TwoFactorRequired { webauthn, .. }) = classify_bad_request(&reply)
        else {
            panic!("expected a two-factor challenge");
        };
        assert_eq!(webauthn, None);
    }

    #[test]
    fn new_device_message_is_matched_case_insensitively_in_any_message_field() {
        for body in [
            r#"{"error":"invalid_grant","error_description":"New device verification required"}"#,
            r#"{"error":"invalid_grant","ErrorModel":{"Message":"new device verification required."}}"#,
            r#"{"message":"NEW DEVICE VERIFICATION REQUIRED"}"#,
        ] {
            assert!(
                matches!(
                    classify_bad_request(&bad_request(body)),
                    Ok(LoginOutcome::NewDeviceOtpRequired)
                ),
                "{body}"
            );
        }
    }

    #[test]
    fn other_bad_requests_become_server_errors_with_the_server_message() {
        let reply =
            bad_request(r#"{"message":"Username or password is incorrect. Try again","error":""}"#);
        match classify_bad_request(&reply) {
            Err(Error::Server {
                status: 400,
                message,
            }) => {
                assert_eq!(message, "Username or password is incorrect. Try again");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn non_json_bad_request_falls_back_to_the_status_reason() {
        match classify_bad_request(&bad_request("<html>")) {
            Err(Error::Server {
                status: 400,
                message,
            }) => assert_eq!(message, "Bad Request"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn invalid_grant_is_recognised_only_by_the_error_code() {
        assert!(is_invalid_grant(br#"{"error":"invalid_grant"}"#));
        assert!(!is_invalid_grant(br#"{"error":""}"#));
        assert!(!is_invalid_grant(b"<html>"));
    }
}
