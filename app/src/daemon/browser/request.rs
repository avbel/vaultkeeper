//! Parse browser requests without retaining a second copy of credentials.

use std::borrow::Cow;

use serde::Deserialize;
use vk_ipc::browser::protocol::{ErrorCode, Request};

#[derive(Deserialize)]
struct Envelope<'a> {
    id: u64,
    #[serde(rename = "type", borrow)]
    kind: Cow<'a, str>,
}

/// Returns the request ID when available so malformed requests can receive an error response.
pub fn decode(body: &[u8]) -> Result<Request, (Option<u64>, ErrorCode)> {
    let envelope: Envelope<'_> =
        serde_json::from_slice(body).map_err(|_| (None, ErrorCode::BadRequest))?;
    if !matches!(
        envelope.kind.as_ref(),
        "hello"
            | "prove"
            | "status"
            | "fill"
            | "save_candidate"
            | "unlock"
            | "open_app"
            | "passkey_create"
            | "passkey_get"
            | "passkey_cancel"
    ) {
        return Err((Some(envelope.id), ErrorCode::UnknownType));
    }
    serde_json::from_slice(body).map_err(|_| (Some(envelope.id), ErrorCode::BadRequest))
}

pub fn validate(request: &Request) -> Result<(), ErrorCode> {
    match request {
        Request::Fill { origin, path, .. } => {
            super::validation::page(origin, path)?;
        }
        Request::SaveCandidate {
            origin,
            path,
            username,
            password,
            ..
        } => {
            super::validation::page(origin, path)?;
            if username.len() > 512 || password.is_empty() || password.len() > 4096 {
                return Err(ErrorCode::BadRequest);
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_save_lengths_and_url() {
        let request = |username: &str, password: &str| Request::SaveCandidate {
            id: 1,
            origin: "https://example.com".into(),
            path: "/".into(),
            username: username.into(),
            password: zeroize::Zeroizing::new(password.into()),
            kind: vk_ipc::browser::protocol::SaveKind::Login,
        };
        assert!(validate(&request(&"a".repeat(512), &"p".repeat(4096))).is_ok());
        assert!(matches!(
            validate(&request(&"a".repeat(513), "p")),
            Err(ErrorCode::BadRequest)
        ));
        assert!(matches!(
            validate(&request("a", "")),
            Err(ErrorCode::BadRequest)
        ));
        assert!(matches!(
            validate(&request("a", &"p".repeat(4097))),
            Err(ErrorCode::BadRequest)
        ));
    }

    #[test]
    fn distinguishes_unknown_type_from_malformed_fields() {
        assert!(matches!(
            decode(br#"{"id":1,"type":"status","extra":42}"#),
            Ok(Request::Status { id: 1 })
        ));
        assert!(matches!(
            decode(br#"{"id":2,"type":"unknown"}"#),
            Err((Some(2), ErrorCode::UnknownType))
        ));
        assert!(matches!(
            decode(br#"{"id":3,"type":"fill"}"#),
            Err((Some(3), ErrorCode::BadRequest))
        ));
        assert!(matches!(
            decode(br#"{"type":"status"}"#),
            Err((None, ErrorCode::BadRequest))
        ));
    }
}
