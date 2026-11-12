use serde::Serialize;
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::b64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    Create,
    Get,
}

#[derive(Serialize)]
struct ClientData<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    challenge: String,
    origin: &'a str,
    #[serde(rename = "crossOrigin")]
    cross_origin: bool,
}

/// The exact `clientDataJSON` bytes: the relying party hashes what it receives, so the same
/// bytes must be both hashed for the authenticator and sent back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDataJson(Vec<u8>);

impl ClientDataJson {
    /// `origin` is a serialized origin such as `https://vault.example.com:8443`, see [`origin_of`].
    #[must_use]
    pub fn new(ceremony: Ceremony, challenge: &[u8], origin: &str) -> Self {
        let data = ClientData {
            kind: match ceremony {
                Ceremony::Create => "webauthn.create",
                Ceremony::Get => "webauthn.get",
            },
            challenge: b64::encode(challenge),
            origin,
            cross_origin: false,
        };
        // Serializing a struct of strings and a bool cannot fail.
        Self(serde_json::to_vec(&data).unwrap_or_default())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.0).into()
    }
}

/// The origin of `url` as browsers write it into client data: no path and no trailing slash, the
/// default port omitted.
#[must_use]
pub fn origin_of(url: &Url) -> String {
    url.origin().ascii_serialization()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_browser_serialization() {
        let data = ClientDataJson::new(Ceremony::Get, &[1, 2, 3], "https://vault.example.com");
        assert_eq!(
            std::str::from_utf8(data.as_bytes()).expect("UTF-8"),
            r#"{"type":"webauthn.get","challenge":"AQID","origin":"https://vault.example.com","crossOrigin":false}"#
        );
    }

    #[test]
    fn origin_drops_path_and_default_port() {
        let url = Url::parse("https://Vault.Example.com:443/vw/").expect("URL");
        assert_eq!(origin_of(&url), "https://vault.example.com");
        let url = Url::parse("http://localhost:8098/").expect("URL");
        assert_eq!(origin_of(&url), "http://localhost:8098");
    }
}
