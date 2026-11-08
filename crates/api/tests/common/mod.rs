#![allow(dead_code, clippy::unwrap_used)]

pub mod hub;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bwl_api::{Client, DeviceInfo};
use serde_json::Value;
use url::Url;
use uuid::Uuid;
use wiremock::{Match, MockServer, Request, ResponseTemplate};

pub const EMAIL: &str = "vault@example.com";
/// Profile id of the user in the captured fixtures; also the `sub` of the access tokens used here.
pub const USER_ID: &str = "f3d28605-dc9d-4db8-8745-0c28f1483035";
pub const DEVICE_ID: &str = "d2be9dea-71cf-49b2-a9e7-a8af15773081";
pub const PASSWORD_HASH: &str = "c2VydmVyLWhhc2g=";

pub fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|error| panic!("fixture {path}: {error}"))
}

pub fn fixture_json(name: &str) -> Value {
    serde_json::from_slice(&fixture(name)).unwrap()
}

pub fn json_response(status: u16, name: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(fixture(name), "application/json")
}

pub fn html_response(status: u16, name: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(fixture(name), "text/html; charset=utf-8")
}

/// A JWT-shaped token whose payload carries `sub`, as the server's access tokens do.
pub fn access_token() -> String {
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{USER_ID}","exp":4102444800}}"#));
    format!("eyJhbGciOiJSUzI1NiJ9.{payload}.test-signature")
}

pub fn device() -> DeviceInfo {
    DeviceInfo {
        identifier: Uuid::parse_str(DEVICE_ID).unwrap(),
        name: "macos".into(),
        device_type: 7,
    }
}

pub fn client_for(base: &str) -> Client {
    Client::new(Url::parse(base).unwrap(), device()).unwrap()
}

pub fn client(server: &MockServer) -> Client {
    client_for(&server.uri())
}

/// Matches a form-encoded body against an exact set of fields, ignoring their order.
pub struct ExactForm(pub Vec<(&'static str, String)>);

impl ExactForm {
    pub fn new(fields: &[(&'static str, &str)]) -> Self {
        Self(fields.iter().map(|(k, v)| (*k, (*v).to_owned())).collect())
    }
}

impl Match for ExactForm {
    fn matches(&self, request: &Request) -> bool {
        let mut actual: Vec<(String, String)> = url::form_urlencoded::parse(&request.body)
            .into_owned()
            .collect();
        let mut expected: Vec<(String, String)> = self
            .0
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        actual.sort();
        expected.sort();
        actual == expected
    }
}

/// The login form every password grant must carry, whatever the 2FA state.
pub fn login_fields() -> Vec<(&'static str, String)> {
    vec![
        ("grant_type", "password".into()),
        ("username", EMAIL.into()),
        ("password", PASSWORD_HASH.into()),
        ("scope", "api offline_access".into()),
        ("client_id", "desktop".into()),
        ("deviceType", "7".into()),
        ("deviceIdentifier", DEVICE_ID.into()),
        ("deviceName", "macos".into()),
    ]
}

pub fn login_form_with(extra: &[(&'static str, &str)]) -> ExactForm {
    let mut fields = login_fields();
    fields.extend(extra.iter().map(|(k, v)| (*k, (*v).to_owned())));
    ExactForm(fields)
}

/// True when the header parses as `year.month.patch` semver at or above 2024.12.0, the threshold
/// Vaultwarden uses to decide whether a client understands SSH key ciphers.
pub fn client_version_shows_ssh_keys(request: &Request) -> bool {
    let Some(version) = request.headers.get("bitwarden-client-version") else {
        return false;
    };
    let parts: Vec<u32> = version
        .to_str()
        .unwrap()
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect();
    parts.len() == 3 && (parts[0], parts[1]) >= (2024, 12)
}
