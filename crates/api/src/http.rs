use std::time::Duration;

use reqwest::{
    RequestBuilder, Response, StatusCode,
    header::{HeaderMap, HeaderValue},
    redirect,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::{ParseError, Url};

use crate::{
    Error, Result,
    normalize::{normalize_keys, parse_normalized},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound for attachment transfers; `READ_TIMEOUT` still aborts a stalled one early.
pub(crate) const TRANSFER_TIMEOUT: Duration = Duration::from_secs(3600);
const MAX_BODY_BYTES: usize = 256 << 20;
const MAX_ERROR_BODY_BYTES: usize = 64 << 10;

/// Vaultwarden hides every SSH key cipher (type 5) from `/api/sync` unless this header parses as
/// semver >= 2024.12.0, so reporting the crate version (0.1.0) would silently drop them.
pub(crate) const CLIENT_VERSION: &str = "2025.12.0";

pub(crate) struct Transport {
    base: Url,
    http: reqwest::Client,
}

pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}

impl Transport {
    pub(crate) fn new(mut base: Url, device_type: u8) -> Result<Self> {
        if base.cannot_be_a_base() {
            return Err(ParseError::RelativeUrlWithCannotBeABaseBase.into());
        }
        base.set_query(None);
        base.set_fragment(None);
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }

        let mut headers = HeaderMap::new();
        headers.insert("device-type", HeaderValue::from(u16::from(device_type)));
        headers.insert("bitwarden-client-name", HeaderValue::from_static("desktop"));
        headers.insert(
            "bitwarden-client-version",
            HeaderValue::from_static(CLIENT_VERSION),
        );

        let http = reqwest::Client::builder()
            .tls_backend_rustls()
            .user_agent(concat!("bw-lite/", env!("CARGO_PKG_VERSION")))
            .default_headers(headers)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            // Credentials and tokens must only ever go to the address the user configured.
            .redirect(redirect::Policy::none())
            .build()?;
        Ok(Self { base, http })
    }

    pub(crate) fn endpoint(&self, segments: &[&str]) -> Result<Url> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| ParseError::RelativeUrlWithCannotBeABaseBase)?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    /// Resolves an attachment URL that is either relative to the server or absolute on the
    /// configured server's own origin. Anything else is refused before a request is made.
    pub(crate) fn resolve_same_origin(&self, raw: &str) -> Result<Url> {
        match Url::parse(raw) {
            Ok(url) if url.origin() == self.base.origin() => Ok(url),
            Ok(url) => Err(Error::UntrustedUrl(
                url.host_str().unwrap_or("<none>").to_owned(),
            )),
            Err(ParseError::RelativeUrlWithoutBase) => {
                Ok(self.base.join(raw.trim_start_matches('/'))?)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn get(&self, url: Url) -> RequestBuilder {
        self.http.get(url)
    }

    pub(crate) fn post(&self, url: Url) -> RequestBuilder {
        self.http.post(url)
    }

    pub(crate) fn put(&self, url: Url) -> RequestBuilder {
        self.http.put(url)
    }

    pub(crate) fn delete(&self, url: Url) -> RequestBuilder {
        self.http.delete(url)
    }

    pub(crate) async fn execute(&self, request: RequestBuilder) -> Result<Reply> {
        let response = request.send().await?;
        read_reply(response).await
    }

    /// Sends a request whose URL carries a secret (attachment download tokens) and returns the
    /// still-unread response on success. Transport errors drop the URL from their message.
    pub(crate) async fn open_sensitive(&self, request: RequestBuilder) -> Result<Response> {
        let response = request.send().await.map_err(reqwest::Error::without_url)?;
        if response.status().is_success() {
            return Ok(response);
        }
        Err(read_reply(response).await?.failure())
    }
}

async fn read_reply(mut response: Response) -> Result<Reply> {
    let status = response.status();
    let success = status.is_success();
    let limit = if success {
        MAX_BODY_BYTES
    } else {
        MAX_ERROR_BODY_BYTES
    };
    let announced = response
        .content_length()
        .map_or(0, |len| usize::try_from(len).unwrap_or(limit));
    let mut body = Vec::with_capacity(announced.min(limit));
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > limit {
            if success {
                return Err(Error::Server {
                    status: status.as_u16(),
                    message: "response body too large".into(),
                });
            }
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Reply { status, body })
}

impl Reply {
    pub(crate) fn into_success(self) -> Result<Self> {
        if self.status.is_success() {
            Ok(self)
        } else {
            Err(self.failure())
        }
    }

    pub(crate) fn failure(&self) -> Error {
        if self.status == StatusCode::UNAUTHORIZED {
            Error::Unauthorized
        } else {
            self.error()
        }
    }

    pub(crate) fn json<T: DeserializeOwned>(self) -> Result<T> {
        parse_normalized(self.body)
    }

    pub(crate) fn error(&self) -> Error {
        Error::Server {
            status: self.status.as_u16(),
            message: error_message(self.status, &self.body),
        }
    }
}

/// Vaultwarden fills `message` and `errorModel.message` and leaves `error`/`error_description`
/// as empty strings; the official server and token refresh failures use the latter two instead.
pub(crate) fn error_message(status: StatusCode, body: &[u8]) -> String {
    if status.is_redirection() {
        return "the server redirected the request; use its final address (including https://) \
                as the server URL"
            .into();
    }
    if let Ok(mut value) = serde_json::from_slice::<Value>(body) {
        normalize_keys(&mut value);
        if let Some(message) = message_candidates(&value).next() {
            return message.to_owned();
        }
    }
    status
        .canonical_reason()
        .map_or_else(|| format!("HTTP {}", status.as_u16()), str::to_owned)
}

pub(crate) fn message_candidates(value: &Value) -> impl Iterator<Item = &str> {
    [
        value.get("message"),
        value.pointer("/errorModel/message"),
        value.get("error_description"),
        value.get("error"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport(base: &str) -> Transport {
        Transport::new(Url::parse(base).unwrap(), 7).unwrap()
    }

    #[test]
    fn endpoint_appends_segments_to_a_bare_host() {
        let url = transport("https://vault.example.com")
            .endpoint(&["api", "sync"])
            .unwrap();
        assert_eq!(url.as_str(), "https://vault.example.com/api/sync");
    }

    #[test]
    fn endpoint_keeps_a_path_prefix_with_or_without_trailing_slash() {
        for base in ["https://host.example/vw", "https://host.example/vw/"] {
            let url = transport(base)
                .endpoint(&["identity", "connect", "token"])
                .unwrap();
            assert_eq!(
                url.as_str(),
                "https://host.example/vw/identity/connect/token",
                "{base}"
            );
        }
    }

    #[test]
    fn endpoint_percent_encodes_identifier_segments() {
        let url = transport("https://h.example/")
            .endpoint(&["api", "ciphers", "a/b c"])
            .unwrap();
        assert_eq!(url.as_str(), "https://h.example/api/ciphers/a%2Fb%20c");
    }

    #[test]
    fn base_query_and_fragment_are_dropped() {
        let url = transport("https://h.example/?x=1#f")
            .endpoint(&["api", "sync"])
            .unwrap();
        assert_eq!(url.as_str(), "https://h.example/api/sync");
    }

    #[test]
    fn non_base_urls_are_rejected() {
        let result = Transport::new(Url::parse("mailto:a@b.example").unwrap(), 7);
        assert!(matches!(result, Err(Error::Url(_))));
    }

    #[test]
    fn same_origin_absolute_urls_pass_through() {
        let t = transport("https://h.example/vw/");
        let url = t
            .resolve_same_origin("https://h.example/vw/attachments/c/a?token=t")
            .unwrap();
        assert_eq!(url.as_str(), "https://h.example/vw/attachments/c/a?token=t");
    }

    #[test]
    fn relative_urls_resolve_against_the_base_path() {
        let t = transport("https://h.example/vw");
        let url = t.resolve_same_origin("/attachments/c/a?token=t").unwrap();
        assert_eq!(url.as_str(), "https://h.example/vw/attachments/c/a?token=t");
    }

    #[test]
    fn foreign_hosts_ports_and_schemes_are_refused() {
        let t = transport("https://h.example/");
        for raw in [
            "https://evil.example/attachments/c/a",
            "https://h.example:8443/attachments/c/a",
            "http://h.example/attachments/c/a",
            "https://h.example.evil.example/x",
        ] {
            let error = t.resolve_same_origin(raw).unwrap_err();
            assert!(matches!(error, Error::UntrustedUrl(_)), "{raw}: {error:?}");
        }
    }

    #[test]
    fn untrusted_host_error_does_not_leak_the_query_token() {
        let t = transport("https://h.example/");
        let error = t
            .resolve_same_origin("https://evil.example/x?token=SECRET")
            .unwrap_err();
        assert!(!error.to_string().contains("SECRET"));
    }

    #[test]
    fn protocol_relative_urls_cannot_escape_the_origin() {
        let t = transport("https://h.example/");
        let url = t.resolve_same_origin("//evil.example/x").unwrap();
        assert_eq!(url.host_str(), Some("h.example"));
    }

    #[test]
    fn message_prefers_message_then_error_model_then_description_then_error() {
        let message = |json: &str| error_message(StatusCode::BAD_REQUEST, json.as_bytes());
        assert_eq!(
            message(
                r#"{"message":"a","errorModel":{"message":"b"},"error":"","error_description":""}"#
            ),
            "a"
        );
        assert_eq!(
            message(r#"{"message":"","errorModel":{"message":"b"}}"#),
            "b"
        );
        assert_eq!(message(r#"{"ErrorModel":{"Message":"c"}}"#), "c");
        assert_eq!(
            message(r#"{"error":"invalid_grant","error_description":"d"}"#),
            "d"
        );
        assert_eq!(message(r#"{"error":"invalid_grant"}"#), "invalid_grant");
    }

    #[test]
    fn non_json_bodies_fall_back_to_the_status_reason() {
        let html = b"<!DOCTYPE html><html><h1>422</h1></html>";
        assert_eq!(
            error_message(StatusCode::UNPROCESSABLE_ENTITY, html),
            "Unprocessable Entity"
        );
        assert_eq!(
            error_message(StatusCode::from_u16(599).unwrap(), b""),
            "HTTP 599"
        );
    }

    #[test]
    fn redirects_get_an_actionable_message() {
        let message = error_message(StatusCode::MOVED_PERMANENTLY, b"");
        assert!(message.contains("redirected"), "{message}");
    }
}
