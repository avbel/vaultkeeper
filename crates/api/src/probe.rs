//! Session-less server checks: `GET /alive` proves a Vaultwarden-style server answers (the login
//! screen's check and the offline probe), `GET /api/version` names its release ("1.37.5", a JSON
//! string). Built with the API client's TLS and redirect setup, so a server the API trusts is
//! also reachable here.

use std::time::Duration;

use url::Url;

use crate::{Error, Result, http::client_builder, validate_server_url};

/// The version body is a short JSON string; anything longer is not what we asked for.
const MAX_VERSION_BODY: usize = 128;
const MAX_VERSION_LEN: usize = 40;

pub struct Prober {
    http: reqwest::Client,
    alive: Url,
    version: Url,
}

impl Prober {
    /// `timeout` bounds the connect and each whole request.
    pub fn new(server: &Url, timeout: Duration) -> Result<Self> {
        validate_server_url(server)?;
        let http = client_builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()?;
        Ok(Self {
            http,
            alive: server_url(server, "alive")?,
            version: server_url(server, "api/version")?,
        })
    }

    /// Any 2xx from `/alive`. A refused status is an [`Error::Server`]; transport errors keep
    /// their [`Error::is_offline`] meaning and never carry the URL.
    pub async fn alive(&self) -> Result<()> {
        let response = self
            .http
            .get(self.alive.clone())
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(Error::Server {
                status: status.as_u16(),
                message: format!("{status} from /alive"),
            })
        }
    }

    /// The server's release, or `None` when it does not say (older Vaultwarden, other servers).
    pub async fn version(&self) -> Option<String> {
        let mut response = self.http.get(self.version.clone()).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if body.len() + chunk.len() > MAX_VERSION_BODY {
                return None;
            }
            body.extend_from_slice(&chunk);
        }
        parse_version(&body)
    }
}

/// `server` joined with a relative `path`, keeping a path prefix such as `/vw`.
fn server_url(server: &Url, path: &str) -> Result<Url> {
    let mut base = server.clone();
    if !base.path().ends_with('/') {
        let prefixed = format!("{}/", base.path());
        base.set_path(&prefixed);
    }
    Ok(base.join(path)?)
}

/// Accepts only a short JSON string of printable characters, since it is shown verbatim.
fn parse_version(body: &[u8]) -> Option<String> {
    let version: String = serde_json::from_slice(body).ok()?;
    let version = version.trim();
    let printable = version.chars().all(|c| c.is_ascii_graphic() || c == ' ');
    (!version.is_empty() && version.len() <= MAX_VERSION_LEN && printable)
        .then(|| version.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_the_json_string_vaultwarden_sends() {
        // Body of `GET /api/version` on vaultwarden/server 1.37.5.
        assert_eq!(parse_version(br#""1.37.5""#).as_deref(), Some("1.37.5"));
        assert_eq!(parse_version(br#"" 1.37.5 ""#).as_deref(), Some("1.37.5"));
    }

    #[test]
    fn other_bodies_give_no_version() {
        assert_eq!(parse_version(b"1.37.5"), None, "not JSON");
        assert_eq!(parse_version(br#"{"version":"1"}"#), None);
        assert_eq!(parse_version(br#""""#), None);
        assert_eq!(parse_version("\"1.0\u{7}\"".as_bytes()), None);
        let long = format!("\"{}\"", "9".repeat(MAX_VERSION_LEN + 1));
        assert_eq!(parse_version(long.as_bytes()), None);
    }

    #[test]
    fn probe_urls_keep_a_path_prefix() {
        let plain = Url::parse("https://vault.example.com").unwrap();
        assert_eq!(
            server_url(&plain, "alive").unwrap().as_str(),
            "https://vault.example.com/alive"
        );
        let prefixed = Url::parse("https://host.example/vw").unwrap();
        assert_eq!(
            server_url(&prefixed, "alive").unwrap().as_str(),
            "https://host.example/vw/alive"
        );
        assert_eq!(
            server_url(&prefixed, "api/version").unwrap().as_str(),
            "https://host.example/vw/api/version"
        );
    }
}
