//! The login screen's server check: `GET /alive` proves a Vaultwarden-style server answers, then
//! `GET /api/version` names its release ("1.37.5", a JSON string).

use std::time::Duration;

use url::Url;

use super::background::{probe_client, server_url};
use crate::{Error, Result, model::ServerProbe};

/// The version body is a short JSON string; anything longer is not what we asked for.
const MAX_VERSION_BODY: usize = 128;
const MAX_VERSION_LEN: usize = 40;

pub(super) async fn probe(server: &Url, timeout: Duration) -> Result<ServerProbe> {
    let http = probe_client(timeout).map_err(bwl_api::Error::from)?;
    let response = http
        .get(server_url(server, "alive").map_err(bwl_api::Error::from)?)
        .send()
        .await
        .map_err(bwl_api::Error::from)?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::Api(bwl_api::Error::Server {
            status: status.as_u16(),
            message: format!("{status} from /alive"),
        }));
    }
    let version = match server_url(server, "api/version") {
        Ok(url) => fetch_version(&http, url).await,
        Err(_) => None,
    };
    Ok(ServerProbe { version })
}

async fn fetch_version(http: &reqwest::Client, url: Url) -> Option<String> {
    let mut response = http.get(url).send().await.ok()?;
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
}
