//! Website icons from the server's `/icons/{host}/icon.png`, the endpoint the official clients
//! use. No session is involved: the request carries no token.

use std::time::Duration;

use reqwest::{StatusCode, redirect};
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::{Error, Result, http::client_builder, is_local_host, validate_server_url};

/// Favicons are a few KB; Vaultwarden itself refuses icons over 512 KB.
const MAX_ICON_BYTES: usize = 512 << 10;
/// With `ICON_SERVICE` set to an external service Vaultwarden answers with a redirect to it.
/// Only https hops to public DNS names are followed (see [`follow`]).
const MAX_REDIRECTS: usize = 3;
/// SHA-256 of Vaultwarden's `static/images/fallback-icon.png`, served with a 200 when a site has
/// no icon; the caller shows its own placeholder instead.
const FALLBACK_ICON_SHA256: [u8; 32] = [
    0x01, 0xd7, 0xdd, 0xb3, 0xc3, 0xc4, 0x6c, 0xa2, 0x4f, 0x7d, 0x91, 0x1a, 0xbd, 0x32, 0x84, 0x9a,
    0xa1, 0x96, 0x27, 0xc8, 0xbe, 0x51, 0x52, 0x73, 0xbd, 0xfb, 0x98, 0x10, 0x04, 0x60, 0xaa, 0xcb,
];

pub struct IconFetcher {
    http: reqwest::Client,
}

impl IconFetcher {
    /// `timeout` bounds the connect and each whole request.
    pub fn new(timeout: Duration) -> Result<Self> {
        let http = client_builder()
            .redirect(redirect::Policy::custom(follow))
            // The previous hop names the self-hosted server and the site.
            .referer(false)
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()?;
        Ok(Self { http })
    }

    /// The icon's bytes, or `None` when the server has none for `host`: a 404 or 410, a redirect
    /// that is not followed, the fallback icon, or something that is not a raster image. Other
    /// statuses (a 502 while Vaultwarden restarts, a 429) and transport errors are `Err`, so the
    /// caller can try again later.
    pub async fn fetch(&self, server: &Url, host: &str) -> Result<Option<Vec<u8>>> {
        validate_server_url(server)?;
        let mut response = self
            .http
            .get(icon_url(server, host)?)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND || status == StatusCode::GONE || status.is_redirection()
        {
            return Ok(None);
        }
        if status != StatusCode::OK {
            return Err(Error::Server {
                status: status.as_u16(),
                message: format!("{status} from the icon service"),
            });
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(reqwest::Error::without_url)?
        {
            if body.len() + chunk.len() > MAX_ICON_BYTES {
                return Ok(None);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(usable(&body).then_some(body))
    }
}

/// Follows a hop only to `https` on a public DNS name, so a redirect can neither downgrade the
/// request to plain text nor point it at this machine or the local network.
fn follow(attempt: redirect::Attempt<'_>) -> redirect::Action {
    let url = attempt.url();
    let public_https = url.scheme() == "https"
        && matches!(url.host(), Some(Host::Domain(_)))
        && url
            .host()
            .is_some_and(|host| !is_local_host(&host.to_owned()));
    if public_https && attempt.previous().len() <= MAX_REDIRECTS {
        attempt.follow()
    } else {
        attempt.stop()
    }
}

/// `{server}/icons/{host}/icon.png`, keeping a path prefix such as `/vw`.
pub fn icon_url(server: &Url, host: &str) -> Result<Url> {
    let mut url = server.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .map_err(|()| url::ParseError::RelativeUrlWithCannotBeABaseBase)?
        .pop_if_empty()
        .extend(["icons", host, "icon.png"]);
    Ok(url)
}

fn usable(body: &[u8]) -> bool {
    is_raster(body) && Sha256::digest(body).as_slice() != FALLBACK_ICON_SHA256
}

/// The raster formats Vaultwarden recognises (its `get_icon_type`). SVG is left out: it would be
/// rasterised on the UI thread.
fn is_raster(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        [137, 80, 78, 71, 13, 10, 26, 10, ..]
            | [82, 73, 70, 70, _, _, _, _, 87, 69, 66, 80, ..]
            | [71, 73, 70, 56, 55 | 57, 97, ..]
            | [66, 77, _, _, _, _, 0, 0, 0, 0, ..]
    ) || matches!(bytes, [0, 0, 1, 0, n1, n2, ..] if u16::from_le_bytes([*n1, *n2]) > 0)
        || matches!(bytes, [255, 216, 255, b, ..] if *b >= 0xC0)
}

#[cfg(test)]
mod tests {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    const PNG: &[u8] = &[137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13];

    fn fetcher() -> IconFetcher {
        IconFetcher::new(Duration::from_secs(5)).expect("client")
    }

    #[test]
    fn icon_url_keeps_a_path_prefix() {
        let plain = Url::parse("https://vault.example").expect("url");
        assert_eq!(
            icon_url(&plain, "github.com").expect("url").as_str(),
            "https://vault.example/icons/github.com/icon.png"
        );
        let prefixed = Url::parse("https://example.org/vw?x=1").expect("url");
        assert_eq!(
            icon_url(&prefixed, "github.com").expect("url").as_str(),
            "https://example.org/vw/icons/github.com/icon.png"
        );
        let slash = Url::parse("https://example.org/vw/").expect("url");
        assert_eq!(
            icon_url(&slash, "a.b").expect("url").as_str(),
            "https://example.org/vw/icons/a.b/icon.png"
        );
    }

    #[test]
    fn recognises_raster_formats_only() {
        assert!(is_raster(PNG));
        assert!(is_raster(&[0, 0, 1, 0, 1, 0, 16, 16]));
        assert!(is_raster(&[255, 216, 255, 0xE0, 0]));
        assert!(is_raster(b"GIF89a...."));
        assert!(is_raster(b"RIFF\0\0\0\0WEBPVP8 "));
        assert!(!is_raster(b"<svg xmlns='http://www.w3.org/2000/svg'/>"));
        assert!(!is_raster(b"<html>"));
        assert!(!is_raster(&[0, 0, 1, 0, 0, 0]), "an ICO with no images");
    }

    #[tokio::test]
    async fn fetches_the_icon_and_drops_misses() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/icons/github.com/icon.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(PNG))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/icons/missing.example/icon.png"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/icons/busy.example/icon.png"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/icons/page.example/icon.png"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
            .mount(&server)
            .await;
        let base = Url::parse(&server.uri()).expect("url");
        let fetcher = fetcher();
        assert_eq!(
            fetcher.fetch(&base, "github.com").await.expect("fetch"),
            Some(PNG.to_vec())
        );
        assert_eq!(
            fetcher
                .fetch(&base, "missing.example")
                .await
                .expect("fetch"),
            None
        );
        assert_eq!(
            fetcher.fetch(&base, "page.example").await.expect("fetch"),
            None
        );
        assert!(
            fetcher.fetch(&base, "busy.example").await.is_err(),
            "a 503 is worth retrying"
        );
    }

    #[tokio::test]
    async fn treats_vaultwardens_fallback_icon_as_a_miss() {
        // Vaultwarden's fallback-icon.png: a 19x19 grey globe.
        let fallback = include_bytes!("../tests/fixtures/vaultwarden-fallback-icon.png");
        assert_eq!(Sha256::digest(fallback).as_slice(), FALLBACK_ICON_SHA256);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/icons/none.example/icon.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(fallback.as_slice()))
            .mount(&server)
            .await;
        let base = Url::parse(&server.uri()).expect("url");
        assert_eq!(
            fetcher().fetch(&base, "none.example").await.expect("fetch"),
            None
        );
    }

    #[tokio::test]
    async fn refuses_redirects_to_plain_http_or_local_addresses() {
        let server = MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        for (host, target) in [
            (
                "plain.example",
                "http://icons.example.net/plain.example.ico",
            ),
            ("loopback.example", "https://127.0.0.1/x.ico"),
            ("local.example", "https://localhost/x.ico"),
            ("lan.example", "https://192.168.1.1/x.ico"),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/icons/{host}/icon.png")))
                .respond_with(ResponseTemplate::new(307).insert_header("location", target))
                .mount(&server)
                .await;
            assert_eq!(
                fetcher().fetch(&base, host).await.expect("fetch"),
                None,
                "{target}"
            );
        }
        let requests = server.received_requests().await.expect("recorded");
        assert!(
            requests
                .iter()
                .all(|request| request.headers.get("referer").is_none()),
            "no Referer"
        );
    }

    #[tokio::test]
    async fn caps_the_body() {
        let server = MockServer::start().await;
        let mut big = PNG.to_vec();
        big.resize(MAX_ICON_BYTES + 1, 0);
        Mock::given(method("GET"))
            .and(path("/icons/big.example/icon.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(big))
            .mount(&server)
            .await;
        let base = Url::parse(&server.uri()).expect("url");
        assert_eq!(
            fetcher().fetch(&base, "big.example").await.expect("fetch"),
            None
        );
    }
}
