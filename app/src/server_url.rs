//! Validation and normalisation of the login screen's server URL.

use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServerUrlError {
    #[error("Enter the server URL")]
    Empty,
    #[error("Not a valid URL")]
    Invalid,
    #[error("Use https:// — http is only allowed for localhost and private networks")]
    InsecurePublic,
    #[error("Only https:// server URLs are supported")]
    UnsupportedScheme,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl {
    pub url: Url,
    /// Set for plain-http URLs on a local or private network.
    pub warning: Option<&'static str>,
}

pub const HTTP_WARNING: &str =
    "Unencrypted http: only use this on a trusted local network or for testing.";

/// Parses what the user typed or pasted. A missing scheme means https; the query, a web-vault
/// fragment (`/#/login`, `/#/vault`) and trailing slashes are dropped; a sub-path such as
/// `/vaultwarden` is kept for servers hosted under one.
pub fn normalize(input: &str) -> Result<ServerUrl, ServerUrlError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ServerUrlError::Empty);
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let mut url = Url::parse(&with_scheme).map_err(|_| ServerUrlError::Invalid)?;
    let host = url
        .host()
        .map(|host| host.to_owned())
        .ok_or(ServerUrlError::Invalid)?;
    let warning = match url.scheme() {
        "https" => None,
        "http" if is_local(&host) => Some(HTTP_WARNING),
        "http" => return Err(ServerUrlError::InsecurePublic),
        _ => return Err(ServerUrlError::UnsupportedScheme),
    };
    url.set_fragment(None);
    url.set_query(None);
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(ServerUrl { url, warning })
}

/// The URL as shown in the field: no trailing slash.
#[must_use]
pub fn display(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_owned()
}

fn is_local(host: &Host<String>) -> bool {
    match host {
        Host::Domain(name) => {
            let name = name.to_ascii_lowercase();
            name == "localhost"
                || std::path::Path::new(&name)
                    .extension()
                    .is_some_and(|tld| tld == "local" || tld == "localhost")
        }
        Host::Ipv4(ip) => is_private_v4(*ip),
        Host::Ipv6(ip) => is_private_v6(*ip),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local()
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    // fc00::/7 unique local, fe80::/10 link local.
    ip.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> ServerUrl {
        normalize(input).unwrap_or_else(|error| panic!("{input}: {error}"))
    }

    #[test]
    fn accepts_https() {
        let server = ok("https://vault.example.com");
        assert_eq!(display(&server.url), "https://vault.example.com");
        assert_eq!(server.warning, None);
    }

    #[test]
    fn missing_scheme_means_https() {
        assert_eq!(
            display(&ok("vault.example.com").url),
            "https://vault.example.com"
        );
    }

    #[test]
    fn web_vault_urls_are_normalized() {
        for pasted in [
            "https://vault.example.com/",
            "https://vault.example.com/#/",
            "https://vault.example.com/#/login",
            "https://vault.example.com/#/vault?itemId=1",
            "  https://vault.example.com//  ",
        ] {
            assert_eq!(
                display(&ok(pasted).url),
                "https://vault.example.com",
                "{pasted}"
            );
        }
        assert_eq!(
            display(&ok("https://example.com/vaultwarden/#/login").url),
            "https://example.com/vaultwarden"
        );
    }

    #[test]
    fn http_is_allowed_with_warning_only_for_local_hosts() {
        for local in [
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://192.168.1.20:8000",
            "http://10.0.0.5",
            "http://172.20.1.1",
            "http://nas.local",
            "http://[::1]:8080",
            "http://[fd12:3456::1]",
        ] {
            assert_eq!(ok(local).warning, Some(HTTP_WARNING), "{local}");
        }
        assert_eq!(
            normalize("http://vault.example.com"),
            Err(ServerUrlError::InsecurePublic)
        );
        assert_eq!(
            normalize("http://8.8.8.8"),
            Err(ServerUrlError::InsecurePublic)
        );
        assert_eq!(
            normalize("http://172.32.0.1"),
            Err(ServerUrlError::InsecurePublic)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(normalize(""), Err(ServerUrlError::Empty));
        assert_eq!(normalize("   "), Err(ServerUrlError::Empty));
        assert_eq!(normalize("not a url at all"), Err(ServerUrlError::Invalid));
        assert_eq!(normalize("https://"), Err(ServerUrlError::Invalid));
        assert_eq!(
            normalize("ftp://vault.example.com"),
            Err(ServerUrlError::UnsupportedScheme)
        );
        assert_eq!(
            normalize("https://exa mple.com"),
            Err(ServerUrlError::Invalid)
        );
        assert_eq!(normalize("https://[::zz]"), Err(ServerUrlError::Invalid));
    }
}
