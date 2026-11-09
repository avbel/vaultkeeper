//! Validation and normalisation of the login screen's server URL.

use url::Url;

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
        "http" if bwl_api::is_local_host(&host) => Some(HTTP_WARNING),
        "http" => return Err(ServerUrlError::InsecurePublic),
        _ => return Err(ServerUrlError::UnsupportedScheme),
    };
    url.set_fragment(None);
    url.set_query(None);
    if bwl_api::validate_server_url(&url).is_err() {
        return Err(ServerUrlError::Invalid);
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(ServerUrl { url, warning })
}

/// The URL as shown in the field: no trailing slash.
#[must_use]
pub fn display(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_owned()
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
        assert_eq!(
            normalize("https://user:pw@vault.example.com"),
            Err(ServerUrlError::Invalid)
        );
    }
}
