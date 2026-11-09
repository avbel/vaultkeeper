use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::{Error, Result};

/// The one definition of which server URLs may carry credentials: `https`, or plain `http` only
/// for loopback and private-network hosts, with no userinfo, query or fragment.
pub fn validate_server_url(url: &Url) -> Result<()> {
    let host = url
        .host()
        .ok_or_else(|| reject("the URL has no host"))?
        .to_owned();
    match url.scheme() {
        "https" => {}
        "http" if is_local_host(&host) => {}
        "http" => {
            return Err(reject(
                "http is only allowed for localhost and private networks",
            ));
        }
        _ => return Err(reject("only https:// server URLs are supported")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(reject("the URL must not contain a user name or password"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(reject("the URL must not contain a query or fragment"));
    }
    Ok(())
}

fn reject(reason: &'static str) -> Error {
    Error::InvalidServerUrl(reason)
}

#[must_use]
pub fn is_local_host(host: &Host<String>) -> bool {
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

    fn check(raw: &str) -> Result<()> {
        validate_server_url(&Url::parse(raw).unwrap())
    }

    #[test]
    fn accepts_https_and_local_http() {
        for raw in [
            "https://vault.example.com",
            "https://vault.example.com/vw",
            "http://localhost:8080",
            "http://127.0.0.1:1234",
            "http://[::1]:8080",
            "http://192.168.1.20",
            "http://nas.local",
        ] {
            check(raw).unwrap_or_else(|error| panic!("{raw}: {error}"));
        }
    }

    #[test]
    fn rejects_public_http_other_schemes_userinfo_query_and_fragment() {
        for raw in [
            "http://vault.example.com",
            "http://8.8.8.8",
            "ftp://vault.example.com",
            "https://user:pw@vault.example.com",
            "https://user@vault.example.com",
            "http://user@localhost",
            "https://vault.example.com/?a=1",
            "https://vault.example.com/#/login",
        ] {
            assert!(
                matches!(check(raw), Err(Error::InvalidServerUrl(_))),
                "{raw}"
            );
        }
    }
}
