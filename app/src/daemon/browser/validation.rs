//! Validation of page URLs supplied by an extension.

use std::net::IpAddr;

use vk_ipc::browser::protocol::ErrorCode;
use vk_vault::uri_match::PageUrl;

pub fn page(origin: &str, path: &str) -> Result<PageUrl, ErrorCode> {
    let page = PageUrl::new(origin, path).ok_or(ErrorCode::BadRequest)?;
    if !page.is_https() && !local_host(page.host_ascii()) {
        return Err(ErrorCode::InsecurePage);
    }
    Ok(page)
}

fn local_host(host: &str) -> bool {
    // A trailing dot marks a fully qualified name, so `ai.` is a real top-level domain and not an
    // intranet single label.
    let qualified = host.contains('.');
    let host = host.trim_end_matches('.');
    let address = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private(),
        Ok(IpAddr::V6(ip)) => ip.is_loopback() || ip.is_unique_local(),
        Err(_) => {
            !qualified
                || host
                    .rsplit_once('.')
                    .is_some_and(|(_, suffix)| suffix == "local")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trailing_dot_makes_a_real_domain_not_an_intranet_name() {
        assert!(matches!(
            page("http://ai.", "/"),
            Err(ErrorCode::InsecurePage)
        ));
        assert!(matches!(
            page("http://example.com.", "/"),
            Err(ErrorCode::InsecurePage)
        ));
        assert!(page("http://printer", "/").is_ok());
    }

    #[test]
    fn permits_only_https_or_explicitly_local_http() {
        for origin in [
            "https://example.com",
            "http://localhost:3000",
            "http://nas.local",
            "http://printer",
            "http://192.168.1.1",
            "http://[::1]",
            "http://[fd00::1]",
        ] {
            assert!(page(origin, "/login").is_ok(), "{origin}");
        }
        for origin in [
            "http://example.com",
            "http://8.8.8.8",
            "http://[2001:4860:4860::8888]",
        ] {
            assert!(
                matches!(page(origin, "/"), Err(ErrorCode::InsecurePage)),
                "{origin}"
            );
        }
        for (origin, path) in [
            ("https://user@example.com", "/"),
            ("https://example.com/path", "/"),
            ("https://example.com", "/?query"),
            ("javascript:alert(1)", "/"),
        ] {
            assert!(
                matches!(page(origin, path), Err(ErrorCode::BadRequest)),
                "{origin} {path}"
            );
        }
    }
}
