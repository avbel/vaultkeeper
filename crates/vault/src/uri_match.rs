//! Browser URL validation and Bitwarden URI matching, without network access.
use url::{Host, Url};

#[derive(Clone, Copy, Debug)]
pub enum MatchRule {
    Domain,
    Host,
    StartsWith,
    Exact,
    Regex,
    Never,
}
#[derive(Clone, Copy, Debug)]
pub enum DefaultMatch {
    Domain,
    Host,
}

pub struct PageUrl {
    url: Url,
}
impl PageUrl {
    #[must_use]
    pub fn new(origin: &str, path: &str) -> Option<Self> {
        if origin.len() > 2048
            || path.len() > 2048
            || !path.starts_with('/')
            || path.contains(['?', '#', '\\'])
            || origin.contains(['?', '#', '@'])
        {
            return None;
        }
        let mut url = Url::parse(origin).ok()?;
        if !web_url(&url)
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return None;
        }
        url.set_path(path);
        Some(Self { url })
    }
    #[must_use]
    pub fn host_ascii(&self) -> &str {
        self.url.host_str().unwrap_or_default()
    }
    /// `scheme://host[:port]` in ASCII form, the address to store for this site.
    #[must_use]
    pub fn origin(&self) -> String {
        self.url.origin().ascii_serialization()
    }
    #[must_use]
    pub fn is_https(&self) -> bool {
        self.url.scheme() == "https"
    }
    /// The registrable domain by the public suffix list, or the whole host when it has none
    /// (an IP address, `localhost`, an unknown suffix). The same key `Domain` matching uses.
    #[must_use]
    pub fn registrable_domain(&self) -> String {
        domain_key(&self.url).to_ascii_lowercase()
    }
    /// The site's own name: the registrable domain without its public suffix, in ASCII form
    /// (`example` for `login.example.co.uk`). `None` for addresses, `localhost`, unknown suffixes
    /// and the private section of the suffix list (`bob.github.io` names a tenant of a host,
    /// not a site that anyone can claim the same name for elsewhere).
    #[must_use]
    pub fn site_label(&self) -> Option<String> {
        site_label_of(&self.url)
    }
}

/// [`PageUrl::site_label`] for a stored address; the scheme may be missing, as for `matches`.
#[must_use]
pub fn saved_site_label(saved_uri: &str) -> Option<String> {
    let parsed = if saved_uri.contains("://") {
        Url::parse(saved_uri)
    } else {
        Url::parse(&format!("https://{saved_uri}"))
    }
    .ok()?;
    web_url(&parsed).then(|| site_label_of(&parsed)).flatten()
}

fn site_label_of(url: &Url) -> Option<String> {
    if !matches!(url.host(), Some(Host::Domain(_))) {
        return None;
    }
    let host = url.host_str()?.trim_end_matches('.');
    let suffix = psl::suffix(host.as_bytes())?;
    if !suffix.is_known() || suffix.typ() != Some(psl::Type::Icann) {
        return None;
    }
    let domain = psl::domain_str(host)?;
    let label = domain
        .strip_suffix(std::str::from_utf8(suffix.as_bytes()).ok()?)?
        .trim_end_matches('.');
    (!label.is_empty()).then(|| label.to_ascii_lowercase())
}
fn web_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https") && url.host().is_some()
}
fn domain_key(url: &Url) -> &str {
    let host = url.host_str().unwrap_or_default().trim_end_matches('.');
    if matches!(url.host(), Some(Host::Domain(_)))
        && psl::suffix(host.as_bytes()).is_some_and(|suffix| suffix.is_known())
    {
        psl::domain_str(host).unwrap_or(host)
    } else {
        host
    }
}
/// Whether a page on `host` may use the WebAuthn relying party id `rp_id`: the host itself or a
/// parent domain of it that is not a public suffix (`example.com` for `login.example.com`, never
/// `com` or `github.io`). Hosts and ids are compared in lower-case ASCII; addresses never pass.
#[must_use]
pub fn valid_rp_id(rp_id: &str, host: &str) -> bool {
    let rp_id = rp_id.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if rp_id.is_empty() || !matches!(Host::parse(&host), Ok(Host::Domain(_))) {
        return false;
    }
    if rp_id == "localhost" {
        return host == "localhost";
    }
    let below = host == rp_id || host.ends_with(&format!(".{rp_id}"));
    below && psl::domain_str(&rp_id).is_some()
}

/// Match a stored Bitwarden URI rule (0..=5); unknown rules never match.
#[must_use]
pub fn matches(saved_uri: &str, rule: Option<u8>, default: DefaultMatch, page: &PageUrl) -> bool {
    let rule = match rule {
        None => match default {
            DefaultMatch::Domain => MatchRule::Domain,
            DefaultMatch::Host => MatchRule::Host,
        },
        Some(0) => MatchRule::Domain,
        Some(1) => MatchRule::Host,
        Some(2) => MatchRule::StartsWith,
        Some(3) => MatchRule::Exact,
        Some(4) => MatchRule::Regex,
        _ => MatchRule::Never,
    };
    if matches!(rule, MatchRule::Never) {
        return false;
    }
    if matches!(rule, MatchRule::Regex) {
        // An ambiguous pattern must not authorize a downgrade to an insecure page.
        if !page.is_https()
            && !saved_uri.starts_with("http://")
            && !saved_uri.starts_with("^http://")
        {
            return false;
        }
        return regex::RegexBuilder::new(saved_uri)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .build()
            .is_ok_and(|regex| regex.is_match(page.url.as_str()));
    }
    let parsed = if saved_uri.contains("://") {
        Url::parse(saved_uri)
    } else {
        Url::parse(&format!("https://{saved_uri}"))
    };
    let Ok(mut saved) = parsed else {
        return false;
    };
    if !web_url(&saved) || (!page.is_https() && saved.scheme() != "http") {
        return false;
    }
    saved.set_query(None);
    saved.set_fragment(None);
    match rule {
        MatchRule::Domain => domain_key(&saved) == domain_key(&page.url),
        MatchRule::Host => {
            saved.host_str().map(|host| host.trim_end_matches('.'))
                == Some(page.host_ascii().trim_end_matches('.'))
                && saved.port_or_known_default() == page.url.port_or_known_default()
        }
        MatchRule::StartsWith => page.url.as_str().starts_with(saved.as_str()),
        MatchRule::Exact => page.url == saved,
        MatchRule::Regex | MatchRule::Never => false,
    }
}

#[cfg(test)]
mod rp_id_tests {
    use super::valid_rp_id;

    #[test]
    fn an_rp_id_is_the_host_or_a_registrable_parent() {
        assert!(valid_rp_id("example.com", "example.com"));
        assert!(valid_rp_id("example.com", "login.example.com"));
        assert!(valid_rp_id("Example.COM.", "login.example.com"));
        assert!(valid_rp_id("login.example.com", "login.example.com"));
        assert!(valid_rp_id("localhost", "localhost"));
        assert!(!valid_rp_id("other.com", "example.com"));
        assert!(!valid_rp_id("ample.com", "example.com"));
        assert!(!valid_rp_id("com", "example.com"));
        assert!(!valid_rp_id("github.io", "bob.github.io"));
        assert!(!valid_rp_id("co.uk", "shop.co.uk"));
        assert!(!valid_rp_id("sub.example.com", "example.com"));
        assert!(!valid_rp_id("127.0.0.1", "127.0.0.1"));
        assert!(!valid_rp_id("", "example.com"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)] // Table from BROWSERS.md, kept together for comparison.
    fn uri_match_plan_cases() {
        let cases = [
            (
                "https://github.com/login",
                None,
                "https://gist.github.com/x",
                true,
            ),
            (
                "https://github.com",
                None,
                "https://github.com.evil.io/",
                false,
            ),
            (
                "https://alice.github.io",
                Some(0),
                "https://bob.github.io/",
                false,
            ),
            ("github.com", None, "https://github.com/", true),
            ("https://example.com", Some(0), "http://example.com/", false),
            (
                "http://nas.local:5000",
                Some(0),
                "http://nas.local:5001/",
                true,
            ),
            ("http://192.168.1.2", Some(0), "http://192.168.1.3/", false),
            (
                "https://a.corp.internal",
                Some(0),
                "https://b.corp.internal/",
                false,
            ),
            (
                "http://localhost:3000",
                Some(0),
                "http://localhost:4000/",
                true,
            ),
            (
                "https://example.com.",
                Some(0),
                "https://example.com/",
                true,
            ),
            (
                "https://a.example.com:8443",
                Some(1),
                "https://a.example.com/",
                false,
            ),
            (
                "https://a.example.com",
                Some(1),
                "https://b.example.com/",
                false,
            ),
            (
                "https://example.com/app",
                Some(2),
                "https://example.com/app/login",
                true,
            ),
            (
                "https://example.com/app",
                Some(2),
                "https://example.com/other",
                false,
            ),
            (
                "https://example.com/login?x=1",
                Some(3),
                "https://example.com/login",
                true,
            ),
            ("https://example.com", Some(3), "https://example.com/", true),
            (
                r"^https://[a-z]+\.example\.com/",
                Some(4),
                "https://dev.example.com/",
                true,
            ),
            ("(", Some(4), "https://example.com/", false),
            (
                "https://example.com",
                Some(5),
                "https://example.com/",
                false,
            ),
            ("androidapp://com.x", None, "https://x.com/", false),
            (
                "https://xn--e1afmkfd.xn--p1ai",
                Some(0),
                "https://пример.рф/",
                true,
            ),
            ("http://[::1]", Some(0), "http://[::2]/", false),
            (
                "https://example.com",
                Some(99),
                "https://example.com/",
                false,
            ),
            (
                "https://EXAMPLE.com/App",
                Some(3),
                "https://example.com/app",
                false,
            ),
        ];
        for (saved, rule, page, expected) in cases {
            let url = Url::parse(page).unwrap();
            let page = PageUrl::new(&url.origin().ascii_serialization(), url.path()).unwrap();
            assert_eq!(
                matches(saved, rule, DefaultMatch::Domain, &page),
                expected,
                "{saved} {rule:?}"
            );
        }
    }

    #[test]
    fn uri_match_validates_page_and_default_host() {
        for origin in [
            "file:///tmp",
            "https://u:p@example.com",
            "https://example.com/path",
            "https://example.com/?",
            "https://example.com/#",
        ] {
            assert!(PageUrl::new(origin, "/").is_none(), "{origin}");
        }
        for path in ["relative", "/?q", "/#f", "/\\evil"] {
            assert!(PageUrl::new("https://example.com", path).is_none());
        }
        let page = PageUrl::new("https://a.example.com", "/").unwrap();
        assert!(!matches(
            "https://b.example.com",
            None,
            DefaultMatch::Host,
            &page
        ));
        assert!(matches(
            "https://a.example.com:443",
            Some(1),
            DefaultMatch::Host,
            &page
        ));
        assert!(matches(
            "http://a.example.com",
            Some(0),
            DefaultMatch::Domain,
            &page
        ));
    }
}

#[cfg(test)]
mod downgrade_tests {
    use super::*;
    #[test]
    fn regex_requires_explicit_http_on_insecure_pages() {
        let page = PageUrl::new("http://example.com", "/").unwrap();
        for (pattern, expected) in [
            ("^http://example", true),
            ("http://example", true),
            (".*example", false),
            ("^https?://example", false),
        ] {
            assert_eq!(
                matches(pattern, Some(4), DefaultMatch::Domain, &page),
                expected
            );
        }
    }

    #[test]
    fn site_labels_link_only_the_same_name_under_another_public_suffix() {
        let page = |origin: &str| PageUrl::new(origin, "/").expect("page");
        // (saved address, page, may the page's address be linked to the login)
        for (saved, origin, linked) in [
            ("https://site.com", "https://site.io", true),
            ("HTTPS://SITE.COM./login", "https://site.io", true),
            ("https://site.co.uk", "https://site.uk", true),
            ("site.com", "https://login.site.io", true),
            ("https://example.co.uk", "https://example.com", true),
            ("https://2ip.ru/login", "https://2ip.io", true),
            ("https://site.com", "https://site.another.com", false),
            ("https://site.com", "https://another.site-login.com", false),
            ("https://site.com", "https://sitе.com", false),
            ("https://site.com", "https://xn--site-9nd.com", false),
            ("https://bob.github.io", "https://bob.gitlab.io", false),
            ("https://nas.local", "https://nas.example.com", false),
            ("http://192.168.1.2", "https://192.168.1.2", false),
            ("https://localhost", "http://localhost", false),
        ] {
            let page = page(origin);
            let same = page.site_label().is_some() && saved_site_label(saved) == page.site_label();
            assert_eq!(same, linked, "{saved} vs {origin}");
        }
    }
}
