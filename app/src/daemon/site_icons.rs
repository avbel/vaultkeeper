//! Website icons for the list rows. The daemon fetches them from the active account's server and
//! keeps the bytes in memory only: on disk they would spell out the vault's sites in plain text.
//! The cache is wiped on lock, logout and account switch.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use tokio::sync::Semaphore;
use url::{Host, Url};
use vk_api::IconFetcher;
use vk_ipc::{IconFuture, SiteIcon, SiteIconHost};

const FETCH_TIMEOUT: Duration = Duration::from_secs(8);
/// Parallel requests to the server; the UI sends a screenful at once.
const MAX_FETCHES: usize = 4;
/// A host whose fetch failed (offline, timeout, 5xx) is tried again after this.
const RETRY_AFTER: Duration = Duration::from_mins(5);
/// Icon bytes kept before the cache starts over; favicons are a few KB each.
const MAX_CACHED_BYTES: usize = 32 << 20;
const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

type ServerOf = dyn Fn() -> Option<Url> + Send + Sync;

pub struct SiteIcons {
    /// The unlocked account's server; `None` while locked or logged out.
    server: Box<ServerOf>,
    fetcher: Option<IconFetcher>,
    gate: Semaphore,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<(Url, String), Entry>,
    bytes: usize,
}

#[derive(Clone)]
enum Entry {
    Icon(Arc<[u8]>),
    Missing,
    Failed(Instant),
}

impl SiteIcons {
    pub fn new(server: impl Fn() -> Option<Url> + Send + Sync + 'static) -> Arc<Self> {
        let fetcher = IconFetcher::new(FETCH_TIMEOUT)
            .inspect_err(|error| tracing::warn!(%error, "no site icon client"))
            .ok();
        Arc::new(Self {
            server: Box::new(server),
            fetcher,
            gate: Semaphore::new(MAX_FETCHES),
            cache: Mutex::default(),
        })
    }

    pub fn clear(&self) {
        *self.cache() = Cache::default();
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn load(&self, host: String) -> SiteIcon {
        if !valid_host(&host) {
            return SiteIcon::Missing;
        }
        let Some(server) = (self.server)() else {
            return SiteIcon::Unavailable;
        };
        let key = (server, host);
        match self.cache().entries.get(&key) {
            Some(Entry::Icon(bytes)) => return SiteIcon::Found(bytes.to_vec()),
            Some(Entry::Missing) => return SiteIcon::Missing,
            Some(Entry::Failed(at)) if at.elapsed() < RETRY_AFTER => return SiteIcon::Unavailable,
            Some(Entry::Failed(_)) | None => {}
        }
        let Ok(_permit) = self.gate.acquire().await else {
            return SiteIcon::Unavailable;
        };
        let Some(fetcher) = self.fetcher.as_ref() else {
            return SiteIcon::Missing;
        };
        let entry = match fetcher.fetch(&key.0, &key.1).await {
            Ok(Some(bytes)) => Entry::Icon(Arc::from(bytes)),
            Ok(None) => Entry::Missing,
            Err(error) => {
                tracing::debug!(%error, "site icon fetch failed");
                Entry::Failed(Instant::now())
            }
        };
        let mut cache = self.cache();
        // Checked under the cache lock, which `clear` also takes: a lock or account switch
        // during the fetch must not leave its result behind.
        if (self.server)().as_ref() != Some(&key.0) {
            return SiteIcon::Unavailable;
        }
        let size = match &entry {
            Entry::Icon(bytes) => bytes.len(),
            Entry::Missing | Entry::Failed(_) => 0,
        };
        if cache.bytes + size > MAX_CACHED_BYTES {
            *cache = Cache::default();
        }
        cache.bytes += size;
        if let Some(Entry::Icon(old)) = cache.entries.insert(key, entry.clone()) {
            cache.bytes -= old.len();
        }
        match entry {
            Entry::Icon(bytes) => SiteIcon::Found(bytes.to_vec()),
            Entry::Missing => SiteIcon::Missing,
            Entry::Failed(_) => SiteIcon::Unavailable,
        }
    }
}

/// The IPC side of [`SiteIcons`]: `SiteIconHost` hands out `'static` futures, so they hold an
/// owned handle.
pub struct IconHost(pub Arc<SiteIcons>);

impl SiteIconHost for IconHost {
    fn icon(&self, host: String) -> IconFuture {
        let icons = Arc::clone(&self.0);
        Box::pin(async move { icons.load(host).await })
    }
}

/// A lowercase DNS name of at least two labels, as the UI derives it from a login URI; anything
/// else is never sent to the server.
fn valid_host(host: &str) -> bool {
    let label_ok = |label: &str| {
        (1..=MAX_LABEL_LEN).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte)
            })
    };
    host.len() <= MAX_HOST_LEN
        && host.split('.').count() >= 2
        && host.split('.').all(label_ok)
        && matches!(Host::parse(host), Ok(Host::Domain(_)))
}

#[cfg(test)]
mod tests {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    const PNG: &[u8] = &[137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3];

    #[test]
    fn only_plain_domains_are_valid_hosts() {
        assert!(valid_host("github.com"));
        assert!(valid_host("xn--80ak6aa92e.com"));
        assert!(valid_host("my_host.example.org"));
        assert!(!valid_host("localhost"), "one label");
        assert!(!valid_host("GitHub.com"));
        assert!(!valid_host("10.0.0.1"));
        for odd in [
            ".", "..", "a..b", "a.b.", ".a.b", "a;b.com", "a,b.com", "-a.com", "a/b.c", "a.b?x", "",
        ] {
            assert!(!valid_host(odd), "{odd:?}");
        }
        assert!(!valid_host(&format!("{}.com", "a".repeat(64))));
    }

    fn found(bytes: &[u8]) -> SiteIcon {
        SiteIcon::Found(bytes.to_vec())
    }

    #[tokio::test]
    async fn caches_icons_and_misses_per_server_until_cleared() {
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        for (server, times) in [(&first, 2), (&second, 1)] {
            Mock::given(method("GET"))
                .and(path("/icons/github.com/icon.png"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(PNG))
                .expect(times)
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/icons/none.example/icon.png"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&first)
            .await;
        Mock::given(method("GET"))
            .and(path("/icons/busy.example/icon.png"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&first)
            .await;
        let first_url = Url::parse(&first.uri()).expect("url");
        let unlocked = Arc::new(Mutex::new(Some(first_url.clone())));
        let current = Arc::clone(&unlocked);
        let icons = SiteIcons::new(move || current.lock().expect("server").clone());
        let host = IconHost(Arc::clone(&icons));

        assert_eq!(host.icon("github.com".into()).await, found(PNG));
        assert_eq!(host.icon("github.com".into()).await, found(PNG));
        assert_eq!(host.icon("none.example".into()).await, SiteIcon::Missing);
        assert_eq!(host.icon("none.example".into()).await, SiteIcon::Missing);
        assert_eq!(
            host.icon("busy.example".into()).await,
            SiteIcon::Unavailable
        );
        assert_eq!(
            host.icon("busy.example".into()).await,
            SiteIcon::Unavailable,
            "answered from the cache until RETRY_AFTER"
        );
        assert_eq!(
            host.icon("../admin".into()).await,
            SiteIcon::Missing,
            "never requested"
        );

        *unlocked.lock().expect("server") = Some(Url::parse(&second.uri()).expect("url"));
        assert_eq!(
            host.icon("github.com".into()).await,
            found(PNG),
            "per server"
        );

        *unlocked.lock().expect("server") = None;
        assert_eq!(
            host.icon("github.com".into()).await,
            SiteIcon::Unavailable,
            "locked"
        );
        *unlocked.lock().expect("server") = Some(first_url);
        icons.clear();
        assert_eq!(host.icon("github.com".into()).await, found(PNG));
    }
}
