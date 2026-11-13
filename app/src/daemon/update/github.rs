//! GitHub's latest-release API and the app zip download.

use std::{path::Path, sync::Mutex, time::Duration};

use reqwest::{StatusCode, header, redirect};
use tokio::io::AsyncWriteExt as _;
use url::Url;

use super::release::{Release, ReleaseError, parse_latest};

const LATEST: &str = "https://api.github.com/repos/avbel/vaultkeeper/releases/latest";
/// Release zips are about 15 MB; anything far larger is not ours.
const MAX_ZIP: u64 = 200 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// No network, DNS or TLS failure: try again later without reporting a failure.
    #[error("GitHub is unreachable")]
    Offline,
    #[error("GitHub rate limit reached")]
    RateLimited,
    #[error("GitHub answered {0}")]
    Status(StatusCode),
    #[error(transparent)]
    Release(#[from] ReleaseError),
}

pub struct GitHub {
    http: reqwest::Client,
    latest: Url,
    /// The last answer and its ETag: a 304 for `If-None-Match` does not count against the limit.
    cached: Mutex<Option<(header::HeaderValue, Option<Release>)>>,
}

impl GitHub {
    pub fn new() -> anyhow::Result<Self> {
        Self::with_api(Url::parse(LATEST)?)
    }

    pub fn with_api(latest: Url) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .tls_backend_rustls()
            // GitHub rejects API requests without a User-Agent.
            .user_agent(concat!("vaultkeeper/", env!("CARGO_PKG_VERSION")))
            // Asset downloads redirect to a CDN host; never follow one off https.
            .redirect(redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 || attempt.url().scheme() != "https" {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .connect_timeout(TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            latest,
            cached: Mutex::new(None),
        })
    }

    /// `Ok(None)` when the repository has no usable release.
    pub async fn latest(&self) -> Result<Option<Release>, CheckError> {
        let etag = self.cached_entry().map(|(etag, _)| etag);
        let mut request = self
            .http
            .get(self.latest.clone())
            .timeout(TIMEOUT)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(etag) = etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        let response = request.send().await.map_err(|_| CheckError::Offline)?;
        match response.status() {
            StatusCode::NOT_MODIFIED => {
                if let Some((_, release)) = self.cached_entry() {
                    return Ok(release);
                }
                Err(CheckError::Status(StatusCode::NOT_MODIFIED))
            }
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => Err(CheckError::RateLimited),
            status if status.is_success() => {
                let etag = response.headers().get(header::ETAG).cloned();
                let body = response.bytes().await.map_err(|_| CheckError::Offline)?;
                let release = parse_latest(&body)?;
                if let Some(etag) = etag {
                    *self.cache() = Some((etag, release.clone()));
                }
                Ok(release)
            }
            status => Err(CheckError::Status(status)),
        }
    }

    /// Streams the release's zip into `dest`, refusing anything larger than the size GitHub
    /// announced (and [`MAX_ZIP`]) or shorter than it.
    pub async fn download(&self, release: &Release, dest: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(
            release.zip_size > 0 && release.zip_size <= MAX_ZIP,
            "unexpected update size {} bytes",
            release.zip_size
        );
        let mut response = self
            .http
            .get(release.zip.clone())
            .timeout(DOWNLOAD_TIMEOUT)
            .send()
            .await?
            .error_for_status()?;
        let mut file = tokio::fs::File::create(dest).await?;
        let mut written = 0_u64;
        while let Some(chunk) = response.chunk().await? {
            written += chunk.len() as u64;
            anyhow::ensure!(
                written <= release.zip_size,
                "the download is larger than announced"
            );
            file.write_all(&chunk).await?;
        }
        anyhow::ensure!(
            written == release.zip_size,
            "the download stopped after {written} of {} bytes",
            release.zip_size
        );
        file.sync_all().await?;
        Ok(())
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Option<(header::HeaderValue, Option<Release>)>> {
        self.cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cached_entry(&self) -> Option<(header::HeaderValue, Option<Release>)> {
        self.cache().clone()
    }
}

#[cfg(test)]
mod tests {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header as has_header, method, path},
    };

    use super::*;

    fn latest_json() -> serde_json::Value {
        serde_json::json!({
            "tag_name": "v9.0.0",
            "html_url": "https://github.com/avbel/vaultkeeper/releases/tag/v9.0.0",
            "assets": [{
                "name": "Vaultkeeper-v9.0.0-arm64.app.zip",
                "browser_download_url": "https://github.com/avbel/vaultkeeper/releases/download/v9.0.0/Vaultkeeper-v9.0.0-arm64.app.zip",
                "size": 5
            }]
        })
    }

    fn client(server: &MockServer) -> GitHub {
        GitHub::with_api(Url::parse(&format!("{}/latest", server.uri())).expect("url"))
            .expect("client")
    }

    #[tokio::test]
    async fn reuses_the_cached_release_on_not_modified() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/latest"))
            .and(has_header("if-none-match", "\"v1\""))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"v1\"")
                    .set_body_json(latest_json()),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let github = client(&server);
        let first = github.latest().await.expect("first").expect("release");
        let second = github.latest().await.expect("second").expect("release");
        assert_eq!(first, second);
        assert_eq!(first.version.to_string(), "9.0.0");
    }

    #[tokio::test]
    async fn rate_limits_and_outages_are_reported_apart() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let github = client(&server);
        assert!(matches!(
            github.latest().await,
            Err(CheckError::RateLimited)
        ));

        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = closed.local_addr().expect("addr").port();
        drop(closed);
        let offline =
            GitHub::with_api(Url::parse(&format!("http://127.0.0.1:{port}/latest")).expect("url"))
                .expect("client");
        assert!(matches!(offline.latest().await, Err(CheckError::Offline)));
    }

    #[tokio::test]
    async fn downloads_exactly_the_announced_size() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello".to_vec()))
            .mount(&server)
            .await;
        let github = client(&server);
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("update.zip");
        let mut release = Release {
            version: "9.0.0".parse().expect("version"),
            zip: Url::parse(&format!("{}/zip", server.uri())).expect("url"),
            zip_size: 5,
            page: Url::parse("https://github.com/avbel/vaultkeeper").expect("url"),
        };
        github.download(&release, &dest).await.expect("download");
        assert_eq!(std::fs::read(&dest).expect("read"), b"hello");

        release.zip_size = 4;
        assert!(
            github.download(&release, &dest).await.is_err(),
            "larger than announced"
        );
        release.zip_size = 6;
        assert!(
            github.download(&release, &dest).await.is_err(),
            "shorter than announced"
        );
        release.zip_size = MAX_ZIP + 1;
        assert!(github.download(&release, &dest).await.is_err(), "too large");
    }
}
