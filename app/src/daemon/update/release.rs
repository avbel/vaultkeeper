//! The latest GitHub release, as far as the updater cares: its version, the app zip and the page.

use std::{fmt, str::FromStr};

use serde::Deserialize;
use url::Url;

/// A release version `major.minor.patch`; tags carry a leading `v`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u64, u64, u64);

impl FromStr for Version {
    type Err = ReleaseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || ReleaseError::Version(text.to_owned());
        let mut parts = text.strip_prefix('v').unwrap_or(text).split('.');
        let mut next = || -> Result<u64, ReleaseError> {
            let part = parts.next().ok_or_else(invalid)?;
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            part.parse().map_err(|_| invalid())
        };
        let version = Self(next()?, next()?, next()?);
        if parts.next().is_some() {
            return Err(invalid());
        }
        Ok(version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

impl Version {
    #[must_use]
    pub fn current() -> Self {
        env!("CARGO_PKG_VERSION").parse().unwrap_or(Self(0, 0, 0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: Version,
    pub zip: Url,
    pub zip_size: u64,
    pub page: Url,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseError {
    #[error("not a release version: {0}")]
    Version(String),
    #[error("the release has no {0}")]
    MissingAsset(String),
    #[error("unexpected download address {0}")]
    Address(String),
    #[error("unreadable release data: {0}")]
    Json(String),
}

#[derive(Deserialize)]
struct Wire {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<WireAsset>,
}

#[derive(Deserialize)]
struct WireAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

#[must_use]
pub fn zip_name(version: Version) -> String {
    format!("Vaultkeeper-v{version}-arm64.app.zip")
}

/// `None` for a draft or a pre-release (`/releases/latest` excludes both; this is a second
/// guard). Addresses must be https on github.com, where release assets live.
pub fn parse_latest(json: &[u8]) -> Result<Option<Release>, ReleaseError> {
    let wire: Wire =
        serde_json::from_slice(json).map_err(|error| ReleaseError::Json(error.to_string()))?;
    if wire.draft || wire.prerelease {
        return Ok(None);
    }
    let version: Version = wire.tag_name.parse()?;
    let name = zip_name(version);
    let asset = wire
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .ok_or(ReleaseError::MissingAsset(name))?;
    Ok(Some(Release {
        version,
        zip: github_url(&asset.browser_download_url)?,
        zip_size: asset.size,
        page: github_url(&wire.html_url)?,
    }))
}

fn github_url(text: &str) -> Result<Url, ReleaseError> {
    let url = Url::parse(text).map_err(|_| ReleaseError::Address(text.to_owned()))?;
    if url.scheme() != "https" || url.host_str() != Some("github.com") {
        return Err(ReleaseError::Address(text.to_owned()));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(tag: &str, asset: &str, url: &str) -> Vec<u8> {
        serde_json::json!({
            "tag_name": tag,
            "html_url": format!("https://github.com/avbel/vaultkeeper/releases/tag/{tag}"),
            "draft": false,
            "prerelease": false,
            "assets": [
                { "name": "SHA256SUMS", "browser_download_url": "https://github.com/a/b", "size": 1 },
                { "name": asset, "browser_download_url": url, "size": 4096 }
            ]
        })
        .to_string()
        .into_bytes()
    }

    const ZIP_URL: &str = "https://github.com/avbel/vaultkeeper/releases/download/v0.2.0/Vaultkeeper-v0.2.0-arm64.app.zip";

    #[test]
    fn the_running_version_parses() {
        // A pre-release crate version would read as 0.0.0 and let any signed release look newer.
        assert_eq!(Version::current().to_string(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn versions_compare_numerically() {
        let parse = |text: &str| text.parse::<Version>().expect(text);
        assert!(parse("v0.10.0") > parse("0.9.9"));
        assert!(parse("1.0.0") > parse("0.99.99"));
        assert_eq!(parse("v0.1.6"), parse("0.1.6"));
        assert_eq!(parse("0.1.6").to_string(), "0.1.6");
        for bad in [
            "",
            "v1",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1.-2.3",
            "1.2.3-beta",
            "1..3",
        ] {
            assert!(bad.parse::<Version>().is_err(), "{bad}");
        }
    }

    #[test]
    fn picks_the_app_zip_of_the_latest_release() {
        let release = parse_latest(&json("v0.2.0", "Vaultkeeper-v0.2.0-arm64.app.zip", ZIP_URL))
            .expect("parse")
            .expect("a release");
        assert_eq!(release.version, "0.2.0".parse().expect("version"));
        assert_eq!(release.zip.as_str(), ZIP_URL);
        assert_eq!(release.zip_size, 4096);
        assert!(release.page.as_str().ends_with("/releases/tag/v0.2.0"));
    }

    #[test]
    fn rejects_releases_the_updater_cannot_use() {
        assert_eq!(
            parse_latest(&json("v0.2.0", "Vaultkeeper-v0.2.0-arm64.dmg", ZIP_URL)),
            Err(ReleaseError::MissingAsset(
                "Vaultkeeper-v0.2.0-arm64.app.zip".to_owned()
            ))
        );
        assert!(matches!(
            parse_latest(&json("nightly", "x", ZIP_URL)),
            Err(ReleaseError::Version(_))
        ));
        for url in [
            "http://github.com/avbel/vaultkeeper/x.zip",
            "https://evil.example/Vaultkeeper.zip",
        ] {
            assert!(matches!(
                parse_latest(&json("v0.2.0", "Vaultkeeper-v0.2.0-arm64.app.zip", url)),
                Err(ReleaseError::Address(_))
            ));
        }
        let mut pre: serde_json::Value =
            serde_json::from_slice(&json("v0.2.0", "Vaultkeeper-v0.2.0-arm64.app.zip", ZIP_URL))
                .expect("json");
        pre["prerelease"] = true.into();
        assert_eq!(parse_latest(pre.to_string().as_bytes()), Ok(None));
        assert!(matches!(parse_latest(b"{"), Err(ReleaseError::Json(_))));
    }
}
