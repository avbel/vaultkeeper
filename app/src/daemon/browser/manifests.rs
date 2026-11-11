//! Native messaging host manifests, one per supported browser.
//!
//! Every function takes the `Application Support` root explicitly so tests can use a temp dir.

use std::{
    fs,
    io::{self, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use serde::Serialize;

use super::ids;

pub const HOST_NAME: &str = "org.vaultkeeper.browser";
pub const MANIFEST_FILE: &str = "org.vaultkeeper.browser.json";
const HOSTS_DIR: &str = "NativeMessagingHosts";
const MANIFEST_MODE: u32 = 0o644;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManifestBrowser {
    Chrome,
    Chromium,
    Brave,
    Edge,
    Firefox,
}

impl ManifestBrowser {
    pub const ALL: [Self; 5] = [
        Self::Chrome,
        Self::Chromium,
        Self::Brave,
        Self::Edge,
        Self::Firefox,
    ];

    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Chromium => "Chromium",
            Self::Brave => "Brave",
            Self::Edge => "Edge",
            Self::Firefox => "Firefox",
        }
    }

    const fn parent_dir(self) -> &'static str {
        match self {
            Self::Chrome => "Google/Chrome",
            Self::Chromium => "Chromium",
            Self::Brave => "BraveSoftware/Brave-Browser",
            Self::Edge => "Microsoft Edge",
            Self::Firefox => "Mozilla",
        }
    }

    #[must_use]
    pub fn dir_under(self, app_support: &Path) -> PathBuf {
        app_support.join(self.parent_dir()).join(HOSTS_DIR)
    }

    #[must_use]
    pub fn manifest_path(self, app_support: &Path) -> PathBuf {
        self.dir_under(app_support).join(MANIFEST_FILE)
    }

    #[must_use]
    pub fn installed(self, app_support: &Path) -> bool {
        app_support.join(self.parent_dir()).is_dir()
    }

    const fn is_firefox(self) -> bool {
        matches!(self, Self::Firefox)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionIds<'a> {
    pub chrome: &'a str,
    pub firefox: &'a str,
}

impl ExtensionIds<'static> {
    pub const DEFAULT: Self = Self {
        chrome: ids::CHROME_EXTENSION_ID,
        firefox: ids::FIREFOX_EXTENSION_ID,
    };
}

impl Default for ExtensionIds<'static> {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Written,
    Unchanged,
    Restored,
    NotInstalled,
}

#[derive(Serialize)]
struct Manifest<'a> {
    name: &'a str,
    description: &'a str,
    r#type: &'a str,
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_origins: Option<[String; 1]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_extensions: Option<[&'a str; 1]>,
}

#[must_use]
pub fn render(browser: ManifestBrowser, exe_path: &Path, ids: &ExtensionIds<'_>) -> Vec<u8> {
    let path = exe_path.to_string_lossy();
    let firefox = browser.is_firefox();
    let manifest = Manifest {
        name: HOST_NAME,
        description: "Vaultkeeper",
        r#type: "stdio",
        path: &path,
        allowed_origins: (!firefox).then(|| [format!("chrome-extension://{}/", ids.chrome)]),
        allowed_extensions: firefox.then_some([ids.firefox]),
    };
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .expect("a manifest of plain strings always serializes");
    bytes.push(b'\n');
    bytes
}

/// The manifest must name the binary that actually runs, so symlinks are resolved.
pub fn current_exe_path() -> io::Result<PathBuf> {
    fs::canonicalize(std::env::current_exe()?)
}

pub fn install(
    app_support: &Path,
    browser: ManifestBrowser,
    exe_path: &Path,
    ids: &ExtensionIds<'_>,
) -> io::Result<Outcome> {
    if !browser.installed(app_support) {
        return Ok(Outcome::NotInstalled);
    }
    let wanted = render(browser, exe_path, ids);
    let dir = browser.dir_under(app_support);
    let target = dir.join(MANIFEST_FILE);
    let outcome = match existing_state(&target, &wanted)? {
        Existing::Matches => return Ok(Outcome::Unchanged),
        Existing::Missing => Outcome::Written,
        Existing::Differs => Outcome::Restored,
    };
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    write_atomic(&dir, &target, &wanted)?;
    Ok(outcome)
}

pub fn remove(app_support: &Path, browser: ManifestBrowser) -> io::Result<()> {
    match fs::remove_file(browser.manifest_path(app_support)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// One browser failing must not stop the others from being checked, so errors are per browser.
#[must_use]
pub fn check_and_restore(
    app_support: &Path,
    enabled: &[ManifestBrowser],
    exe_path: &Path,
    ids: &ExtensionIds<'_>,
) -> Vec<(ManifestBrowser, io::Result<Outcome>)> {
    enabled
        .iter()
        .map(|&browser| (browser, install(app_support, browser, exe_path, ids)))
        .collect()
}

#[must_use]
pub fn restored_toast(browser: ManifestBrowser) -> String {
    format!(
        "The browser connection file for {} was changed and has been restored",
        browser.display_name()
    )
}

enum Existing {
    Missing,
    Matches,
    Differs,
}

/// A symlink never counts as a match: the browser would read whatever it points at.
fn existing_state(target: &Path, wanted: &[u8]) -> io::Result<Existing> {
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Existing::Missing),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Ok(Existing::Differs);
    }
    let current = fs::read(target)?;
    let mode_ok = metadata.permissions().mode() & 0o777 == MANIFEST_MODE;
    Ok(if current == wanted && mode_ok {
        Existing::Matches
    } else {
        Existing::Differs
    })
}

fn write_atomic(dir: &Path, target: &Path, data: &[u8]) -> io::Result<()> {
    let temp = dir.join(format!(
        ".{MANIFEST_FILE}.{}.{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = write_temp(&temp, data).and_then(|()| fs::rename(&temp, target));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn write_temp(temp: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MANIFEST_MODE)
        .open(temp)?;
    file.write_all(data)?;
    // The umask may have stripped bits from the creation mode.
    file.set_permissions(fs::Permissions::from_mode(MANIFEST_MODE))?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    const IDS: ExtensionIds<'static> = ExtensionIds {
        chrome: "abcdefghijklmnopabcdefghijklmnop",
        firefox: "browser-extension@vaultkeeper",
    };
    const EXE: &str = "/Applications/Vaultkeeper.app/Contents/MacOS/vaultkeeper";

    fn exe() -> &'static Path {
        Path::new(EXE)
    }

    fn root_with(browser: ManifestBrowser) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("directory");
        fs::create_dir_all(root.path().join(browser.parent_dir())).expect("browser dir");
        root
    }

    fn read_json(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(path).expect("manifest")).expect("json")
    }

    #[test]
    fn directory_table_matches_the_plan() {
        let root = Path::new("/s");
        let dirs: Vec<_> = ManifestBrowser::ALL
            .iter()
            .map(|browser| browser.dir_under(root))
            .collect();
        assert_eq!(
            dirs,
            [
                "/s/Google/Chrome/NativeMessagingHosts",
                "/s/Chromium/NativeMessagingHosts",
                "/s/BraveSoftware/Brave-Browser/NativeMessagingHosts",
                "/s/Microsoft Edge/NativeMessagingHosts",
                "/s/Mozilla/NativeMessagingHosts",
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn chrome_family_uses_allowed_origins() {
        for browser in [
            ManifestBrowser::Chrome,
            ManifestBrowser::Chromium,
            ManifestBrowser::Brave,
            ManifestBrowser::Edge,
        ] {
            let json: serde_json::Value =
                serde_json::from_slice(&render(browser, exe(), &IDS)).expect("json");
            assert_eq!(
                json,
                serde_json::json!({
                    "name": "org.vaultkeeper.browser",
                    "description": "Vaultkeeper",
                    "type": "stdio",
                    "path": EXE,
                    "allowed_origins": [format!("chrome-extension://{}/", IDS.chrome)],
                })
            );
        }
    }

    #[test]
    fn firefox_uses_allowed_extensions() {
        let json: serde_json::Value =
            serde_json::from_slice(&render(ManifestBrowser::Firefox, exe(), &IDS)).expect("json");
        assert_eq!(
            json,
            serde_json::json!({
                "name": "org.vaultkeeper.browser",
                "description": "Vaultkeeper",
                "type": "stdio",
                "path": EXE,
                "allowed_extensions": ["browser-extension@vaultkeeper"],
            })
        );
    }

    #[test]
    fn render_is_deterministic_with_trailing_newline() {
        let first = render(ManifestBrowser::Chrome, exe(), &IDS);
        assert_eq!(first, render(ManifestBrowser::Chrome, exe(), &IDS));
        assert!(first.ends_with(b"}\n"));
        let text = String::from_utf8(first).expect("utf8");
        assert!(text.starts_with("{\n  \"name\": \"org.vaultkeeper.browser\",\n"));
    }

    #[test]
    fn writes_then_reports_unchanged() {
        let root = root_with(ManifestBrowser::Chrome);
        let first = install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");
        assert_eq!(first, Outcome::Written);
        let again = install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");
        assert_eq!(again, Outcome::Unchanged);
        let path = ManifestBrowser::Chrome.manifest_path(root.path());
        assert_eq!(
            fs::read(path).expect("manifest"),
            render(ManifestBrowser::Chrome, exe(), &IDS)
        );
    }

    #[test]
    fn restores_a_tampered_manifest() {
        let root = root_with(ManifestBrowser::Firefox);
        install(root.path(), ManifestBrowser::Firefox, exe(), &IDS).expect("install");
        let path = ManifestBrowser::Firefox.manifest_path(root.path());
        fs::write(&path, b"{\"path\":\"/tmp/evil\"}").expect("tamper");

        let outcome = install(root.path(), ManifestBrowser::Firefox, exe(), &IDS).expect("install");

        assert_eq!(outcome, Outcome::Restored);
        assert_eq!(
            fs::read(&path).expect("manifest"),
            render(ManifestBrowser::Firefox, exe(), &IDS)
        );
    }

    #[test]
    fn a_changed_exe_path_counts_as_a_difference() {
        let root = root_with(ManifestBrowser::Chrome);
        install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");
        let moved = Path::new("/Users/someone/Vaultkeeper.app/Contents/MacOS/vaultkeeper");
        let outcome = install(root.path(), ManifestBrowser::Chrome, moved, &IDS).expect("install");
        assert_eq!(outcome, Outcome::Restored);
    }

    #[test]
    fn restores_a_manifest_with_loosened_mode() {
        let root = root_with(ManifestBrowser::Chrome);
        install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");
        let path = ManifestBrowser::Chrome.manifest_path(root.path());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("chmod");

        let outcome = install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");

        assert_eq!(outcome, Outcome::Restored);
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn remove_deletes_and_tolerates_absence() {
        let root = root_with(ManifestBrowser::Chrome);
        install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");
        let path = ManifestBrowser::Chrome.manifest_path(root.path());
        remove(root.path(), ManifestBrowser::Chrome).expect("remove");
        assert!(!path.exists());
        remove(root.path(), ManifestBrowser::Chrome).expect("remove again");
        remove(root.path(), ManifestBrowser::Edge).expect("remove for an absent browser");
    }

    #[test]
    fn uninstalled_browser_gets_nothing_created() {
        let root = tempfile::tempdir().expect("directory");
        for browser in ManifestBrowser::ALL {
            assert!(!browser.installed(root.path()));
            let outcome = install(root.path(), browser, exe(), &IDS).expect("install");
            assert_eq!(outcome, Outcome::NotInstalled);
        }
        assert_eq!(fs::read_dir(root.path()).expect("read").count(), 0);
    }

    #[test]
    fn only_the_hosts_directory_is_created() {
        let root = root_with(ManifestBrowser::Chrome);
        install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");
        assert!(ManifestBrowser::Chrome.dir_under(root.path()).is_dir());
        assert!(!root.path().join("Mozilla").exists());
        let leftovers: Vec<_> = fs::read_dir(ManifestBrowser::Chrome.dir_under(root.path()))
            .expect("read")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(leftovers, [MANIFEST_FILE]);
    }

    #[test]
    fn manifest_mode_is_0644() {
        let root = root_with(ManifestBrowser::Chrome);
        install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");
        let path = ManifestBrowser::Chrome.manifest_path(root.path());
        let mode = fs::metadata(path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn a_symlink_at_the_manifest_path_is_replaced_not_followed() {
        let root = root_with(ManifestBrowser::Chrome);
        let dir = ManifestBrowser::Chrome.dir_under(root.path());
        fs::create_dir(&dir).expect("hosts dir");
        let victim = root.path().join("victim.json");
        fs::write(&victim, b"untouched").expect("victim");
        let path = dir.join(MANIFEST_FILE);
        symlink(&victim, &path).expect("symlink");

        let outcome = install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");

        assert_eq!(outcome, Outcome::Restored);
        assert_eq!(fs::read(&victim).expect("victim"), b"untouched");
        assert!(
            !fs::symlink_metadata(&path)
                .expect("metadata")
                .file_type()
                .is_symlink()
        );
        assert_eq!(read_json(&path)["name"], HOST_NAME);
    }

    #[test]
    fn a_symlink_to_identical_content_is_still_replaced() {
        let root = root_with(ManifestBrowser::Chrome);
        let dir = ManifestBrowser::Chrome.dir_under(root.path());
        fs::create_dir(&dir).expect("hosts dir");
        let elsewhere = root.path().join("copy.json");
        fs::write(&elsewhere, render(ManifestBrowser::Chrome, exe(), &IDS)).expect("copy");
        symlink(&elsewhere, dir.join(MANIFEST_FILE)).expect("symlink");

        let outcome = install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");

        assert_eq!(outcome, Outcome::Restored);
    }

    #[test]
    fn check_and_restore_covers_each_enabled_browser() {
        let root = root_with(ManifestBrowser::Chrome);
        fs::create_dir_all(root.path().join("Mozilla")).expect("firefox dir");
        install(root.path(), ManifestBrowser::Chrome, exe(), &IDS).expect("install");
        fs::write(ManifestBrowser::Chrome.manifest_path(root.path()), b"x").expect("tamper");

        let results = check_and_restore(
            root.path(),
            &[
                ManifestBrowser::Chrome,
                ManifestBrowser::Firefox,
                ManifestBrowser::Edge,
            ],
            exe(),
            &IDS,
        );

        let outcomes: Vec<_> = results
            .into_iter()
            .map(|(browser, outcome)| (browser, outcome.expect("outcome")))
            .collect();
        assert_eq!(
            outcomes,
            [
                (ManifestBrowser::Chrome, Outcome::Restored),
                (ManifestBrowser::Firefox, Outcome::Written),
                (ManifestBrowser::Edge, Outcome::NotInstalled),
            ]
        );
    }

    #[test]
    fn toast_text_names_the_browser() {
        assert_eq!(
            restored_toast(ManifestBrowser::Firefox),
            "The browser connection file for Firefox was changed and has been restored"
        );
    }

    #[test]
    fn current_exe_is_absolute_and_canonical() {
        let path = current_exe_path().expect("exe");
        assert!(path.is_absolute());
        assert_eq!(fs::canonicalize(&path).expect("canonical"), path);
    }

    #[test]
    fn default_ids_come_from_the_ids_module() {
        let defaults = ExtensionIds::default();
        assert_eq!(defaults.chrome, ids::CHROME_EXTENSION_ID);
        assert_eq!(defaults.firefox, ids::FIREFOX_EXTENSION_ID);
    }
}
