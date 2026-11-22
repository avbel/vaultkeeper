//! What the Settings window says about browser integration, computed in the UI process.

use std::path::Path;

use crate::daemon::browser::manifests::ManifestBrowser;

pub const SIGNED_BUILD_REASON: &str = "Cannot start: needs the signed app build";
pub const UNHARDENED_REASON: &str = "Cannot start: process hardening failed";

/// The browsers that get a per-browser switch. The other manifest targets are out of version 1.
const SWITCHABLE: [ManifestBrowser; 2] = [ManifestBrowser::Chrome, ManifestBrowser::Firefox];

/// Why the browser listener refuses to start in this build; `None` when it may start. The daemon
/// asks the same question, so the Settings line never promises what the daemon will refuse.
#[must_use]
pub fn start_blocker() -> Option<&'static str> {
    let dev_override = cfg!(debug_assertions)
        && std::env::var_os("VAULTKEEPER_DEV_BROWSER").as_deref()
            == Some(std::ffi::OsStr::new("1"));
    let allowed = runtime_hardened() || cfg!(feature = "vw-it") || dev_override;
    // Only macOS ties the gate to a signed build; Windows and Linux check runtime hardening.
    let reason = if cfg!(target_os = "macos") {
        SIGNED_BUILD_REASON
    } else {
        UNHARDENED_REASON
    };
    (!allowed).then_some(reason)
}

// Authenticode is not consulted on Windows: a signature does not stop same-user injection, the
// process DACL does (docs/solutions/windows-support.md §5.1, §5.3).
fn runtime_hardened() -> bool {
    #[cfg(windows)]
    {
        vk_platform::hardening::process_dacl_applied()
    }
    #[cfg(target_os = "linux")]
    {
        vk_platform::hardening::is_hardened()
    }
    #[cfg(target_os = "macos")]
    {
        vk_ipc::has_hardened_runtime()
    }
}

#[must_use]
pub fn state_line(enabled: bool, blocker: Option<&'static str>) -> &'static str {
    match (enabled, blocker) {
        (false, _) => "Off",
        (true, Some(reason)) => reason,
        (true, None) => "On",
    }
}

/// Browsers whose application-support directory exists, detected like the manifest writer does so
/// a visible switch always has a manifest it can install.
#[must_use]
pub fn installed_browsers(app_support: &Path) -> Vec<ManifestBrowser> {
    SWITCHABLE
        .into_iter()
        .filter(|browser| browser.installed(app_support))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_line_names_the_blocker_only_while_enabled() {
        assert_eq!(state_line(false, Some(SIGNED_BUILD_REASON)), "Off");
        assert_eq!(state_line(false, None), "Off");
        assert_eq!(state_line(true, None), "On");
        assert_eq!(
            state_line(true, Some(SIGNED_BUILD_REASON)),
            "Cannot start: needs the signed app build"
        );
    }

    // Windows detects browsers from %APPDATA%/%LOCALAPPDATA%, not from the data dir.
    #[cfg(not(windows))]
    #[test]
    fn only_browsers_with_a_profile_directory_are_listed() {
        let dir = tempfile::tempdir().expect("directory");
        assert_eq!(installed_browsers(dir.path()).len(), 0);
        let create = |browser: ManifestBrowser| {
            std::fs::create_dir_all(browser.profile_dir(dir.path())).expect("browser dir");
        };
        create(ManifestBrowser::Firefox);
        assert_eq!(installed_browsers(dir.path()), [ManifestBrowser::Firefox]);
        create(ManifestBrowser::Chrome);
        create(ManifestBrowser::Chromium);
        assert_eq!(
            installed_browsers(dir.path()),
            [ManifestBrowser::Chrome, ManifestBrowser::Firefox]
        );
    }
}
