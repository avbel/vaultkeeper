//! Which process counts as the browser on Linux (linux-plan.md 5b, chain C12): pure over plain
//! records so the rules are tested on every target; `linux.rs` only gathers the records.

use vk_ipc::browser::protocol::KnownBrowser;

use crate::cli::HostCaller;

/// One process as `/proc` described it while a pidfd held it. `started` is the stat start time
/// in clock ticks; only its order matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    pub pid: i32,
    pub parent_pid: i32,
    pub started: u64,
    /// The resolved path of `/proc/<pid>/exe`.
    pub exe: String,
}

/// Flatpak's portal starts hosts for sandboxed browsers; its parent is checked instead.
const PROXY: &str = "/xdg-native-messaging-proxy";

/// Install paths of the browsers we trust, as distribution packages and the vendors' own
/// repositories lay them out. `*` stands for one snap revision directory.
const FIREFOX: [&str; 3] = [
    "/usr/lib/firefox/firefox",
    "/usr/lib64/firefox/firefox",
    "/snap/firefox/*/usr/lib/firefox/firefox",
];
const CHROMIUM: [(&str, KnownBrowser); 5] = [
    ("/opt/google/chrome/chrome", KnownBrowser::Chrome),
    ("/usr/lib/chromium/chromium", KnownBrowser::Chrome),
    (
        "/usr/lib64/chromium-browser/chromium-browser",
        KnownBrowser::Chrome,
    ),
    ("/opt/brave.com/brave/brave", KnownBrowser::Chrome),
    ("/opt/microsoft/msedge/msedge", KnownBrowser::Edge),
];

/// The browser behind the host's parent, or `None` for an unknown or untrusted chain: a
/// Flatpak browser (its parent is `bwrap`), a proxy whose own parent is no allowlisted browser,
/// or a parent started after its child (a recycled pid).
pub fn select_browser(
    parent: &ProcessRecord,
    caller: &HostCaller,
    find: impl Fn(i32) -> Option<ProcessRecord>,
) -> Option<KnownBrowser> {
    let browser = if parent.exe.ends_with(PROXY) {
        find(parent.parent_pid).filter(|grandparent| grandparent.started <= parent.started)?
    } else {
        parent.clone()
    };
    browser_for_exe(&browser.exe, caller)
}

/// A browser must sit at its vendor's install path and match the kind of caller that started
/// the host, so a Firefox binary cannot vouch for a Chromium origin.
pub fn browser_for_exe(exe: &str, caller: &HostCaller) -> Option<KnownBrowser> {
    match caller {
        HostCaller::Firefox { .. } => FIREFOX
            .iter()
            .any(|pattern| matches(pattern, exe))
            .then_some(KnownBrowser::Firefox),
        HostCaller::Chromium { .. } => CHROMIUM
            .iter()
            .find(|(path, _)| *path == exe)
            .map(|&(_, browser)| browser),
    }
}

/// `*` matches exactly one non-empty path component.
fn matches(pattern: &str, path: &str) -> bool {
    let mut parts = path.split('/');
    pattern.split('/').all(|expected| {
        parts
            .next()
            .is_some_and(|part| part == expected || (expected == "*" && !part.is_empty()))
    }) && parts.next().is_none()
}

/// Parent pid and start time from `/proc/<pid>/stat`. The command name in parentheses may
/// itself contain spaces and `)`, so fields are counted from the last `)`.
pub fn parse_stat(stat: &str) -> Option<(i32, u64)> {
    let fields: Vec<&str> = stat
        .get(stat.rfind(')')? + 1..)?
        .split_whitespace()
        .collect();
    // After the name: state is field 3, ppid 4, starttime 22 (proc_pid_stat(5)).
    let parent_pid = fields.get(1)?.parse().ok()?;
    let started = fields.get(19)?.parse().ok()?;
    Some((parent_pid, started))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pid: i32, parent_pid: i32, started: u64, exe: &str) -> ProcessRecord {
        ProcessRecord {
            pid,
            parent_pid,
            started,
            exe: exe.to_owned(),
        }
    }

    fn firefox() -> HostCaller {
        HostCaller::Firefox {
            extension_id: "vaultkeeper@avbel".to_owned(),
        }
    }

    fn chromium() -> HostCaller {
        HostCaller::Chromium {
            origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop/".to_owned(),
        }
    }

    #[test]
    fn allowlisted_browsers_are_known_only_to_their_own_kind_of_caller() {
        assert_eq!(
            browser_for_exe("/usr/lib/firefox/firefox", &firefox()),
            Some(KnownBrowser::Firefox)
        );
        assert_eq!(
            browser_for_exe("/snap/firefox/6123/usr/lib/firefox/firefox", &firefox()),
            Some(KnownBrowser::Firefox)
        );
        assert_eq!(
            browser_for_exe("/opt/microsoft/msedge/msedge", &chromium()),
            Some(KnownBrowser::Edge)
        );
        assert_eq!(
            browser_for_exe("/usr/lib/firefox/firefox", &chromium()),
            None
        );
        assert_eq!(
            browser_for_exe("/opt/google/chrome/chrome", &firefox()),
            None
        );
    }

    #[test]
    fn lookalike_paths_are_unknown() {
        for exe in [
            "/home/me/usr/lib/firefox/firefox",
            "/snap/firefox/usr/lib/firefox/firefox",
            "/snap/firefox/1/2/usr/lib/firefox/firefox",
            "/usr/lib/firefox/firefox-bin",
            "/usr/bin/bwrap",
        ] {
            assert_eq!(browser_for_exe(exe, &firefox()), None, "{exe}");
        }
    }

    #[test]
    fn the_proxy_vouches_only_through_an_older_allowlisted_parent() {
        let proxy = record(20, 10, 200, "/usr/libexec/xdg-native-messaging-proxy");
        let browser = record(10, 1, 100, "/usr/lib/firefox/firefox");
        let lookup = |found: ProcessRecord| move |pid| (pid == found.pid).then(|| found.clone());
        assert_eq!(
            select_browser(&proxy, &firefox(), lookup(browser.clone())),
            Some(KnownBrowser::Firefox)
        );
        let recycled = ProcessRecord {
            started: 300,
            ..browser
        };
        assert_eq!(select_browser(&proxy, &firefox(), lookup(recycled)), None);
        let flatpak = record(10, 1, 100, "/usr/bin/bwrap");
        assert_eq!(select_browser(&proxy, &firefox(), lookup(flatpak)), None);
        assert_eq!(select_browser(&proxy, &firefox(), |_| None), None);
    }

    #[test]
    fn a_direct_parent_is_judged_by_its_own_path() {
        let chrome = record(10, 1, 100, "/opt/google/chrome/chrome");
        assert_eq!(
            select_browser(&chrome, &chromium(), |_| None),
            Some(KnownBrowser::Chrome)
        );
        let bwrap = record(10, 1, 100, "/usr/bin/bwrap");
        assert_eq!(select_browser(&bwrap, &chromium(), |_| None), None);
    }

    #[test]
    fn stat_fields_are_counted_from_the_last_parenthesis() {
        let stat = "4242 (Web Content) x) S 4100 4242 4242 0 -1 4194560 1 0 0 0 3 1 0 0 20 0 \
                    1 0 987654 1000 10";
        assert_eq!(parse_stat(stat), Some((4100, 987_654)));
        assert_eq!(parse_stat("4242 (cut"), None);
    }
}
