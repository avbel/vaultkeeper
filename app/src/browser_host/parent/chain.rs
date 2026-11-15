//! Which process counts as the browser: pure over plain records so the rules are tested on every
//! target; the Windows half only gathers the records.

use vk_ipc::browser::protocol::KnownBrowser;

use crate::cli::HostCaller;

/// Creation time is in FILETIME ticks; only its order matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    pub pid: u32,
    pub parent_pid: u32,
    pub created: u64,
    pub name: String,
}

const SHELL: &str = "cmd.exe";

/// The browser process behind `child`, or `None` when the chain cannot be trusted.
///
/// Chromium starts native hosts through `cmd.exe` unless a policy says otherwise, so exactly one
/// `cmd.exe` is skipped; a second one is not a browser and ends up rejected by the signer check.
/// A parent created after its child is a recycled pid, not the real parent.
pub fn select_parent(
    child: &ProcessRecord,
    find: impl Fn(u32) -> Option<ProcessRecord>,
) -> Option<ProcessRecord> {
    let parent = older_parent(child, &find)?;
    if parent.name.eq_ignore_ascii_case(SHELL) {
        return older_parent(&parent, &find);
    }
    Some(parent)
}

fn older_parent(
    child: &ProcessRecord,
    find: &impl Fn(u32) -> Option<ProcessRecord>,
) -> Option<ProcessRecord> {
    find(child.parent_pid).filter(|parent| parent.created <= child.created)
}

const CHROMIUM_SIGNERS: [&str; 3] = [
    "Google LLC",
    "Microsoft Corporation",
    "Brave Software, Inc.",
];
const FIREFOX_SIGNER: &str = "Mozilla Corporation";

/// A browser must be signed by its vendor and match the kind of caller that started the host, so
/// a Firefox-signed parent cannot vouch for a Chromium origin.
pub fn browser_for_signer(signer: &str, caller: &HostCaller) -> Option<KnownBrowser> {
    match caller {
        HostCaller::Chromium { .. } => CHROMIUM_SIGNERS
            .contains(&signer)
            .then_some(KnownBrowser::Chrome),
        HostCaller::Firefox { .. } => (signer == FIREFOX_SIGNER).then_some(KnownBrowser::Firefox),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn record(pid: u32, parent_pid: u32, created: u64, name: &str) -> ProcessRecord {
        ProcessRecord {
            pid,
            parent_pid,
            created,
            name: name.to_owned(),
        }
    }

    fn table(records: &[ProcessRecord]) -> impl Fn(u32) -> Option<ProcessRecord> {
        let map: HashMap<u32, ProcessRecord> = records.iter().map(|r| (r.pid, r.clone())).collect();
        move |pid| map.get(&pid).cloned()
    }

    #[test]
    fn direct_parent_is_chosen() {
        let host = record(30, 20, 300, "vaultkeeper.exe");
        let browser = record(20, 1, 200, "chrome.exe");
        let found = select_parent(&host, table(std::slice::from_ref(&browser)));
        assert_eq!(found, Some(browser));
    }

    #[test]
    fn one_cmd_is_skipped() {
        let host = record(30, 25, 300, "vaultkeeper.exe");
        let shell = record(25, 20, 250, "CMD.EXE");
        let browser = record(20, 1, 200, "chrome.exe");
        let found = select_parent(&host, table(&[shell, browser.clone()]));
        assert_eq!(found, Some(browser));
    }

    #[test]
    fn a_second_cmd_is_returned_as_is() {
        let host = record(30, 25, 300, "vaultkeeper.exe");
        let shell = record(25, 22, 250, "cmd.exe");
        let outer = record(22, 1, 200, "cmd.exe");
        let found = select_parent(&host, table(&[shell, outer.clone()]));
        assert_eq!(found, Some(outer));
    }

    #[test]
    fn parent_created_after_child_is_rejected() {
        let host = record(30, 20, 300, "vaultkeeper.exe");
        let reused = record(20, 1, 301, "chrome.exe");
        assert_eq!(select_parent(&host, table(&[reused])), None);
    }

    #[test]
    fn grandparent_created_after_cmd_is_rejected() {
        let host = record(30, 25, 300, "vaultkeeper.exe");
        let shell = record(25, 20, 250, "cmd.exe");
        let reused = record(20, 1, 251, "chrome.exe");
        assert_eq!(select_parent(&host, table(&[shell, reused])), None);
    }

    #[test]
    fn missing_parent_gives_none() {
        let host = record(30, 20, 300, "vaultkeeper.exe");
        assert_eq!(select_parent(&host, table(&[])), None);
    }

    #[test]
    fn signer_must_match_caller_kind() {
        let chromium = HostCaller::Chromium {
            origin: "chrome-extension://x/".into(),
        };
        let firefox = HostCaller::Firefox {
            extension_id: "x@y".into(),
        };
        for signer in [
            "Google LLC",
            "Microsoft Corporation",
            "Brave Software, Inc.",
        ] {
            assert_eq!(
                browser_for_signer(signer, &chromium),
                Some(KnownBrowser::Chrome)
            );
            assert_eq!(browser_for_signer(signer, &firefox), None);
        }
        assert_eq!(
            browser_for_signer("Mozilla Corporation", &firefox),
            Some(KnownBrowser::Firefox)
        );
        assert_eq!(browser_for_signer("Mozilla Corporation", &chromium), None);
        assert_eq!(browser_for_signer("Evil Inc.", &chromium), None);
    }
}
