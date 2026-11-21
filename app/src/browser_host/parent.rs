#[cfg(any(windows, test))]
mod chain;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", test))]
mod linux_rules;
#[cfg(windows)]
mod windows;

#[cfg(all(unix, not(target_os = "linux")))]
use vk_ipc::browser::protocol::KnownBrowser;
#[cfg(unix)]
use vk_ipc::browser::protocol::ParentInfo;

#[cfg(unix)]
use crate::cli::HostCaller;

#[cfg(unix)]
pub fn identify(caller: &HostCaller) -> ParentInfo {
    let pid = vk_ipc::parent_pid();
    let executable = vk_ipc::process_executable(pid)
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let browser = identify_browser(pid, caller);
    let browser = (pid > 1 && vk_ipc::parent_pid() == pid)
        .then_some(browser)
        .flatten();
    ParentInfo {
        pid,
        executable,
        browser,
    }
}

#[cfg(target_os = "macos")]
const CHROMIUM_REQUIREMENTS: [(KnownBrowser, &str); 2] = [
    (
        KnownBrowser::Chrome,
        "identifier \"com.google.Chrome\" and anchor apple generic and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"",
    ),
    // From Microsoft's published team id; not yet checked against an installed Edge.
    (
        KnownBrowser::Edge,
        "identifier \"com.microsoft.edgemac\" and anchor apple generic and certificate leaf[subject.OU] = \"UBF8T346G9\"",
    ),
];

#[cfg(target_os = "macos")]
const FIREFOX_REQUIREMENT: (KnownBrowser, &str) = (
    KnownBrowser::Firefox,
    "identifier \"org.mozilla.firefox\" and anchor apple generic and certificate leaf[subject.OU] = \"43AQ936H96\"",
);

#[cfg(target_os = "macos")]
fn identify_browser(pid: i32, caller: &HostCaller) -> Option<KnownBrowser> {
    let candidates: &[(KnownBrowser, &str)] = match caller {
        HostCaller::Chromium { .. } => &CHROMIUM_REQUIREMENTS,
        HostCaller::Firefox { .. } => std::slice::from_ref(&FIREFOX_REQUIREMENT),
    };
    candidates
        .iter()
        .find(|(_, requirement)| vk_ipc::check_pid(pid, requirement).is_ok())
        .map(|&(browser, _)| browser)
}

#[cfg(target_os = "linux")]
use linux::identify_browser;

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn identify_browser(_pid: i32, _caller: &HostCaller) -> Option<KnownBrowser> {
    None
}

#[cfg(windows)]
pub use windows::identify;
