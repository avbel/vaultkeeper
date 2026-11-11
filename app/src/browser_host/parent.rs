use vk_ipc::browser::protocol::{KnownBrowser, ParentInfo};

use crate::cli::HostCaller;

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
fn identify_browser(pid: i32, caller: &HostCaller) -> Option<KnownBrowser> {
    let (browser, requirement) = match caller {
        HostCaller::Chromium { .. } => (
            KnownBrowser::Chrome,
            "identifier \"com.google.Chrome\" and anchor apple generic and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"",
        ),
        HostCaller::Firefox { .. } => (
            KnownBrowser::Firefox,
            "identifier \"org.mozilla.firefox\" and anchor apple generic and certificate leaf[subject.OU] = \"43AQ936H96\"",
        ),
    };
    vk_ipc::check_pid(pid, requirement).ok().map(|()| browser)
}

#[cfg(not(target_os = "macos"))]
fn identify_browser(_pid: i32, _caller: &HostCaller) -> Option<KnownBrowser> {
    None
}
