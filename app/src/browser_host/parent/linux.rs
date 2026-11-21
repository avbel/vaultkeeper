//! Gathers the process records the Linux rules judge: each process is pinned with a pidfd
//! before `/proc` is read and checked alive afterwards, so a pid reused in between is noticed.

use vk_ipc::browser::protocol::KnownBrowser;

use super::linux_rules::{ProcessRecord, parse_stat, select_browser};
use crate::cli::HostCaller;

pub fn identify_browser(pid: i32, caller: &HostCaller) -> Option<KnownBrowser> {
    let parent = record(pid)?;
    select_browser(&parent, caller, record)
}

fn record(pid: i32) -> Option<ProcessRecord> {
    let pidfd = vk_ipc::pidfd::open(pid).ok()?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    if vk_ipc::pidfd::exited(&pidfd) {
        return None;
    }
    let (parent_pid, started) = parse_stat(&stat)?;
    Some(ProcessRecord {
        pid,
        parent_pid,
        started,
        exe: exe.to_string_lossy().into_owned(),
    })
}
