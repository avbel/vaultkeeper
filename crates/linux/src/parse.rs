//! Parsers for kernel text interfaces, kept apart from the reads so they test on any host.

/// `major.minor` from `uname -r` / `/proc/sys/kernel/osrelease` ("7.3.0-12-generic").
#[must_use]
pub fn kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split(['.', '-']);
    let major = parts.next()?.parse().ok()?;
    let minor: String = parts
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let minor = minor.parse().ok()?;
    Some((major, minor))
}

/// `/sys/kernel/security/lsm` is a comma list ("capability,landlock,lockdown,yama,bpf").
#[must_use]
pub fn lsm_has(list: &str, name: &str) -> bool {
    list.trim().split(',').any(|item| item == name)
}

/// `/proc/sys/kernel/yama/ptrace_scope`: 0 classic, 1 restricted, 2 admin-only, 3 none.
#[must_use]
pub fn yama_scope(text: &str) -> Option<u8> {
    text.trim().parse().ok().filter(|scope| *scope <= 3)
}

/// The `Name: value` field of `/proc/<pid>/status`.
#[must_use]
pub fn status_field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':').map(str::trim))
}

/// `TracerPid` of `/proc/<pid>/status`: 0 when nothing traces the process.
#[must_use]
pub fn tracer_pid(status: &str) -> Option<u32> {
    status_field(status, "TracerPid")?.parse().ok()
}

/// The first non-zero `TracerPid` among the per-thread statuses of `/proc/<pid>/task/*/status`,
/// 0 when no thread is traced. ptrace attaches to single threads, so one traced worker is enough
/// to read the whole address space. `None` when a status has no readable `TracerPid`.
#[must_use]
pub fn any_tracer<'a>(statuses: impl IntoIterator<Item = &'a str>) -> Option<u32> {
    let mut tracer = 0;
    for status in statuses {
        let this = tracer_pid(status)?;
        if tracer == 0 {
            tracer = this;
        }
    }
    Some(tracer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_versions_from_real_release_strings() {
        assert_eq!(kernel_version("7.3.0-12-generic\n"), Some((7, 3)));
        assert_eq!(kernel_version("7.2.15-arch1-1-omarchy"), Some((7, 2)));
        assert_eq!(kernel_version("6.18.4-200.fc45.x86_64"), Some((6, 18)));
        assert_eq!(kernel_version("6.8.0-1017-azure"), Some((6, 8)));
        assert_eq!(kernel_version("7.3rc2"), Some((7, 3)));
        assert_eq!(kernel_version("garbage"), None);
    }

    #[test]
    fn lsm_list_matches_whole_names_only() {
        let list = "capability,landlock,lockdown,yama,integrity,bpf\n";
        assert!(lsm_has(list, "bpf"));
        assert!(lsm_has(list, "landlock"));
        assert!(!lsm_has(list, "selinux"));
        assert!(!lsm_has("bpfx", "bpf"));
    }

    #[test]
    fn yama_scope_rejects_out_of_range() {
        assert_eq!(yama_scope("1\n"), Some(1));
        assert_eq!(yama_scope("0"), Some(0));
        assert_eq!(yama_scope("4"), None);
        assert_eq!(yama_scope(""), None);
    }

    #[test]
    fn status_fields() {
        let status = "Name:\tvaultkeeper\nUmask:\t0077\nPPid:\t1\n";
        assert_eq!(status_field(status, "PPid"), Some("1"));
        assert_eq!(status_field(status, "Umask"), Some("0077"));
        assert_eq!(status_field(status, "Missing"), None);
    }

    #[test]
    fn tracer_pid_from_status() {
        let untraced = "Name:\tvaultkeeper\nState:\tS (sleeping)\nTracerPid:\t0\nUid:\t1000\n";
        assert_eq!(tracer_pid(untraced), Some(0));
        assert_eq!(
            tracer_pid("Name:\tvaultkeeper\nTracerPid:\t4242\n"),
            Some(4242)
        );
        assert_eq!(tracer_pid("Name:\tvaultkeeper\nPPid:\t1\n"), None);
        assert_eq!(tracer_pid("TracerPid:\tgarbage\n"), None);
    }

    #[test]
    fn any_thread_tracer_counts() {
        let main = "Name:\tvaultkeeper\nTracerPid:\t0\n";
        let worker = "Name:\tvaultkeeper-port\nTracerPid:\t31337\n";
        assert_eq!(any_tracer([main, main]), Some(0));
        assert_eq!(any_tracer([main, worker, main]), Some(31337));
        assert_eq!(any_tracer([main, "Name:\tbroken\n"]), None);
        assert_eq!(any_tracer([]), Some(0));
    }
}
