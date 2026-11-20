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
}
