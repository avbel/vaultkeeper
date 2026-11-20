//! Which distribution this is, from `/etc/os-release`. Used only to pick the fix text of a failed
//! probe, never to skip one (linux-plan.md conventions).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    Ubuntu,
    Fedora,
    /// Arch with the Omarchy package set, the supported Arch configuration.
    Omarchy,
    OtherArch,
    Other,
}

/// `os_release` is the file's text; `omarchy` says whether the Omarchy marker exists.
#[must_use]
pub fn classify(os_release: &str, omarchy: bool) -> Distro {
    let id = field(os_release, "ID").unwrap_or_default();
    let like = field(os_release, "ID_LIKE").unwrap_or_default();
    let is = |name: &str| id == name || like.split_whitespace().any(|item| item == name);
    if is("arch") {
        if omarchy {
            Distro::Omarchy
        } else {
            Distro::OtherArch
        }
    } else if id == "ubuntu" {
        Distro::Ubuntu
    } else if id == "fedora" {
        Distro::Fedora
    } else {
        Distro::Other
    }
}

/// Reads the real files: `/etc/os-release` (or `/usr/lib/os-release`) and `/usr/share/omarchy`.
#[must_use]
pub fn detect() -> Distro {
    let text = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default();
    classify(&text, std::path::Path::new("/usr/share/omarchy").exists())
}

fn field(os_release: &str, key: &str) -> Option<String> {
    os_release.lines().find_map(|line| {
        let value = line.strip_prefix(key)?.strip_prefix('=')?;
        Some(value.trim().trim_matches(['"', '\'']).to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU: &str = "PRETTY_NAME=\"Ubuntu 26.10\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"26.10\"\nID=ubuntu\nID_LIKE=debian\n";
    const KUBUNTU: &str = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVARIANT=\"Kubuntu\"\n";
    const FEDORA: &str =
        "NAME=\"Fedora Linux\"\nVERSION_ID=45\nID=fedora\nVARIANT_ID=workstation\n";
    const ARCH: &str =
        "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n";

    #[test]
    fn classifies_the_supported_systems() {
        assert_eq!(classify(UBUNTU, false), Distro::Ubuntu);
        assert_eq!(classify(KUBUNTU, false), Distro::Ubuntu);
        assert_eq!(classify(FEDORA, false), Distro::Fedora);
        assert_eq!(classify(ARCH, true), Distro::Omarchy);
        assert_eq!(classify(ARCH, false), Distro::OtherArch);
    }

    #[test]
    fn arch_derivatives_and_unknowns() {
        assert_eq!(
            classify("ID=endeavouros\nID_LIKE=arch\n", false),
            Distro::OtherArch
        );
        assert_eq!(classify("ID=debian\n", false), Distro::Other);
        assert_eq!(classify("", false), Distro::Other);
    }
}
