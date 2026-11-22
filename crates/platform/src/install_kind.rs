//! How this copy of Vaultkeeper was installed (linux-ideas.md §8). A package manager owns the
//! updates of a managed install, so the built-in updater stays off for it. The rules are plain
//! functions over [`Probe`] so they test on any host; [`detect`] feeds them the real files.

use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallKind {
    /// A hand-unpacked tarball, a dev build, or any macOS/Windows install today.
    Direct,
    Homebrew,
    Deb,
    Rpm,
}

impl InstallKind {
    /// The tool that updates a managed install, for "Updates: managed by …".
    #[must_use]
    pub const fn manager(self) -> Option<&'static str> {
        match self {
            Self::Direct => None,
            Self::Homebrew => Some("Homebrew"),
            Self::Deb => Some("apt"),
            Self::Rpm => Some("dnf"),
        }
    }

    /// The command that updates it.
    #[must_use]
    pub const fn upgrade_command(self) -> Option<&'static str> {
        match self {
            Self::Direct => None,
            Self::Homebrew => Some("brew upgrade vaultkeeper"),
            Self::Deb => Some("sudo apt upgrade vaultkeeper"),
            Self::Rpm => Some("sudo dnf upgrade vaultkeeper"),
        }
    }

    /// The word `vaultkeeper --version` prints after `install:`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Homebrew => "homebrew",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
        }
    }

    fn from_marker(text: &str) -> Option<Self> {
        match text.trim() {
            "homebrew" => Some(Self::Homebrew),
            "deb" => Some(Self::Deb),
            "rpm" => Some(Self::Rpm),
            _ => None,
        }
    }

    fn from_label(label: &str) -> Option<Self> {
        match label {
            "direct" => Some(Self::Direct),
            other => Self::from_marker(other),
        }
    }
}

/// What detection looks at, read by [`detect`] or written by a test.
#[derive(Debug, Clone, Default)]
pub struct Probe {
    /// `realpath(/proc/self/exe)`.
    pub exe: PathBuf,
    /// Contents of `<bindir>/../share/vaultkeeper/install-kind`, when present.
    pub marker: Option<String>,
    /// Contents of `/var/lib/dpkg/info/vaultkeeper.list`, when present.
    pub dpkg_list: Option<String>,
    /// Whether an rpm database exists and the exe lives under `/usr/`.
    pub rpm_owned: bool,
}

/// The marker wins; then the Homebrew path shape; then dpkg's file list; then rpm.
#[must_use]
pub fn classify(probe: &Probe) -> InstallKind {
    if let Some(kind) = probe.marker.as_deref().and_then(InstallKind::from_marker) {
        return kind;
    }
    let exe = probe.exe.to_string_lossy();
    if exe.contains("/Cellar/vaultkeeper/") {
        return InstallKind::Homebrew;
    }
    if probe
        .dpkg_list
        .as_deref()
        .is_some_and(|list| list.lines().any(|line| Path::new(line) == probe.exe))
    {
        return InstallKind::Deb;
    }
    if probe.rpm_owned {
        return InstallKind::Rpm;
    }
    InstallKind::Direct
}

/// The path launchers and autostart entries should run: for Homebrew the `opt` symlink, which
/// survives upgrades (`<prefix>/Cellar/vaultkeeper/<version>/bin/x` → `<prefix>/opt/vaultkeeper/bin/x`),
/// otherwise `exe` itself.
#[must_use]
pub fn stable_path(exe: &Path) -> PathBuf {
    let text = exe.to_string_lossy();
    let Some((prefix, rest)) = text.split_once("/Cellar/vaultkeeper/") else {
        return exe.to_owned();
    };
    match rest.split_once('/') {
        Some((_version, inner)) => PathBuf::from(format!("{prefix}/opt/vaultkeeper/{inner}")),
        None => exe.to_owned(),
    }
}

/// The stable install path of this running copy.
#[must_use]
pub fn current_install_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    Some(stable_path(&exe))
}

/// The kind of this running copy. Only Linux has managed installs so far.
#[must_use]
pub fn detect() -> InstallKind {
    if cfg!(target_os = "linux") {
        classify(&probe_files())
    } else {
        InstallKind::Direct
    }
}

/// How the daemon tells the UI it starts what it found.
pub const KIND_ENV: &str = "VAULTKEEPER_INSTALL_KIND";

static KIND: OnceLock<InstallKind> = OnceLock::new();

/// [`detect`], once per process. The daemon asks before it sandboxes itself: detection may run
/// `rpm`, which the sandbox does not let it execute.
#[must_use]
pub fn cached() -> InstallKind {
    *KIND.get_or_init(detect)
}

/// For the UI process, which inherits the daemon's sandbox and so cannot run `rpm` itself:
/// takes the kind the daemon put into [`KIND_ENV`]. Without a valid value the UI detects.
pub fn adopt_from_env() {
    let kind = std::env::var(KIND_ENV)
        .ok()
        .as_deref()
        .and_then(InstallKind::from_label);
    if let Some(kind) = kind {
        // A value set earlier in this process stays: both came from the same daemon.
        let _ = KIND.set(kind);
    }
}

fn probe_files() -> Probe {
    let exe = std::fs::canonicalize("/proc/self/exe").unwrap_or_default();
    let marker = exe
        .parent()
        .and_then(Path::parent)
        .map(|prefix| prefix.join("share/vaultkeeper/install-kind"))
        .and_then(|path| std::fs::read_to_string(path).ok());
    let rpm_db = ["/usr/lib/sysimage/rpm", "/var/lib/rpm"]
        .iter()
        .any(|dir| Path::new(dir).exists());
    Probe {
        rpm_owned: rpm_db && exe.starts_with("/usr/") && rpm_owns(&exe),
        dpkg_list: std::fs::read_to_string("/var/lib/dpkg/info/vaultkeeper.list").ok(),
        marker,
        exe,
    }
}

/// `rpm -qf`, spawned only when no marker said otherwise (about 50 ms).
fn rpm_owns(exe: &Path) -> bool {
    std::process::Command::new("rpm")
        .arg("-qf")
        .arg(exe)
        .output()
        .is_ok_and(|output| output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exe(path: &str) -> Probe {
        Probe {
            exe: PathBuf::from(path),
            ..Probe::default()
        }
    }

    #[test]
    fn the_marker_decides_first() {
        let probe = Probe {
            marker: Some("deb\n".to_owned()),
            ..exe("/home/linuxbrew/.linuxbrew/Cellar/vaultkeeper/0.2.0/bin/vaultkeeper")
        };
        assert_eq!(classify(&probe), InstallKind::Deb);
    }

    #[test]
    fn an_unknown_marker_falls_through_to_the_path() {
        let probe = Probe {
            marker: Some("snap".to_owned()),
            ..exe("/home/linuxbrew/.linuxbrew/Cellar/vaultkeeper/0.2.0/bin/vaultkeeper")
        };
        assert_eq!(classify(&probe), InstallKind::Homebrew);
    }

    #[test]
    fn dpkg_lists_must_name_this_binary() {
        let listed = Probe {
            dpkg_list: Some("/usr\n/usr/bin\n/usr/bin/vaultkeeper\n".to_owned()),
            ..exe("/usr/bin/vaultkeeper")
        };
        assert_eq!(classify(&listed), InstallKind::Deb);
        let elsewhere = Probe {
            dpkg_list: listed.dpkg_list.clone(),
            ..exe("/opt/vk/bin/vaultkeeper")
        };
        assert_eq!(classify(&elsewhere), InstallKind::Direct);
    }

    #[test]
    fn rpm_and_direct() {
        let rpm = Probe {
            rpm_owned: true,
            ..exe("/usr/bin/vaultkeeper")
        };
        assert_eq!(classify(&rpm), InstallKind::Rpm);
        assert_eq!(
            classify(&exe("/home/me/vaultkeeper/vaultkeeper")),
            InstallKind::Direct
        );
    }

    #[test]
    fn cellar_paths_map_to_the_opt_symlink() {
        assert_eq!(
            stable_path(Path::new(
                "/home/linuxbrew/.linuxbrew/Cellar/vaultkeeper/0.2.0/bin/vaultkeeper"
            )),
            Path::new("/home/linuxbrew/.linuxbrew/opt/vaultkeeper/bin/vaultkeeper")
        );
        assert_eq!(
            stable_path(Path::new("/usr/bin/vaultkeeper")),
            Path::new("/usr/bin/vaultkeeper")
        );
    }

    #[test]
    fn managers_and_commands() {
        assert_eq!(InstallKind::Homebrew.manager(), Some("Homebrew"));
        assert_eq!(InstallKind::Direct.upgrade_command(), None);
        assert_eq!(InstallKind::Rpm.label(), "rpm");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn other_systems_are_direct() {
        assert_eq!(detect(), InstallKind::Direct);
    }
}
