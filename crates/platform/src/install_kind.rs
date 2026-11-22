//! How this copy of Vaultkeeper was installed (linux-ideas.md §8). A package manager owns the
//! updates of a managed install, so the built-in updater stays off for it. The rules are plain
//! functions over [`Probe`] so they test on any host; [`detect`] feeds them the real files.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

/// Absolute, so a directory early on `$PATH` cannot answer for rpm; without either, the install
/// counts as not rpm-owned.
const RPM_PROGRAMS: [&str; 2] = ["/usr/bin/rpm", "/bin/rpm"];
/// Runs on the daemon's startup path; a normal query takes about 50 ms.
const RPM_TIMEOUT: Duration = Duration::from_secs(2);
const RPM_POLL: Duration = Duration::from_millis(10);

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

/// `rpm -qf`, spawned only when no marker said otherwise.
fn rpm_owns(exe: &Path) -> bool {
    RPM_PROGRAMS
        .iter()
        .map(Path::new)
        .find(|program| program.is_file())
        .is_some_and(|program| owns_with(program, exe, RPM_TIMEOUT))
}

/// Whether `program -qf exe` succeeds within `timeout`; a slow one is killed and reaped.
fn owns_with(program: &Path, exe: &Path, timeout: Duration) -> bool {
    let spawned = Command::new(program)
        .arg("-qf")
        .arg(exe)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            tracing::warn!(%error, "cannot run rpm; treating the install as not rpm-owned");
            return false;
        }
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(RPM_POLL),
            Ok(None) => {
                tracing::warn!(
                    "rpm -qf did not answer in time; treating the install as not rpm-owned"
                );
                break;
            }
            Err(error) => {
                tracing::warn!(%error, "cannot wait for rpm; treating the install as not rpm-owned");
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    false
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

    #[cfg(unix)]
    fn script(dir: &tempfile::TempDir, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = dir.path().join("rpm");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    #[cfg(unix)]
    #[test]
    fn a_hung_rpm_is_killed_on_the_deadline_and_means_not_owned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rpm = script(&dir, "exec sleep 30");
        let started = Instant::now();
        assert!(!owns_with(
            &rpm,
            Path::new("/usr/bin/vk"),
            Duration::from_millis(200)
        ));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    /// `true` and `false` ignore their arguments, and unlike a freshly written script they are
    /// never "text file busy".
    #[cfg(unix)]
    #[test]
    fn rpm_exit_status_decides_ownership() {
        let exe = Path::new("/usr/bin/vk");
        assert!(owns_with(Path::new("/usr/bin/true"), exe, RPM_TIMEOUT));
        assert!(!owns_with(Path::new("/usr/bin/false"), exe, RPM_TIMEOUT));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn other_systems_are_direct() {
        assert_eq!(detect(), InstallKind::Direct);
    }
}
