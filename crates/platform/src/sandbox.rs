//! Landlock self-sandbox of the daemon and, by inheritance, the UI it starts (linux-plan.md 1f,
//! chain C6). The daemon may only read the system and its own install, and write its data,
//! runtime, log, launcher, autostart and manifest directories; another file the user owns, such
//! as `~/.ssh` or a browser profile, is out of reach even if the process were compromised.
//!
//! Off unless `VAULTKEEPER_LANDLOCK=1` until the VM runs confirm that fonts, GPU drivers,
//! portals, the tray and file dialogs work under the rule set: the UI inherits it, and a file
//! chosen in a dialog outside these directories cannot be opened (checklist §2).

use std::path::{Path, PathBuf};

/// Where the rule set allows access. Missing paths are skipped when applied, so one list fits
/// every distribution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
}

/// The directories this user's Vaultkeeper works with.
#[derive(Debug, Clone)]
pub struct Dirs<'a> {
    pub home: &'a Path,
    pub data_dir: &'a Path,
    pub socket_dir: &'a Path,
    pub log_dir: &'a Path,
    /// The install prefix: the binary re-executes itself for the UI and after an update.
    pub install_prefix: &'a Path,
    pub runtime_dir: Option<&'a Path>,
    pub config_home: &'a Path,
    pub data_home: &'a Path,
    pub cache_home: &'a Path,
}

/// Read-only: the system, the install and the session's sockets. Read-write: our own state,
/// the files we keep up to date for the desktop, and caches the GPU and font stacks fill.
#[must_use]
pub fn rules(dirs: &Dirs<'_>) -> Rules {
    let mut read: Vec<PathBuf> = [
        "/usr",
        "/etc",
        "/opt",
        "/proc",
        "/sys",
        "/dev",
        "/var/cache",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    read.push(dirs.install_prefix.to_owned());
    read.push(dirs.data_home.join("fonts"));
    read.push(dirs.home.join(".fonts"));
    if let Some(runtime) = dirs.runtime_dir {
        read.push(runtime.to_owned());
    }
    let config = |relative: &str| dirs.config_home.join(relative);
    let write = vec![
        dirs.data_dir.to_owned(),
        dirs.socket_dir.to_owned(),
        dirs.log_dir.to_owned(),
        config("autostart"),
        config("systemd/user"),
        config("google-chrome/NativeMessagingHosts"),
        config("chromium/NativeMessagingHosts"),
        config("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
        config("microsoft-edge/NativeMessagingHosts"),
        dirs.home.join(".mozilla/native-messaging-hosts"),
        dirs.data_home.join("applications"),
        dirs.data_home.join("icons"),
        dirs.cache_home.to_owned(),
    ];
    Rules { read, write }
}

/// Whether the user turned the sandbox on for this start.
#[must_use]
pub fn requested() -> bool {
    std::env::var_os("VAULTKEEPER_LANDLOCK").is_some_and(|value| value == "1")
}

/// Applies `rules` to this process and every child it starts later. Best effort: a kernel
/// without Landlock, or with an older ABI, enforces what it can; the returned text says what.
#[cfg(target_os = "linux")]
pub fn restrict(rules: &Rules) -> Result<String, landlock::RulesetError> {
    use landlock::{
        ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
        path_beneath_rules,
    };

    let abi = ABI::V10;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        // Abstract sockets and signals reach only processes inside this sandbox (the UI).
        .scope(Scope::AbstractUnixSocket | Scope::Signal)?
        .create()?
        .add_rules(path_beneath_rules(&rules.read, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(&rules.write, AccessFs::from_all(abi)))?
        .restrict_self()?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => "Landlock fully enforced".to_owned(),
        RulesetStatus::PartiallyEnforced => {
            "Landlock partly enforced (older kernel ABI)".to_owned()
        }
        RulesetStatus::NotEnforced => {
            "Landlock not enforced: unavailable on this kernel".to_owned()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> Dirs<'static> {
        Dirs {
            home: Path::new("/home/me"),
            data_dir: Path::new("/home/me/.local/share/vaultkeeper"),
            socket_dir: Path::new("/run/user/1000/vaultkeeper"),
            log_dir: Path::new("/home/me/.local/state/vaultkeeper/logs"),
            install_prefix: Path::new("/home/linuxbrew/.linuxbrew"),
            runtime_dir: Some(Path::new("/run/user/1000")),
            config_home: Path::new("/home/me/.config"),
            data_home: Path::new("/home/me/.local/share"),
            cache_home: Path::new("/home/me/.cache"),
        }
    }

    #[test]
    fn our_state_is_writable_and_the_rest_of_home_is_not_listed() {
        let rules = rules(&dirs());
        for path in [
            "/home/me/.local/share/vaultkeeper",
            "/run/user/1000/vaultkeeper",
            "/home/me/.config/autostart",
            "/home/me/.mozilla/native-messaging-hosts",
        ] {
            assert!(rules.write.contains(&PathBuf::from(path)), "{path}");
        }
        let all = rules.read.iter().chain(&rules.write);
        assert!(
            all.clone().all(|path| path != Path::new("/home/me")),
            "the home directory itself is never granted"
        );
        assert!(all.clone().all(|path| !path.starts_with("/home/me/.ssh")));
        assert!(
            rules
                .read
                .contains(&PathBuf::from("/home/linuxbrew/.linuxbrew"))
        );
    }

    #[test]
    fn no_runtime_dir_means_no_session_sockets() {
        let rules = rules(&Dirs {
            runtime_dir: None,
            ..dirs()
        });
        assert!(!rules.read.contains(&PathBuf::from("/run/user/1000")));
    }

    /// Runs only as the child of the test below (`VK_SANDBOX_CHILD` names its base dir): it
    /// restricts itself, writes where allowed and must be refused next to it. Exit 2 means the
    /// kernel has no Landlock.
    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_child() {
        let Some(base) = std::env::var_os("VK_SANDBOX_CHILD").map(PathBuf::from) else {
            return;
        };
        let rules = Rules {
            read: vec![PathBuf::from("/usr"), PathBuf::from("/proc")],
            write: vec![base.join("allowed")],
        };
        let status = restrict(&rules).expect("ruleset");
        if status.starts_with("Landlock not enforced") {
            std::process::exit(2);
        }
        std::fs::write(base.join("allowed/a"), b"a").expect("allowed write");
        assert!(
            std::fs::write(base.join("denied/b"), b"b").is_err(),
            "sibling write refused"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_restricted_process_writes_its_dir_but_not_a_sibling() {
        let base = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(base.path().join("allowed")).expect("allowed");
        std::fs::create_dir(base.path().join("denied")).expect("denied");
        let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "sandbox::tests::sandbox_child",
                "--test-threads=1",
            ])
            .env("VK_SANDBOX_CHILD", base.path())
            .status()
            .expect("child");
        if vk_linux::probes::landlock_abi().is_ok_and(|abi| abi > 0) {
            assert!(status.success(), "the sandboxed child failed: {status}");
            assert!(base.path().join("allowed/a").exists());
            assert!(!base.path().join("denied/b").exists());
        } else {
            assert_eq!(
                status.code(),
                Some(2),
                "no Landlock, so the child reports it"
            );
        }
    }
}
