//! Landlock self-sandbox of the daemon and, by inheritance, the UI it starts (linux-plan.md 1f,
//! chain C6). The daemon may only read the system and its own install, write its data, runtime,
//! log, launcher, autostart and manifest directories, connect to the sockets it works with, and
//! execute itself and the one tool it spawns ([`exec_paths`]). Nothing it can write can be
//! executed.
//!
//! What this is worth: a bug that makes the process open, list, run or connect to a path of the
//! attacker's choosing no longer reaches `~/.ssh`, a browser profile, or the SSH and GPG agent
//! sockets of the session, and cannot start a file dropped into the data or cache directory. It
//! is not a boundary against code running inside the process: the session bus stays reachable
//! (systemd's `StartTransientUnit` runs anything outside the sandbox), a library in a writable
//! directory can still be mapped, and the writable autostart and systemd user unit directories
//! give persistence. Closing that needs a bus proxy, which is not built.
//!
//! Off unless `VAULTKEEPER_LANDLOCK=1` until the VM runs confirm that fonts, GPU drivers,
//! portals, the tray and file dialogs work under the rule set: the UI inherits it, and a file
//! chosen in a dialog outside these directories cannot be opened (checklist §2).

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

mod exec;

pub use exec::{exec_paths, interpreter};

/// Where the rule set allows access. Missing paths are skipped when applied, so one list fits
/// every distribution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    pub read: Vec<PathBuf>,
    /// Everything but execution: a file the process wrote must not become a program.
    pub write: Vec<PathBuf>,
    /// Files that may be executed.
    pub exec: Vec<PathBuf>,
    /// Unix sockets that may be connected to, each by its own path, or a directory of them.
    /// Landlock ABI 9+ guards `connect(2)` on a path socket as its own right, which the read set
    /// does not carry; an older kernel does not restrict it, and the rule is dropped there. A
    /// rule on a socket holds for that inode: one recreated later (a restarted service) stays
    /// out of reach until Vaultkeeper restarts. The daemon pins these inodes
    /// (`crate::pins`), detects a recreated socket and triggers the same quiet restart as an
    /// upgrade.
    pub connect: Vec<PathBuf>,
    /// Device nodes opened for writing and driven by ioctl, which the read set refuses.
    pub devices: Vec<PathBuf>,
}

/// The session's sockets as the environment names them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    pub runtime_dir: Option<PathBuf>,
    pub wayland_display: Option<OsString>,
    pub bus_address: Option<String>,
}

impl Session {
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            runtime_dir: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            wayland_display: std::env::var_os("WAYLAND_DISPLAY"),
            bus_address: std::env::var("DBUS_SESSION_BUS_ADDRESS").ok(),
        }
    }

    /// The compositor, the session bus and the accessibility bus. Nothing else in the runtime
    /// directory: the SSH and GPG agents, the systemd user manager and container engines listen
    /// there too.
    #[must_use]
    pub fn sockets(&self) -> Vec<PathBuf> {
        let runtime = self
            .runtime_dir
            .as_deref()
            .filter(|path| path.is_absolute());
        let mut sockets = Vec::new();
        let display = self
            .wayland_display
            .as_deref()
            .map_or(Path::new("wayland-0"), Path::new);
        if display.is_absolute() {
            sockets.push(display.to_owned());
        } else if let Some(runtime) = runtime {
            sockets.push(runtime.join(display));
        }
        match &self.bus_address {
            Some(address) => sockets.extend(bus_paths(address)),
            None => sockets.extend(runtime.map(|runtime| runtime.join("bus"))),
        }
        // Slint's accessibility support talks to the bus AT-SPI keeps in this directory.
        sockets.extend(runtime.map(|runtime| runtime.join("at-spi")));
        sockets
    }
}

/// The `unix:path=` sockets of a D-Bus address list. An abstract socket has no path to grant, and
/// the abstract-socket scope already keeps it out of reach.
fn bus_paths(address: &str) -> Vec<PathBuf> {
    address
        .split(';')
        .filter_map(|entry| entry.strip_prefix("unix:"))
        .flat_map(|options| options.split(','))
        .filter_map(|option| option.strip_prefix("path="))
        .filter_map(unescape)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .collect()
}

/// D-Bus address values escape bytes outside `[-0-9A-Za-z_/.\*]` as `%xx`.
fn unescape(value: &str) -> Option<OsString> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut rest = value.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'%' {
            let hex = std::str::from_utf8(tail.get(..2)?).ok()?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            rest = tail.get(2..)?;
        } else {
            bytes.push(byte);
            rest = tail;
        }
    }
    String::from_utf8(bytes).ok().map(OsString::from)
}

/// The directories this user's Vaultkeeper works with.
#[derive(Debug, Clone)]
pub struct Dirs<'a> {
    pub home: &'a Path,
    pub data_dir: &'a Path,
    pub socket_dir: &'a Path,
    pub log_dir: &'a Path,
    /// From [`install_paths`].
    pub install: &'a [PathBuf],
    /// From [`exec_paths`]: the binary re-executes itself for the UI.
    pub exec: &'a [PathBuf],
    pub session: &'a Session,
    pub config_home: &'a Path,
    pub data_home: &'a Path,
    pub cache_home: &'a Path,
}

/// Sockets outside the session's runtime directory: the system bus (`/var/run` is a link to
/// `/run`), and the service `systemd-creds --user` hands the token to (measured with strace on
/// Fedora 45: its only connect, for encrypt and decrypt alike).
const SYSTEM_SOCKETS: [&str; 2] = ["/run/dbus/system_bus_socket", CREDS_SOCKET];

pub const CREDS_SOCKET: &str = "/run/systemd/io.systemd.Credentials";

/// What a child's discarded output is opened on: without it `systemd-creds` cannot even be
/// spawned. No GPU node is granted because Slint draws with its software renderer; a GPU
/// renderer would need `/dev/dri/renderD*` here (read, write and ioctl) to start.
const NULL_DEVICE: &str = "/dev/null";

/// What of the install the sandbox may read, given the path of the running binary.
/// A prefix of its own (`/usr`, `/opt/vaultkeeper`, Homebrew) is granted whole: under Homebrew
/// `opt/vaultkeeper` resolves to a versioned Cellar directory, and the next upgrade's binary
/// lives in another one. A binary inside the home directory gets its own directory and
/// `share/vaultkeeper` next to it, never a prefix such as `~/.local` or `~/.cargo`, which hold
/// keyrings and tokens; one directly in the home directory gets the file alone.
///
/// `None` when either path is not absolute: no rule can be derived, and the caller must not
/// sandbox with a guess.
#[must_use]
pub fn install_paths(install: &Path, home: &Path) -> Option<Vec<PathBuf>> {
    if !install.is_absolute() || !home.is_absolute() {
        return None;
    }
    let bin_dir = install.parent()?;
    let layout_prefix = bin_dir.parent();
    let text = install.to_string_lossy();
    let homebrew = text
        .split_once("/opt/vaultkeeper/")
        .map(|(prefix, _)| PathBuf::from(prefix))
        .filter(|prefix| prefix.is_absolute());
    let outside_home = |dir: &Path| !home.starts_with(dir) && !dir.starts_with(home);
    if let Some(prefix) = homebrew.as_deref().or(layout_prefix)
        && outside_home(prefix)
    {
        return Some(vec![prefix.to_owned()]);
    }
    if home.starts_with(bin_dir) {
        return Some(vec![install.to_owned()]);
    }
    let mut paths = vec![bin_dir.to_owned()];
    paths.extend(layout_prefix.map(|prefix| prefix.join("share/vaultkeeper")));
    if let Some(prefix) = &homebrew {
        paths.push(prefix.join("Cellar/vaultkeeper"));
    }
    Some(paths)
}

/// Read-only: the system and the install. Read-write: our own state, the files we keep up to
/// date for the desktop, and caches the GPU and font stacks fill. Nothing in the runtime
/// directory is readable but our socket directory: Wayland and D-Bus need only the connect.
/// An executable path inside a writable directory is dropped: what the process can write must
/// never run.
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
    read.extend(dirs.install.iter().cloned());
    read.push(dirs.data_home.join("fonts"));
    read.push(dirs.home.join(".fonts"));
    let mut connect: Vec<PathBuf> = SYSTEM_SOCKETS.iter().map(PathBuf::from).collect();
    connect.extend(dirs.session.sockets());
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
    let exec = dirs
        .exec
        .iter()
        .filter(|path| !write.iter().any(|dir| path.starts_with(dir)))
        .cloned()
        .collect();
    Rules {
        read,
        write,
        exec,
        connect,
        devices: vec![PathBuf::from(NULL_DEVICE)],
    }
}

/// Whether the user turned the sandbox on for this start.
#[must_use]
pub fn requested() -> bool {
    std::env::var_os("VAULTKEEPER_LANDLOCK").is_some_and(|value| value == "1")
}

/// How much of a rule set the kernel took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    Full,
    /// An older kernel ABI: the rights it does not know stay unrestricted.
    Partial,
    /// No Landlock on this kernel.
    None,
}

impl std::fmt::Display for Enforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Full => "Landlock fully enforced",
            Self::Partial => "Landlock partly enforced (older kernel ABI)",
            Self::None => "Landlock not enforced: unavailable on this kernel",
        })
    }
}

/// Applies `rules` to this process and every child it starts later. Best effort: a kernel
/// without Landlock, or with an older ABI, enforces what it can; the result says how much.
#[cfg(target_os = "linux")]
pub fn restrict(rules: &Rules) -> Result<Enforcement, landlock::RulesetError> {
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
        .add_rules(path_beneath_rules(
            &rules.read,
            AccessFs::ReadFile | AccessFs::ReadDir,
        ))?
        .add_rules(path_beneath_rules(
            &rules.write,
            AccessFs::from_all(abi) & !AccessFs::Execute,
        ))?
        // Opening a file for execution asks for both rights.
        .add_rules(path_beneath_rules(
            &rules.exec,
            AccessFs::Execute | AccessFs::ReadFile,
        ))?
        .add_rules(path_beneath_rules(&rules.connect, AccessFs::ResolveUnix))?
        .add_rules(path_beneath_rules(
            &rules.devices,
            AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::WriteFile | AccessFs::IoctlDev,
        ))?
        .restrict_self()?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => Enforcement::Full,
        RulesetStatus::PartiallyEnforced => Enforcement::Partial,
        RulesetStatus::NotEnforced => Enforcement::None,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod kernel_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            runtime_dir: Some(PathBuf::from("/run/user/1000")),
            wayland_display: Some(OsString::from("wayland-1")),
            bus_address: Some("unix:path=/run/user/1000/bus".to_owned()),
        }
    }

    fn dirs<'a>(install: &'a [PathBuf], session: &'a Session) -> Dirs<'a> {
        Dirs {
            home: Path::new("/home/me"),
            data_dir: Path::new("/home/me/.local/share/vaultkeeper"),
            socket_dir: Path::new("/run/user/1000/vaultkeeper"),
            log_dir: Path::new("/home/me/.local/state/vaultkeeper/logs"),
            install,
            exec: &[],
            session,
            config_home: Path::new("/home/me/.config"),
            data_home: Path::new("/home/me/.local/share"),
            cache_home: Path::new("/home/me/.cache"),
        }
    }

    fn paths(list: &[&str]) -> Vec<PathBuf> {
        list.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn our_state_is_writable_and_the_rest_of_home_is_not_listed() {
        let install = paths(&["/home/linuxbrew/.linuxbrew"]);
        let session = session();
        let rules = rules(&dirs(&install, &session));
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
    fn nothing_writable_is_executable_and_no_gpu_node_is_a_device() {
        let session = session();
        let exec = paths(&[
            "/usr/bin/vaultkeeper",
            "/usr/lib64/ld-linux-x86-64.so.2",
            "/home/me/.cache/dropped",
            "/home/me/.local/share/vaultkeeper/update/vaultkeeper",
        ]);
        let rules = rules(&Dirs {
            exec: &exec,
            ..dirs(&[], &session)
        });
        assert_eq!(
            rules.exec,
            paths(&["/usr/bin/vaultkeeper", "/usr/lib64/ld-linux-x86-64.so.2"])
        );
        assert_eq!(rules.devices, paths(&["/dev/null"]));
    }

    // Fixtures are Unix paths; "/run/..." is not absolute on Windows, where the sandbox does not exist.
    #[cfg(unix)]
    #[test]
    fn the_runtime_dir_is_neither_readable_nor_connectable_as_a_whole() {
        let session = session();
        let rules = rules(&dirs(&[], &session));
        let runtime = Path::new("/run/user/1000");
        let granted = rules.read.iter().chain(&rules.write).chain(&rules.connect);
        assert!(granted.clone().all(|path| path != runtime));
        assert!(
            granted
                .clone()
                .all(|path| !runtime.starts_with(path) && path != Path::new("/run")),
            "nor through a parent"
        );
        assert_eq!(
            rules.connect,
            paths(&[
                "/run/dbus/system_bus_socket",
                "/run/systemd/io.systemd.Credentials",
                "/run/user/1000/wayland-1",
                "/run/user/1000/bus",
                "/run/user/1000/at-spi",
            ])
        );
        for agent in [
            "gcr/ssh",
            "keyring/ssh",
            "gnupg/S.gpg-agent",
            "systemd/private",
        ] {
            let socket = runtime.join(agent);
            assert!(
                rules.connect.iter().all(|path| !socket.starts_with(path)),
                "{agent}"
            );
        }
    }

    #[test]
    fn no_runtime_dir_means_no_session_sockets() {
        let session = Session::default();
        let rules = rules(&dirs(&[], &session));
        assert_eq!(rules.connect, paths(&SYSTEM_SOCKETS));
    }

    #[cfg(unix)]
    #[test]
    fn session_sockets_follow_the_environment() {
        let defaults = Session {
            runtime_dir: Some(PathBuf::from("/run/user/7")),
            ..Session::default()
        };
        assert_eq!(
            defaults.sockets(),
            paths(&[
                "/run/user/7/wayland-0",
                "/run/user/7/bus",
                "/run/user/7/at-spi"
            ])
        );
        let custom = Session {
            runtime_dir: Some(PathBuf::from("/run/user/7")),
            wayland_display: Some(OsString::from("/tmp/compositor/wl")),
            bus_address: Some(
                "unix:abstract=/tmp/dbus-x,guid=1;unix:path=/tmp/my%20bus,guid=2;tcp:host=h"
                    .to_owned(),
            ),
        };
        assert_eq!(
            custom.sockets(),
            paths(&["/tmp/compositor/wl", "/tmp/my bus", "/run/user/7/at-spi"])
        );
        let relative = Session {
            runtime_dir: Some(PathBuf::from("run")),
            wayland_display: None,
            bus_address: Some("unix:path=bus;unix:path=/a%zz".to_owned()),
        };
        assert!(relative.sockets().is_empty(), "{:?}", relative.sockets());
    }

    #[cfg(unix)]
    #[test]
    fn an_install_with_its_own_prefix_is_granted_whole() {
        let home = Path::new("/home/me");
        let grant = |install: &str| install_paths(Path::new(install), home);
        assert_eq!(grant("/usr/bin/vaultkeeper"), Some(paths(&["/usr"])));
        assert_eq!(
            grant("/opt/vaultkeeper/bin/vaultkeeper"),
            Some(paths(&["/opt/vaultkeeper"]))
        );
        assert_eq!(
            grant("/home/linuxbrew/.linuxbrew/opt/vaultkeeper/bin/vaultkeeper"),
            Some(paths(&["/home/linuxbrew/.linuxbrew"]))
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_install_inside_home_never_grants_a_shared_prefix() {
        let home = Path::new("/home/me");
        let grant = |install: &str| install_paths(Path::new(install), home);
        assert_eq!(
            grant("/home/me/bin/vaultkeeper"),
            Some(paths(&["/home/me/bin", "/home/me/share/vaultkeeper"]))
        );
        assert_eq!(
            grant("/home/me/.local/bin/vaultkeeper"),
            Some(paths(&[
                "/home/me/.local/bin",
                "/home/me/.local/share/vaultkeeper"
            ]))
        );
        assert_eq!(
            grant("/home/me/.cargo/bin/vaultkeeper"),
            Some(paths(&[
                "/home/me/.cargo/bin",
                "/home/me/.cargo/share/vaultkeeper"
            ]))
        );
        assert_eq!(
            grant("/home/me/opt/vaultkeeper/bin/vaultkeeper"),
            Some(paths(&[
                "/home/me/opt/vaultkeeper/bin",
                "/home/me/opt/vaultkeeper/share/vaultkeeper",
                "/home/me/Cellar/vaultkeeper",
            ]))
        );
        assert_eq!(
            grant("/home/me/vaultkeeper"),
            Some(paths(&["/home/me/vaultkeeper"]))
        );
        assert_eq!(
            grant("/home/vaultkeeper"),
            Some(paths(&["/home/vaultkeeper"]))
        );
        assert_eq!(grant("/vaultkeeper"), Some(paths(&["/vaultkeeper"])));
        assert_eq!(
            grant("/bin/vaultkeeper"),
            Some(paths(&["/bin", "/share/vaultkeeper"]))
        );
    }

    #[test]
    fn an_unknown_install_or_home_gives_no_rule() {
        assert_eq!(install_paths(Path::new(""), Path::new("/home/me")), None);
        assert_eq!(
            install_paths(Path::new("bin/vaultkeeper"), Path::new("/home/me")),
            None
        );
        assert_eq!(
            install_paths(Path::new("/usr/bin/vaultkeeper"), Path::new("")),
            None
        );
    }
}
