//! Landlock self-sandbox of the daemon and, by inheritance, the UI it starts (linux-plan.md 1f,
//! chain C6). The daemon may only read the system and its own install, write its data, runtime,
//! log, launcher, autostart and manifest directories, and connect to the sockets it works with.
//!
//! What this is worth: a bug that makes the process open, list or connect to a path of the
//! attacker's choosing no longer reaches `~/.ssh`, a browser profile, or the SSH and GPG agent
//! sockets of the session. It is not a boundary against code running inside the process: the
//! session bus stays reachable (systemd's `StartTransientUnit` runs anything outside the sandbox),
//! `/usr/bin/systemd-run` can be executed, and the writable autostart and systemd user unit
//! directories give persistence. Closing that needs a bus proxy, which is not built.
//!
//! Off unless `VAULTKEEPER_LANDLOCK=1` until the VM runs confirm that fonts, GPU drivers,
//! portals, the tray and file dialogs work under the rule set: the UI inherits it, and a file
//! chosen in a dialog outside these directories cannot be opened (checklist §2).

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

/// Where the rule set allows access. Missing paths are skipped when applied, so one list fits
/// every distribution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    /// Unix sockets that may be connected to, each by its own path, or a directory of them.
    /// Landlock ABI 9+ guards `connect(2)` on a path socket as its own right, which the read set
    /// does not carry; an older kernel does not restrict it, and the rule is dropped there. A
    /// rule on a socket holds for that inode: one recreated later (a restarted service) stays
    /// out of reach until Vaultkeeper restarts.
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
    /// From [`install_paths`]: the binary re-executes itself for the UI and after an update.
    pub install: &'a [PathBuf],
    pub session: &'a Session,
    pub config_home: &'a Path,
    pub data_home: &'a Path,
    pub cache_home: &'a Path,
}

/// Sockets outside the session's runtime directory: the system bus (`/var/run` is a link to
/// `/run`), and the service `systemd-creds --user` hands the token to (measured with strace on
/// Fedora 45: its only connect, for encrypt and decrypt alike).
const SYSTEM_SOCKETS: [&str; 2] = [
    "/run/dbus/system_bus_socket",
    "/run/systemd/io.systemd.Credentials",
];

/// `/dev/null` is what a child's discarded output is opened on (without it `systemd-creds` cannot
/// even be spawned), and the GPU nodes are opened read-write and driven by ioctl.
const DEVICES: [&str; 2] = ["/dev/null", "/dev/dri"];

/// What of the install the sandbox may read and execute, given the path of the running binary.
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
    Rules {
        read,
        write,
        connect,
        devices: DEVICES.iter().map(PathBuf::from).collect(),
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
        .add_rules(path_beneath_rules(&rules.read, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(&rules.write, AccessFs::from_all(abi)))?
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

    /// Runs only as the child of the test below (`VK_SANDBOX_CHILD` names its base dir): it
    /// restricts itself, writes where allowed and must be refused next to it. Exit 2 means the
    /// kernel has no Landlock.
    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_child() {
        use std::os::unix::net::UnixStream;
        let Some(base) = std::env::var_os("VK_SANDBOX_CHILD").map(PathBuf::from) else {
            return;
        };
        let rules = Rules {
            read: vec![PathBuf::from("/usr"), PathBuf::from("/proc")],
            write: vec![base.join("allowed")],
            connect: vec![base.join("sock"), base.join("mixed/granted")],
            devices: Vec::new(),
        };
        if restrict(&rules).expect("ruleset") == Enforcement::None {
            std::process::exit(2);
        }
        std::fs::write(base.join("allowed/a"), b"a").expect("allowed write");
        assert!(
            std::fs::write(base.join("denied/b"), b"b").is_err(),
            "sibling write refused"
        );
        for granted in ["sock/s", "mixed/granted"] {
            let connected = UnixStream::connect(base.join(granted));
            assert!(connected.is_ok(), "{granted}: {connected:?}");
        }
        if vk_linux::probes::landlock_abi().is_ok_and(|abi| abi >= 9) {
            for refused in ["denied/s", "mixed/other"] {
                assert!(
                    UnixStream::connect(base.join(refused)).is_err(),
                    "{refused} is refused"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn run_child(test: &str, variable: &str, base: &Path) -> std::process::ExitStatus {
        std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", test, "--test-threads=1"])
            .env(variable, base)
            .status()
            .expect("child")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_restricted_process_writes_its_dir_but_not_a_sibling() {
        let base = tempfile::tempdir().expect("tempdir");
        for dir in ["allowed", "denied", "sock", "mixed"] {
            std::fs::create_dir(base.path().join(dir)).expect(dir);
        }
        // A rule on one socket must not open its neighbours in the same directory.
        let listeners = ["sock/s", "denied/s", "mixed/granted", "mixed/other"].map(|name| {
            std::os::unix::net::UnixListener::bind(base.path().join(name)).expect("listener")
        });
        let status = run_child(
            "sandbox::tests::sandbox_child",
            "VK_SANDBOX_CHILD",
            base.path(),
        );
        drop(listeners);
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

    /// Sockets of the session that the sandbox must keep out of reach when they exist.
    #[cfg(target_os = "linux")]
    const FOREIGN_SOCKETS: [&str; 7] = [
        "gcr/ssh",
        "keyring/ssh",
        "gnupg/S.gpg-agent",
        "systemd/private",
        "pipewire-0",
        "podman/podman.sock",
        "docker.sock",
    ];

    #[cfg(target_os = "linux")]
    fn connects(path: &Path) -> bool {
        std::os::unix::net::UnixStream::connect(path).is_ok()
    }

    /// Runs only as the child of the test below (`VK_SANDBOX_SESSION_CHILD` names its base dir):
    /// the production rule set over this machine's real session. What worked before the sandbox
    /// and is granted must still work; the session's other sockets must not. It leaves a
    /// `proved` file listing what the machine let it check.
    #[cfg(target_os = "linux")]
    #[test]
    fn session_child() {
        let Some(base) = std::env::var_os("VK_SANDBOX_SESSION_CHILD").map(PathBuf::from) else {
            return;
        };
        let session = Session::from_env();
        let runtime = session.runtime_dir.clone().unwrap_or_default();
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        let rules = rules(&Dirs {
            home: &home,
            data_dir: &base.join("data"),
            socket_dir: &base.join("socket"),
            log_dir: &base.join("logs"),
            install: &[],
            session: &session,
            config_home: &base.join("config"),
            data_home: &base.join("share"),
            cache_home: &base.join("cache"),
        });
        let creds = crate::creds::Detection::system();
        let granted: Vec<PathBuf> = [runtime.join("bus"), runtime.join("wayland-0")]
            .into_iter()
            .filter(|socket| rules.connect.contains(socket) && connects(socket))
            .collect();
        let foreign: Vec<PathBuf> = FOREIGN_SOCKETS
            .iter()
            .map(|name| runtime.join(name))
            .filter(|socket| connects(socket))
            .collect();
        let listed = std::fs::read_dir(&runtime).is_ok();

        if restrict(&rules).expect("ruleset") == Enforcement::None {
            std::process::exit(2);
        }
        let mut proved = Vec::new();
        if let Some(creds) = creds.creds() {
            let blob = creds.encrypt(b"token").expect("systemd-creds encrypts");
            let plain = creds.decrypt(&blob).expect("systemd-creds decrypts");
            assert_eq!(plain.as_slice(), b"token");
            proved.push("creds".to_owned());
        }
        for socket in &granted {
            assert!(connects(socket), "{} stays reachable", socket.display());
            proved.push(format!("granted {}", socket.display()));
        }
        if listed {
            assert!(
                std::fs::read_dir(&runtime).is_err(),
                "the runtime directory is not listed"
            );
            proved.push("runtime dir unreadable".to_owned());
        }
        if vk_linux::probes::landlock_abi().is_ok_and(|abi| abi >= 9) {
            for socket in &foreign {
                let refused = std::os::unix::net::UnixStream::connect(socket)
                    .expect_err("a foreign socket is refused");
                assert_eq!(
                    refused.kind(),
                    std::io::ErrorKind::PermissionDenied,
                    "{}",
                    socket.display()
                );
                proved.push(format!("refused {}", socket.display()));
            }
        }
        std::fs::write(base.join("data/proved"), proved.join("\n")).expect("report");
    }

    /// `VK_SANDBOX_EXPECT_SESSION=1` (the VM runs) makes an empty proof a failure: a desktop
    /// session with systemd-creds, a session bus, a compositor and an SSH agent socket.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_session_rule_set_keeps_creds_and_the_bus_and_refuses_other_sockets() {
        let base = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(base.path().join("data")).expect("data");
        let status = run_child(
            "sandbox::tests::session_child",
            "VK_SANDBOX_SESSION_CHILD",
            base.path(),
        );
        if vk_linux::probes::landlock_abi().is_ok_and(|abi| abi > 0) {
            assert!(status.success(), "the sandboxed child failed: {status}");
        } else {
            assert_eq!(status.code(), Some(2));
            return;
        }
        let proved = std::fs::read_to_string(base.path().join("data/proved")).expect("report");
        if std::env::var_os("VK_SANDBOX_EXPECT_SESSION").is_some_and(|value| value == "1") {
            for expected in ["creds", "granted", "refused", "runtime dir unreadable"] {
                assert!(
                    proved.lines().any(|line| line.starts_with(expected)),
                    "{expected} missing from: {proved}"
                );
            }
            let lines: Vec<&str> = proved.lines().collect();
            assert!(
                lines
                    .iter()
                    .filter(|line| line.starts_with("granted"))
                    .count()
                    == 2,
                "bus and compositor: {proved}"
            );
        }
    }
}
