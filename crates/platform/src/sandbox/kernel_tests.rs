//! The rule set against the real kernel: each test starts this test binary again as a child that
//! restricts itself, since a Landlock domain can never be left.

use std::{
    ffi::CString,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use super::*;

/// A system binary no production rule lists, when this machine has one that runs.
fn unlisted_tool() -> Option<PathBuf> {
    ["/usr/bin/true", "/bin/true"]
        .map(PathBuf::from)
        .into_iter()
        .find(|tool| runs(&mut Command::new(tool)).is_ok_and(|ran| ran))
}

fn real_loader(binary: &Path) -> Option<PathBuf> {
    interpreter(binary)?.canonicalize().ok()
}

/// Runs only as a process the restricted child below starts (`VK_SANDBOX_INHERITED` names the
/// base dir): it never restricts itself and must still be held by its parent's rules.
#[test]
fn inherited_child() {
    let Some(base) = std::env::var_os("VK_SANDBOX_INHERITED").map(PathBuf::from) else {
        return;
    };
    std::fs::write(base.join("allowed/inherited"), b"a").expect("allowed write");
    assert!(
        refused(&std::fs::write(base.join("denied/inherited"), b"b")),
        "the parent's rules hold in a process it started"
    );
}

/// A rule on a file is a rule on that inode: the granted tool runs, and the file a package
/// manager would rename over it does not. That is why an upgrade needs a restart into a fresh
/// sandbox, and why that restart must not be a child of this process.
fn prove_file_grants(base: &Path, tool: &Path) {
    let granted = runs(&mut Command::new(tool));
    assert!(
        granted.as_ref().is_ok_and(|ran| *ran),
        "the granted file runs: {granted:?}"
    );
    let staged = base.join("allowed/staged");
    std::fs::copy(tool, &staged).expect("stage the upgrade");
    std::fs::rename(&staged, tool).expect("replace the tool");
    let replaced = runs(&mut Command::new(tool));
    assert!(
        refused(&replaced),
        "the new file behind the path: {replaced:?}"
    );
}

/// Runs only as the child of the test below (`VK_SANDBOX_CHILD` names its base dir): it
/// restricts itself, writes where allowed and must be refused next to it. Exit 2 means the
/// kernel has no Landlock.
#[test]
fn sandbox_child() {
    use std::os::unix::net::UnixStream;
    let Some(base) = std::env::var_os("VK_SANDBOX_CHILD").map(PathBuf::from) else {
        return;
    };
    let exe = std::env::current_exe().expect("test binary");
    let tool = unlisted_tool().map(|system| {
        let tool = base.join("allowed/tool");
        std::fs::copy(system, &tool).expect("copy a tool");
        tool
    });
    let exec: Vec<PathBuf> = [Some(exe.clone()), tool.clone()]
        .into_iter()
        .flatten()
        .flat_map(|binary| [real_loader(&binary), Some(binary)])
        .flatten()
        .collect();
    let rules = Rules {
        read: vec![PathBuf::from("/usr"), PathBuf::from("/proc")],
        write: vec![base.join("allowed")],
        exec,
        connect: vec![base.join("sock"), base.join("mixed/granted")],
        devices: vec![PathBuf::from("/dev/null")],
    };
    if restrict(&rules).expect("ruleset") == Enforcement::None {
        std::process::exit(2);
    }
    std::fs::write(base.join("allowed/a"), b"a").expect("allowed write");
    if let Some(tool) = &tool {
        prove_file_grants(&base, tool);
    }
    let inherited = runs(
        Command::new(&exe)
            .args(["--exact", "sandbox::kernel_tests::inherited_child"])
            .env("VK_SANDBOX_INHERITED", &base),
    );
    assert!(
        inherited.as_ref().is_ok_and(|ran| *ran),
        "the started process: {inherited:?}"
    );
    assert!(base.join("allowed/inherited").exists());
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

fn run_child(test: &str, variable: &str, base: &Path) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", test, "--test-threads=1"])
        .env(variable, base)
        .status()
        .expect("child")
}

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
        "sandbox::kernel_tests::sandbox_child",
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
const FOREIGN_SOCKETS: [&str; 7] = [
    "gcr/ssh",
    "keyring/ssh",
    "gnupg/S.gpg-agent",
    "systemd/private",
    "pipewire-0",
    "podman/podman.sock",
    "docker.sock",
];

fn connects(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

/// glibc ships these and nothing in this test binary links them.
const SPARE_LIBRARIES: [&str; 4] = [
    "libBrokenLocale.so.1",
    "libanl.so.1",
    "libutil.so.1",
    "libresolv.so.2",
];

fn dlopens(library: &Path, flags: libc::c_int) -> bool {
    let Ok(name) = CString::new(library.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `name` is a NUL-terminated string that outlives the call; the handle is only
    // compared with null and never closed, so nothing of the library is used.
    !unsafe { libc::dlopen(name.as_ptr(), flags) }.is_null()
}

fn read_write(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
}

fn runs(command: &mut Command) -> std::io::Result<bool> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
}

fn refused(result: &std::io::Result<impl Sized>) -> bool {
    result
        .as_ref()
        .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
}

/// What this machine offers the child to check, found before it restricts itself.
struct Machine {
    exe: PathBuf,
    unlisted: Option<PathBuf>,
    /// Two libraries that are not loaded yet: one to load from the system, one to copy.
    libraries: Vec<PathBuf>,
    /// The GPU nodes this user can open for rendering or mode setting.
    gpu_nodes: Vec<PathBuf>,
}

impl Machine {
    fn find() -> Self {
        let exe = std::env::current_exe().expect("test binary");
        // Fedora keeps libraries in /usr/lib64 whatever directory holds the loader; Debian
        // keeps both in one multiarch directory.
        let loader_dir = interpreter(&exe)
            .and_then(|loader| loader.canonicalize().ok())
            .and_then(|loader| loader.parent().map(Path::to_owned));
        let lib_dirs: Vec<PathBuf> = [PathBuf::from("/usr/lib64"), PathBuf::from("/usr/lib")]
            .into_iter()
            .chain(loader_dir)
            .collect();
        let libraries = SPARE_LIBRARIES
            .iter()
            .filter(|name| !dlopens(Path::new(name), libc::RTLD_NOLOAD | libc::RTLD_LAZY))
            .filter_map(|name| {
                lib_dirs
                    .iter()
                    .map(|dir| dir.join(name))
                    .find(|library| library.is_file())
            })
            .take(2)
            .collect();
        let gpu_nodes = std::fs::read_dir("/dev/dri")
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|node| read_write(node).is_ok())
            .collect();
        Self {
            exe,
            unlisted: unlisted_tool(),
            libraries,
            gpu_nodes,
        }
    }
}

/// Only what the rule set names runs; nothing written by the process does.
fn prove_execution(machine: &Machine, data_dir: &Path, proved: &mut Vec<String>) {
    let again = runs(Command::new(&machine.exe).args(["--exact", "sandbox::no_such_test"]));
    assert!(
        again.as_ref().is_ok_and(|ran| *ran),
        "the binary starts itself: {again:?}"
    );
    proved.push("exec self".to_owned());
    if let Some(unlisted) = &machine.unlisted {
        let ran = runs(&mut Command::new(unlisted));
        assert!(refused(&ran), "{} is refused: {ran:?}", unlisted.display());
        proved.push(format!("refused exec {}", unlisted.display()));
        let written = data_dir.join("written");
        std::fs::copy(unlisted, &written).expect("the data dir takes an executable file");
        let ran = runs(&mut Command::new(&written));
        assert!(refused(&ran), "a written file is refused: {ran:?}");
        proved.push("refused exec of a written file".to_owned());
    }
}

/// Mapping a library is not execution to Landlock: a GPU driver loads from a directory without
/// Execute, and so does a library the process wrote itself.
fn prove_libraries(machine: &Machine, data_dir: &Path, proved: &mut Vec<String>) {
    let [system, copied] = machine.libraries.as_slice() else {
        return;
    };
    assert!(dlopens(system, libc::RTLD_NOW), "{}", system.display());
    proved.push(format!("dlopen {}", system.display()));
    let written = data_dir.join("written.so");
    std::fs::copy(copied, &written).expect("copy a library");
    assert!(dlopens(&written, libc::RTLD_NOW), "{}", written.display());
    proved.push("dlopen of a written library (not an Execute access)".to_owned());
}

/// No GPU node is granted: the software renderer opens none.
fn prove_gpu_nodes(machine: &Machine, proved: &mut Vec<String>) {
    for node in &machine.gpu_nodes {
        let opened = read_write(node);
        assert!(refused(&opened), "{}: {opened:?}", node.display());
        proved.push(format!("refused gpu node {}", node.display()));
    }
}

/// Runs only as the child of the test below (`VK_SANDBOX_SESSION_CHILD` names its base dir):
/// the production rule set over this machine's real session. What worked before the sandbox
/// and is granted must still work; the session's other sockets, other programs and the GPU
/// nodes must not. It leaves a `proved` file listing what the machine let it check.
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
    let creds = crate::creds::Detection::system();
    let tools: Vec<PathBuf> = creds
        .creds()
        .map(|creds| creds.program().to_owned())
        .into_iter()
        .collect();
    let machine = Machine::find();
    let data_dir = base.join("data");
    let rules = rules(&Dirs {
        home: &home,
        data_dir: &data_dir,
        socket_dir: &base.join("socket"),
        log_dir: &base.join("logs"),
        install: &install_paths(&machine.exe, &home).expect("install paths"),
        exec: &exec_paths(&machine.exe, &tools).expect("exec paths"),
        session: &session,
        config_home: &base.join("config"),
        data_home: &base.join("share"),
        cache_home: &base.join("cache"),
    });
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
    prove_execution(&machine, &data_dir, &mut proved);
    prove_libraries(&machine, &data_dir, &mut proved);
    prove_gpu_nodes(&machine, &mut proved);
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
    std::fs::write(data_dir.join("proved"), proved.join("\n")).expect("report");
}

/// `VK_SANDBOX_EXPECT_SESSION=1` (the VM runs) makes an empty proof a failure: a desktop
/// session with systemd-creds, a session bus, a compositor, an SSH agent socket and a GPU.
#[test]
fn the_session_rule_set_keeps_creds_and_the_bus_and_refuses_other_sockets() {
    let base = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(base.path().join("data")).expect("data");
    let status = run_child(
        "sandbox::kernel_tests::session_child",
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
        for expected in [
            "creds",
            "granted",
            "refused /",
            "runtime dir unreadable",
            "exec self",
            "refused exec /",
            "refused exec of a written file",
            "dlopen /",
            "dlopen of a written library",
            "refused gpu node",
        ] {
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
