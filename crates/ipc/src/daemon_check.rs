//! How a client checks the daemon on Linux (linux-plan.md 2c). The daemon is non-dumpable, so its
//! `/proc/<pid>/exe` is hidden from same-user processes and [`crate::SameExecutable`] cannot be
//! used in this direction. Instead:
//!
//! 1. the socket directory is ours (owner, 0700, not a symlink) and the socket inode in it is a
//!    socket we own, checked through the directory's descriptor;
//! 2. the peer runs as our uid, and its pidfd still names a live process;
//! 3. the cgroup the kernel reports for that pidfd matches the one `/proc/<pid>/cgroup` names, and
//!    its name says whether systemd started Vaultkeeper.
//!
//! Without the BPF socket gate (linux-plan.md 4c) a same-user process could still run its own
//! server in a Vaultkeeper-named unit, so these are mistake guards, and [`Binding`] says so.

use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

use tokio::net::UnixStream;

use crate::pidfd;

const DIR_MODE: u32 = 0o700;
const UNIT_MARK: &str = "io.github.avbel.Vaultkeeper";

/// What the cgroup check could establish about the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// Its cgroup is a Vaultkeeper unit or app scope, bound to the connected process.
    VaultkeeperUnit(String),
    /// Started outside systemd (a terminal, a compositor `exec`): accepted, reported as Reduced.
    Unbound(String),
}

/// Step 1, before connecting: the directory and the socket belong to us.
pub fn check_socket(socket: &Path) -> io::Result<()> {
    let dir_path = socket
        .parent()
        .ok_or_else(|| denied(format!("{} has no directory", socket.display())))?;
    let dir = open_dir(dir_path)?;
    let meta = dir.metadata()?;
    let euid = own_uid();
    if meta.uid() != euid {
        return Err(denied(format!(
            "{} is owned by uid {}, not {euid}",
            dir_path.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o777 != DIR_MODE {
        return Err(denied(format!(
            "{} has mode {:o}, not 700",
            dir_path.display(),
            meta.mode() & 0o777
        )));
    }
    let name = socket
        .file_name()
        .ok_or_else(|| denied(format!("{} has no file name", socket.display())))?;
    let stat = stat_at(&dir, name)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK || stat.st_uid != euid {
        return Err(denied(format!(
            "{} is not a socket owned by this user",
            socket.display()
        )));
    }
    Ok(())
}

/// Steps 2 and 3, after connecting.
pub fn check_peer(stream: &UnixStream) -> io::Result<Binding> {
    let credentials = stream.peer_cred()?;
    if credentials.uid() != own_uid() {
        return Err(denied("the daemon runs as another user".to_owned()));
    }
    let pid = credentials
        .pid()
        .ok_or_else(|| denied("the kernel does not report the daemon's pid".to_owned()))?;
    let pidfd = pidfd::of_peer(stream)?;
    let cgroup_id = pidfd::cgroup_id(&pidfd)?;
    // World-readable even for a non-dumpable task, unlike its exe link.
    let cgroups = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let path = cgroup_path(&cgroups)
        .ok_or_else(|| denied("the daemon has no cgroup v2 path".to_owned()))?;
    let inode = std::fs::metadata(format!("/sys/fs/cgroup{path}"))?.ino();
    if inode != cgroup_id {
        return Err(denied(
            "the daemon's cgroup does not match its process".to_owned(),
        ));
    }
    if pidfd::exited(&pidfd) {
        return Err(denied("the daemon exited during the check".to_owned()));
    }
    Ok(classify(path))
}

/// The cgroup v2 line of `/proc/<pid>/cgroup` (`0::<path>`).
fn cgroup_path(text: &str) -> Option<&str> {
    text.lines().find_map(|line| line.strip_prefix("0::"))
}

/// The unit is the last path segment: `io.github.avbel.Vaultkeeper.service` from our user unit,
/// `app-…io.github.avbel.Vaultkeeper….scope` from a desktop launch on GNOME, KDE or UWSM.
fn classify(path: &str) -> Binding {
    let unit = path.rsplit('/').next().unwrap_or(path);
    let kind = Path::new(unit)
        .extension()
        .and_then(std::ffi::OsStr::to_str);
    let ours = unit.contains(UNIT_MARK) && matches!(kind, Some("service" | "scope"));
    if ours {
        Binding::VaultkeeperUnit(unit.to_owned())
    } else {
        Binding::Unbound(unit.to_owned())
    }
}

fn denied(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn own_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) || path.is_symlink() {
                denied(format!("{} is a symbolic link", path.display()))
            } else {
                error
            }
        })
}

fn stat_at(dir: &File, name: &std::ffi::OsStr) -> io::Result<libc::stat> {
    let name = std::ffi::CString::new(name.as_encoded_bytes()).map_err(io::Error::other)?;
    // SAFETY: zeroed is a valid stat to be overwritten.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is open, `name` is NUL-terminated and `stat` is writable.
    let status = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &raw mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn units_and_scopes_are_classified() {
        assert_eq!(
            classify(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/io.github.avbel.Vaultkeeper.service"
            ),
            Binding::VaultkeeperUnit("io.github.avbel.Vaultkeeper.service".to_owned())
        );
        assert!(matches!(
            classify(
                "/user.slice/user@1000.service/app.slice/app-gnome-io.github.avbel.Vaultkeeper-4242.scope"
            ),
            Binding::VaultkeeperUnit(_)
        ));
        assert!(matches!(
            classify("/user.slice/user@1000.service/app.slice/app-org.kde.konsole-1.scope"),
            Binding::Unbound(_)
        ));
        assert_eq!(
            cgroup_path("0::/user.slice/x.scope\n"),
            Some("/user.slice/x.scope")
        );
        assert_eq!(cgroup_path("12:cpu:/x\n"), None);
    }

    #[tokio::test]
    async fn a_private_directory_with_our_socket_passes() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let socket = dir.path().join("cli.sock");
        let _listener = tokio::net::UnixListener::bind(&socket).expect("bind");
        check_socket(&socket).expect("our socket");
    }

    #[tokio::test]
    async fn a_shared_directory_is_refused_naming_the_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let socket = dir.path().join("cli.sock");
        let _listener = tokio::net::UnixListener::bind(&socket).expect("bind");
        let error = check_socket(&socket).expect_err("0755");
        assert!(error.to_string().contains("mode 755"), "{error}");
    }

    #[test]
    fn a_regular_file_is_not_a_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let socket = dir.path().join("cli.sock");
        std::fs::write(&socket, b"").expect("file");
        assert!(check_socket(&socket).is_err());
    }

    #[test]
    fn a_symlinked_directory_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("real");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let error = check_socket(&link.join("cli.sock")).expect_err("symlink");
        assert!(error.to_string().contains("symbolic link"), "{error}");
    }

    /// The case `SameExecutable` cannot handle and this check exists for: the peer is
    /// non-dumpable, so its `/proc/<pid>/exe` is unreadable. Our own process stands in for the
    /// daemon. The cgroup binding needs PIDFD_GET_INFO (6.13+); older kernels skip.
    #[tokio::test]
    async fn a_non_dumpable_peer_is_accepted_without_reading_its_exe() {
        if vk_linux::probes::pidfd_get_info().is_err() {
            return;
        }
        // SAFETY: PR_SET_DUMPABLE takes the value and no pointers.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0_u64, 0_u64, 0_u64) };
        let (client, _server) = UnixStream::pair().expect("pair");
        let binding = check_peer(&client).expect("our own process");
        assert!(matches!(
            binding,
            Binding::VaultkeeperUnit(_) | Binding::Unbound(_)
        ));
    }
}
