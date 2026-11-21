//! Probes that ask the running kernel and session. Each one only reads or creates and drops a
//! throwaway object; none changes the calling process, so they can run before hardening.
//! The D-Bus name probes (portal, notifications, tray watcher, logind) arrive with the first
//! D-Bus client in step 3a.

use std::{
    ffi::CString,
    fs,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::{Path, PathBuf},
};

use crate::{ProbeResult, consts, parse};

const TMPFS_MAGIC: i64 = 0x0102_1994;

fn read(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))
}

fn last_error() -> String {
    std::io::Error::last_os_error().to_string()
}

/// Takes ownership of a descriptor a syscall just returned (non-negative, owned by nothing else).
fn owned(fd: libc::c_long) -> Result<OwnedFd, String> {
    let fd = libc::c_int::try_from(fd).map_err(|error| error.to_string())?;
    // SAFETY: the caller passes a fresh descriptor from a successful syscall.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Kernel `major.minor` at least `floor`.
pub fn kernel_at_least(floor: (u32, u32)) -> ProbeResult {
    let release = read("/proc/sys/kernel/osrelease")?;
    let version = parse::kernel_version(&release)
        .ok_or_else(|| format!("unrecognised kernel release {}", release.trim()))?;
    if version >= floor {
        Ok(format!("kernel {}.{}", version.0, version.1))
    } else {
        Err(format!(
            "kernel {}.{} is older than {}.{}",
            version.0, version.1, floor.0, floor.1
        ))
    }
}

pub fn lsm_has(name: &str) -> ProbeResult {
    let list = read("/sys/kernel/security/lsm")?;
    if parse::lsm_has(&list, name) {
        Ok(format!("{name} in the LSM list"))
    } else {
        Err(format!("the LSM list ({}) lacks {name}", list.trim()))
    }
}

pub fn yama_scope() -> Result<u8, String> {
    let text = read("/proc/sys/kernel/yama/ptrace_scope")?;
    parse::yama_scope(&text).ok_or_else(|| format!("unexpected ptrace_scope {}", text.trim()))
}

/// `SO_PEERPIDFD` on a fresh socketpair (kernel 6.5+).
pub fn peer_pidfd() -> ProbeResult {
    let (ours, _theirs) = UnixStream::pair().map_err(|error| error.to_string())?;
    let mut pidfd: libc::c_int = -1;
    let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(4);
    // SAFETY: `pidfd` and `len` are valid for writes of the sizes passed, and the socket fd is
    // open for the call.
    let result = unsafe {
        libc::getsockopt(
            ours.as_raw_fd(),
            libc::SOL_SOCKET,
            consts::SO_PEERPIDFD,
            (&raw mut pidfd).cast(),
            &raw mut len,
        )
    };
    if result != 0 {
        return Err(format!("SO_PEERPIDFD: {}", last_error()));
    }
    // SAFETY: the kernel returned a new pidfd that nothing else owns.
    drop(unsafe { OwnedFd::from_raw_fd(pidfd) });
    Ok("SO_PEERPIDFD".to_owned())
}

/// `PIDFD_GET_INFO` on our own pidfd (kernel 6.13+).
pub fn pidfd_get_info() -> ProbeResult {
    // SAFETY: pidfd_open with our own pid and no flags has no memory preconditions.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if fd < 0 {
        return Err(format!("pidfd_open: {}", last_error()));
    }
    let pidfd = owned(fd)?;
    let mut info = consts::PidfdInfo {
        mask: consts::PIDFD_INFO_CGROUPID,
        ..consts::PidfdInfo::default()
    };
    // SAFETY: `info` is a properly sized, writable `pidfd_info`, matching the request's size.
    let result = unsafe {
        libc::ioctl(
            pidfd.as_raw_fd(),
            consts::PIDFD_GET_INFO as libc::Ioctl,
            &raw mut info,
        )
    };
    if result != 0 {
        return Err(format!("PIDFD_GET_INFO: {}", last_error()));
    }
    Ok(format!("PIDFD_GET_INFO (cgroup {})", info.cgroupid))
}

/// `memfd_secret` create and close (needs `secretmem.enable`, on by default since 6.5).
pub fn memfd_secret() -> ProbeResult {
    // SAFETY: memfd_secret with flags 0 only returns a new fd or an error.
    let fd = unsafe { libc::syscall(consts::SYS_MEMFD_SECRET, 0) };
    if fd < 0 {
        return Err(format!("memfd_secret: {}", last_error()));
    }
    drop(owned(fd)?);
    Ok("memfd_secret".to_owned())
}

/// `mseal` on a private anonymous page that is unmapped never (sealed pages cannot be), so the
/// probe leaks exactly one page per call; it runs once at startup.
pub fn mseal() -> ProbeResult {
    // SAFETY: a fresh anonymous private mapping; no existing memory is touched.
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page == libc::MAP_FAILED {
        return Err(format!("mmap: {}", last_error()));
    }
    // SAFETY: `page` is the mapping created above, owned by this function.
    let result = unsafe { libc::syscall(consts::SYS_MSEAL, page, 4096_usize, 0) };
    if result != 0 {
        let error = last_error();
        // SAFETY: the seal failed, so the mapping can still be removed.
        unsafe { libc::munmap(page, 4096) };
        return Err(format!("mseal: {error}"));
    }
    Ok("mseal".to_owned())
}

/// Whether `PR_GET_MDWE` is understood (6.3+); setting it is hardening's job (1d).
pub fn mdwe_supported() -> ProbeResult {
    // SAFETY: PR_GET_MDWE takes no pointers; unused arguments must be zero.
    let result = unsafe { libc::prctl(consts::PR_GET_MDWE, 0, 0, 0, 0) };
    if result < 0 {
        Err(format!("PR_GET_MDWE: {}", last_error()))
    } else {
        Ok(format!("MDWE (flags {result:#x})"))
    }
}

/// Makes this process non-dumpable: no ptrace attach, no `/proc/<pid>/mem` or `exe` for
/// same-user processes, no core dumps. Not a probe, but it lives with its reader below.
pub fn drop_dumpable() {
    // SAFETY: PR_SET_DUMPABLE takes the value and no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0_u64, 0_u64, 0_u64) } != 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "could not drop dumpable");
    }
}

/// Who traces any thread of this process, 0 for nobody. Clearing dumpable does not detach a
/// tracer that attached before, so hardening checks this right after [`drop_dumpable`].
pub fn tracer_pid() -> Result<u32, String> {
    let tasks = fs::read_dir("/proc/self/task")
        .map_err(|error| format!("cannot list /proc/self/task: {error}"))?;
    let mut statuses = Vec::new();
    for task in tasks {
        let task = task.map_err(|error| format!("cannot list /proc/self/task: {error}"))?;
        match fs::read_to_string(task.path().join("status")) {
            Ok(status) => statuses.push(status),
            // The thread exited between the listing and the read.
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(error) => return Err(format!("cannot read a thread status: {error}")),
        }
    }
    parse::any_tracer(statuses.iter().map(String::as_str))
        .ok_or_else(|| "a thread status has no TracerPid".to_owned())
}

pub fn dumpable() -> Result<bool, String> {
    // SAFETY: PR_GET_DUMPABLE takes no arguments.
    let result = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    if result < 0 {
        Err(format!("PR_GET_DUMPABLE: {}", last_error()))
    } else {
        Ok(result != 0)
    }
}

/// Landlock ABI version, 0 when Landlock is compiled out or disabled.
pub fn landlock_abi() -> Result<u32, String> {
    // SAFETY: the version query passes a null attr with size 0, as the man page requires.
    let abi = unsafe {
        libc::syscall(
            consts::SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<u8>(),
            0_usize,
            consts::LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 {
        Err(format!("Landlock: {}", last_error()))
    } else {
        u32::try_from(abi).map_err(|error| error.to_string())
    }
}

/// `$XDG_RUNTIME_DIR`: set, a directory we own, mode 0700, on tmpfs.
pub fn runtime_dir() -> Result<PathBuf, String> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or("XDG_RUNTIME_DIR is not set")?;
    let meta = fs::symlink_metadata(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(format!(
            "{} is owned by uid {}, not {euid}",
            dir.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o777 != 0o700 {
        return Err(format!(
            "{} has mode {:o}, not 700",
            dir.display(),
            meta.mode() & 0o777
        ));
    }
    if !on_tmpfs(&dir)? {
        return Err(format!("{} is not on tmpfs", dir.display()));
    }
    Ok(dir)
}

fn on_tmpfs(path: &Path) -> Result<bool, String> {
    let c_path =
        CString::new(path.as_os_str().as_encoded_bytes()).map_err(|error| error.to_string())?;
    // SAFETY: zeroed is a valid statfs to be overwritten.
    let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is NUL-terminated and `stats` is writable.
    if unsafe { libc::statfs(c_path.as_ptr(), &raw mut stats) } != 0 {
        return Err(format!("statfs {}: {}", path.display(), last_error()));
    }
    #[allow(clippy::useless_conversion, clippy::unnecessary_cast)] // f_type's width differs by arch
    Ok(i64::from(stats.f_type as i64) == TMPFS_MAGIC)
}

/// A Wayland session we can actually connect to.
pub fn wayland() -> ProbeResult {
    let display = std::env::var_os("WAYLAND_DISPLAY").ok_or("WAYLAND_DISPLAY is not set")?;
    let path = Path::new(&display);
    let socket = if path.is_absolute() {
        path.to_owned()
    } else {
        runtime_dir()?.join(path)
    };
    UnixStream::connect(&socket)
        .map(|_| format!("Wayland ({})", display.to_string_lossy()))
        .map_err(|error| format!("cannot connect to {}: {error}", socket.display()))
}

/// The user's systemd manager runs (its notify socket is in the runtime dir).
pub fn systemd_user_manager() -> ProbeResult {
    let notify = runtime_dir()?.join("systemd/notify");
    if notify.exists() {
        Ok("systemd user manager".to_owned())
    } else {
        Err("no systemd user manager in this session".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Docker and CI kernels differ, so these only require an answer, never a particular one.
    #[test]
    fn kernel_probes_answer_without_panicking() {
        let results = [
            kernel_at_least((6, 5)),
            lsm_has("bpf"),
            peer_pidfd(),
            pidfd_get_info(),
            memfd_secret(),
            mseal(),
            mdwe_supported(),
        ];
        drop(results);
        assert!(kernel_at_least((3, 0)).is_ok());
        assert!(dumpable().is_ok());
        let _ = (landlock_abi(), yama_scope());
    }

    #[test]
    fn peer_pidfd_works_on_the_kernels_we_test_on() {
        assert_eq!(
            peer_pidfd(),
            Ok("SO_PEERPIDFD".to_owned()),
            "kernel 6.5+ expected"
        );
    }

    #[test]
    fn session_probes_report_a_reason_outside_a_desktop() {
        if std::env::var_os("WAYLAND_DISPLAY").is_none() {
            assert!(wayland().is_err_and(|why| why.contains("WAYLAND_DISPLAY")));
        }
        let _ = systemd_user_manager();
    }

    #[test]
    fn runtime_dir_checks_mode_and_owner() {
        if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
            assert_eq!(runtime_dir(), Err("XDG_RUNTIME_DIR is not set".to_owned()));
        }
    }
}
