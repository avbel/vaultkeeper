//! Who is on the other end of an accepted socket.
//!
//! Known limit: the pid is read after `accept`, so a same-uid process could connect and then
//! `exec` the real binary before the check. The 0700 socket directory and the uid check keep
//! every other user out; same-user processes are outside what this check can stop.

use std::{
    io,
    path::{Path, PathBuf},
};

use tokio::net::UnixStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub pid: i32,
    /// Canonicalized path of the peer's executable.
    pub executable: PathBuf,
}

/// Decides whether a connecting process may talk to the daemon. The server already rejects
/// peers running as another uid before asking.
pub trait PeerVerifier: Send + Sync + 'static {
    fn verify(&self, peer: &PeerCredentials) -> bool;
}

impl<F> PeerVerifier for F
where
    F: Fn(&PeerCredentials) -> bool + Send + Sync + 'static,
{
    fn verify(&self, peer: &PeerCredentials) -> bool {
        self(peer)
    }
}

/// Accepts peers whose executable is a given binary: by default our own, so only another
/// `bw-lite` process (or, in tests, the test binary itself) gets in.
#[derive(Debug, Clone)]
pub struct SameExecutable {
    executable: PathBuf,
}

impl SameExecutable {
    pub fn current() -> io::Result<Self> {
        Self::new(&std::env::current_exe()?)
    }

    pub fn new(executable: &Path) -> io::Result<Self> {
        Ok(Self {
            executable: executable.canonicalize()?,
        })
    }
}

impl PeerVerifier for SameExecutable {
    fn verify(&self, peer: &PeerCredentials) -> bool {
        peer.executable == self.executable
    }
}

pub fn own_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

pub fn credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let (uid, pid) = uid_and_pid(stream)?;
    let executable = executable_of(pid)?.canonicalize()?;
    Ok(PeerCredentials {
        uid,
        pid,
        executable,
    })
}

#[cfg(target_os = "macos")]
fn uid_and_pid(stream: &UnixStream) -> io::Result<(u32, i32)> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is an open socket borrowed from `stream` for the whole call, and both out
    // pointers point at live, writable locals of the right type.
    if unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pid: libc::pid_t = 0;
    let mut len = libc::socklen_t::try_from(size_of::<libc::pid_t>())
        .map_err(|_| io::Error::other("pid_t size does not fit socklen_t"))?;
    // SAFETY: `fd` is open (see above); `pid` is writable for `len` bytes and `len` is a live
    // in/out local, as getsockopt(SOL_LOCAL, LOCAL_PEERPID) requires.
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut len,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((uid, pid))
}

#[cfg(target_os = "macos")]
fn executable_of(pid: i32) -> io::Result<PathBuf> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let capacity = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).unwrap_or(4096);
    let mut buffer = vec![0_u8; capacity];
    let size = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    // SAFETY: `buffer` is valid for writes of `size` bytes for the duration of the call.
    let written = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), size) };
    let written = usize::try_from(written)
        .ok()
        .filter(|&len| len > 0)
        .ok_or_else(io::Error::last_os_error)?;
    buffer.truncate(written);
    Ok(PathBuf::from(OsString::from_vec(buffer)))
}

#[cfg(not(target_os = "macos"))]
fn uid_and_pid(stream: &UnixStream) -> io::Result<(u32, i32)> {
    let credentials = stream.peer_cred()?;
    let pid = credentials
        .pid()
        .ok_or_else(|| io::Error::other("the OS does not report the peer pid"))?;
    Ok((credentials.uid(), pid))
}

#[cfg(not(target_os = "macos"))]
fn executable_of(pid: i32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reports_our_own_uid_pid_and_executable_for_a_socket_pair() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");
        let peer = credentials(&ours).expect("credentials");
        assert_eq!(peer.uid, own_uid());
        assert_eq!(
            peer.pid,
            i32::try_from(std::process::id()).expect("pid fits")
        );
        let exe = std::env::current_exe()
            .expect("current exe")
            .canonicalize()
            .expect("canonical");
        assert_eq!(peer.executable, exe);
        assert!(SameExecutable::current().expect("verifier").verify(&peer));
    }

    #[test]
    fn same_executable_rejects_other_binaries() {
        let verifier = SameExecutable::new(Path::new("/bin/sh")).expect("exists");
        let peer = PeerCredentials {
            uid: own_uid(),
            pid: 1,
            executable: std::env::current_exe().expect("exe"),
        };
        assert!(!verifier.verify(&peer));
    }

    #[test]
    fn closures_are_verifiers() {
        let deny_all = |_: &PeerCredentials| false;
        let peer = PeerCredentials {
            uid: 0,
            pid: 1,
            executable: PathBuf::from("/"),
        };
        assert!(!deny_all.verify(&peer));
    }
}
