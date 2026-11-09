//! Who is on the other end of an accepted socket.
//!
//! On macOS the peer is identified by its audit token (`LOCAL_PEERTOKEN`), which names one
//! process incarnation: unlike a pid, it cannot be recycled by a connect-then-`exec` race. The
//! default verifier then asks the kernel for that process's code object and checks it against a
//! `cdhash` requirement taken from the daemon's own signature, so only the very same signed
//! binary gets in (ad-hoc, linker-signed and certificate-signed builds alike), and only while
//! its signature is still dynamically valid.

use std::{
    io,
    path::{Path, PathBuf},
};

use tokio::net::UnixStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub pid: i32,
    /// Canonicalized path of the peer's executable, for logs; empty when the OS would not say.
    /// Never used to decide: the path can change under a live process.
    pub executable: PathBuf,
    /// The kernel's `audit_token_t` of the peer process (macOS).
    audit_token: Option<[u32; 8]>,
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

/// Accepts peers running the same code as a given binary: by default our own, so only another
/// `bw-lite` process (or, in tests, the test binary itself) gets in.
///
/// macOS compares code signatures (cdhash) through the audit token; other unix targets compare
/// the executable path.
#[derive(Debug, Clone)]
pub struct SameExecutable {
    #[cfg(target_os = "macos")]
    requirement: String,
    #[cfg(not(target_os = "macos"))]
    executable: PathBuf,
}

impl SameExecutable {
    /// The running process's own code. On macOS this is the signature the kernel loaded, so a
    /// binary rebuilt on disk after the daemon started is a different peer.
    pub fn current() -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                requirement: code_identity::own_requirement()?,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::new(&std::env::current_exe()?)
        }
    }

    pub fn new(executable: &Path) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                requirement: code_identity::requirement_of(executable)?,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(Self {
                executable: executable.canonicalize()?,
            })
        }
    }
}

impl PeerVerifier for SameExecutable {
    #[cfg(target_os = "macos")]
    fn verify(&self, peer: &PeerCredentials) -> bool {
        let Some(token) = &peer.audit_token else {
            return false;
        };
        match code_identity::check_guest(token, &self.requirement) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(%error, pid = peer.pid, "IPC peer runs other code");
                false
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn verify(&self, peer: &PeerCredentials) -> bool {
        peer.executable == self.executable
    }
}

pub fn own_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

pub fn credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let (uid, pid, audit_token) = identify(stream)?;
    let executable = executable_of(pid)
        .and_then(|path| path.canonicalize())
        .unwrap_or_default();
    Ok(PeerCredentials {
        uid,
        pid,
        executable,
        audit_token,
    })
}

#[cfg(target_os = "macos")]
fn identify(stream: &UnixStream) -> io::Result<(u32, i32, Option<[u32; 8]>)> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is an open socket borrowed from `stream` for the whole call, and both out
    // pointers point at live, writable locals of the right type.
    if unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut token = [0_u32; 8];
    let mut len = libc::socklen_t::try_from(size_of_val(&token))
        .map_err(|_| io::Error::other("audit_token_t size does not fit socklen_t"))?;
    // SAFETY: `fd` is open (see above); `token` is a writable `audit_token_t`-sized buffer (eight
    // u32) and `len` a live in/out local, as getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN) requires.
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(len).ok() != Some(size_of_val(&token)) {
        return Err(io::Error::other("short audit token"));
    }
    // audit_token_t layout (bsm/libbsm.h, audit_token_to_pid): val[5] is the pid.
    let pid = i32::try_from(token[5]).map_err(|_| io::Error::other("pid out of range"))?;
    Ok((uid, pid, Some(token)))
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
fn identify(stream: &UnixStream) -> io::Result<(u32, i32, Option<[u32; 8]>)> {
    let credentials = stream.peer_cred()?;
    let pid = credentials
        .pid()
        .ok_or_else(|| io::Error::other("the OS does not report the peer pid"))?;
    Ok((credentials.uid(), pid, None))
}

#[cfg(not(target_os = "macos"))]
fn executable_of(pid: i32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

#[cfg(target_os = "macos")]
mod code_identity {
    use std::{ffi::c_void, fmt::Write as _, io, path::Path};

    use core_foundation::{
        base::{CFType, TCFType},
        data::CFData,
        dictionary::{CFDictionary, CFDictionaryRef},
        string::{CFString, CFStringRef},
        url::CFURL,
    };
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
    };

    /// `kSecCSSigningInformation` (SecCode.h); not exported by security-framework-sys.
    const SIGNING_INFORMATION: u32 = 1 << 1;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecCodeInfoUnique: CFStringRef;
        // Takes a SecStaticCodeRef; Apple documents that a SecCodeRef is accepted too.
        fn SecCodeCopySigningInformation(
            code: *const c_void,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> i32;
    }

    fn os_error(what: &str, error: impl std::fmt::Display) -> io::Error {
        io::Error::other(format!("{what}: {error}"))
    }

    pub(super) fn own_requirement() -> io::Result<String> {
        let code =
            SecCode::for_self(Flags::NONE).map_err(|error| os_error("SecCodeCopySelf", error))?;
        requirement_for(code.as_CFTypeRef())
    }

    pub(super) fn requirement_of(executable: &Path) -> io::Result<String> {
        let url = CFURL::from_path(executable, false)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a file path"))?;
        let code = SecStaticCode::from_path(&url, Flags::NONE)
            .map_err(|error| os_error("SecStaticCodeCreateWithPath", error))?;
        requirement_for(code.as_CFTypeRef())
    }

    /// `cdhash H"<hex>"`: matches exactly one build, which is what the UI is (the daemon starts
    /// its own executable). A designated requirement would also admit anything else signed with
    /// the local certificate, whose private key sits in the user's keychain.
    fn requirement_for(code: *const c_void) -> io::Result<String> {
        let mut info: CFDictionaryRef = std::ptr::null();
        // SAFETY: `code` is a live SecCode/SecStaticCode owned by the caller for the whole call;
        // `info` is a writable out pointer that receives a +1 dictionary on success.
        let status =
            unsafe { SecCodeCopySigningInformation(code, SIGNING_INFORMATION, &raw mut info) };
        if status != 0 || info.is_null() {
            return Err(os_error("SecCodeCopySigningInformation", status));
        }
        // SAFETY: `info` is a non-null dictionary returned under the create rule.
        let info: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(info) };
        // SAFETY: a framework constant, valid for the life of the process.
        let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoUnique) };
        let cdhash = info
            .find(&key)
            .and_then(|value| value.downcast::<CFData>())
            .ok_or_else(|| io::Error::other("this executable is not code signed"))?;
        Ok(cdhash_requirement(cdhash.bytes()))
    }

    pub(super) fn cdhash_requirement(cdhash: &[u8]) -> String {
        let mut text = String::with_capacity(10 + cdhash.len() * 2);
        text.push_str("cdhash H\"");
        for byte in cdhash {
            let _ = write!(text, "{byte:02x}");
        }
        text.push('"');
        text
    }

    /// Looks the peer up by audit token (no pid race) and checks that its running code is valid
    /// and is the build `requirement` names.
    pub(super) fn check_guest(token: &[u32; 8], requirement: &str) -> io::Result<()> {
        let bytes: Vec<u8> = token.iter().flat_map(|word| word.to_ne_bytes()).collect();
        let token = CFData::from_buffer(&bytes);
        let mut attributes = GuestAttributes::new();
        attributes.set_audit_token(token.as_concrete_TypeRef());
        let guest = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
            .map_err(|error| os_error("SecCodeCopyGuestWithAttributes", error))?;
        let requirement: SecRequirement = requirement
            .parse()
            .map_err(|error| os_error("SecRequirementCreateWithString", error))?;
        guest
            .check_validity(Flags::NONE, &requirement)
            .map_err(|error| os_error("SecCodeCheckValidity", error))
    }
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
        assert!(
            SameExecutable::new(&exe).expect("verifier").verify(&peer),
            "the binary on disk is the code that runs"
        );
    }

    #[tokio::test]
    async fn same_executable_rejects_other_binaries() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");
        let peer = credentials(&ours).expect("credentials");
        let verifier = SameExecutable::new(Path::new("/bin/sh")).expect("exists");
        assert!(!verifier.verify(&peer));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_process_running_another_binary_is_refused() {
        let dir = tempfile_dir();
        let socket = dir.join("peer.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind");
        // `nc` is a platform binary: same uid, different code.
        let mut nc = std::process::Command::new("/usr/bin/nc")
            .arg("-U")
            .arg(&socket)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("nc");
        let (stream, _) = listener.accept().await.expect("accept");
        let peer = credentials(&stream).expect("credentials");
        assert_eq!(peer.uid, own_uid());
        assert_eq!(peer.pid, i32::try_from(nc.id()).expect("pid fits"));
        assert_eq!(peer.executable, PathBuf::from("/usr/bin/nc"));
        assert!(!SameExecutable::current().expect("verifier").verify(&peer));
        let _ = nc.kill();
        let _ = nc.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bwl-peer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_peer_without_an_audit_token_is_refused() {
        let peer = PeerCredentials {
            uid: own_uid(),
            pid: i32::try_from(std::process::id()).expect("pid fits"),
            executable: std::env::current_exe().expect("exe"),
            audit_token: None,
        };
        assert!(!SameExecutable::current().expect("verifier").verify(&peer));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_requirement_pins_the_cdhash() {
        assert_eq!(
            code_identity::cdhash_requirement(&[0x00, 0xab, 0x10, 0xff]),
            "cdhash H\"00ab10ff\""
        );
    }

    #[test]
    fn closures_are_verifiers() {
        let deny_all = |_: &PeerCredentials| false;
        let peer = PeerCredentials {
            uid: 0,
            pid: 1,
            executable: PathBuf::from("/"),
            audit_token: None,
        };
        assert!(!deny_all.verify(&peer));
    }
}
