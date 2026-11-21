//! Who is on the other end of an accepted socket.
//!
//! On macOS the peer is identified by its audit token (`LOCAL_PEERTOKEN`), which names one
//! process incarnation: unlike a pid, it cannot be recycled by a connect-then-`exec` race. The
//! default verifier then asks the kernel for that process's code object and checks it against a
//! `cdhash` requirement taken from the daemon's own signature, so only the very same signed
//! binary gets in (ad-hoc, linker-signed and certificate-signed builds alike), and only while
//! its signature is still dynamically valid.
//!
//! On Linux the peer's executable is identified by the device and inode of `/proc/<pid>/exe`,
//! read while a pidfd from `SO_PEERPIDFD` pins the connecting process: if it exited and its pid
//! was reused before the read, the pidfd reports the exit and the identity is dropped
//! (linux-plan.md 2c). The path never admits a peer: identity alone does, so a Homebrew Cellar path
//! change does not matter and a copy elsewhere does not get in. The one use of the path is
//! [`Verdict::DaemonOutdated`], where it must match the install path in addition to the file's
//! current on-disk identity.

use std::{
    io,
    path::{Path, PathBuf},
};

#[cfg(all(test, unix))]
use tokio::net::UnixStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub pid: i32,
    /// Canonicalized path of the peer's executable, for logs; empty when the OS would not say.
    /// A necessary but never sufficient condition: it only qualifies a peer for
    /// [`Verdict::DaemonOutdated`], together with the install path's on-disk identity, because the
    /// path can change under a live process.
    pub executable: PathBuf,
    /// The kernel's `audit_token_t` of the peer process (macOS).
    pub(crate) audit_token: Option<[u32; 8]>,
    /// The console/RDP session the peer runs in (Windows); a peer from another session of the
    /// same user is refused.
    #[cfg(windows)]
    pub session_id: u32,
    /// The peer's executable file, read while the peer was known to be alive (Linux).
    #[cfg(target_os = "linux")]
    pub(crate) exe_identity: Option<FileIdentity>,
}

/// One file on one filesystem: what `stat` reports as `st_dev` and `st_ino`.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

#[cfg(target_os = "linux")]
impl FileIdentity {
    pub(crate) fn of(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
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
/// `vaultkeeper` process (or, in tests, the test binary itself) gets in.
///
/// macOS compares code signatures (cdhash) through the audit token, Windows and Linux compare the
/// executable's file identity, and other unix targets compare the executable path.
#[derive(Debug, Clone)]
pub struct SameExecutable {
    #[cfg(target_os = "macos")]
    requirement: String,
    #[cfg(windows)]
    identity: vk_win::ImageIdentity,
    #[cfg(target_os = "linux")]
    identity: FileIdentity,
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
    executable: PathBuf,
}

impl SameExecutable {
    /// The running process's own code. On macOS this is the signature the kernel loaded, so a
    /// binary rebuilt on disk after the daemon started is a different peer; on Windows the cached
    /// identity of the running image, so renaming it aside does not change who we are.
    pub fn current() -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                requirement: code_identity::own_requirement()?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                identity: vk_win::ImageIdentity::of_current_exe()?,
            })
        }
        // `/proc/self/exe` resolves to the image the kernel loaded, even after an upgrade
        // replaced or deleted the file at the install path.
        #[cfg(target_os = "linux")]
        {
            Self::new(Path::new("/proc/self/exe"))
        }
        #[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
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
        #[cfg(windows)]
        {
            Ok(Self {
                identity: vk_win::ImageIdentity::of_path(executable)?,
            })
        }
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                identity: FileIdentity::of(executable)?,
            })
        }
        #[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
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

    #[cfg(windows)]
    fn verify(&self, peer: &PeerCredentials) -> bool {
        let Ok(pid) = u32::try_from(peer.pid) else {
            return false;
        };
        let Ok(own_session) = vk_win::current_session_id() else {
            tracing::warn!("cannot read our own session");
            return false;
        };
        if peer.session_id != own_session {
            tracing::warn!(
                session = peer.session_id,
                pid = peer.pid,
                "IPC peer runs in another session"
            );
            return false;
        }
        match vk_win::ImageIdentity::of_pid(pid) {
            Ok(identity) => identity == self.identity,
            Err(error) => {
                tracing::warn!(%error, pid = peer.pid, "cannot identify the IPC peer");
                false
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn verify(&self, peer: &PeerCredentials) -> bool {
        peer.exe_identity == Some(self.identity)
    }

    #[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
    fn verify(&self, peer: &PeerCredentials) -> bool {
        peer.executable == self.executable
    }
}

/// How the CLI socket treats a connecting peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accepted,
    /// The peer is the binary now installed at the daemon's install path while this daemon still
    /// runs the one it replaced (Linux): it may be told to restart the daemon, nothing else.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "decided on Linux only")
    )]
    DaemonOutdated,
    Rejected,
}

/// The file now behind the daemon's install path.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Installed {
    path: PathBuf,
    identity: FileIdentity,
}

#[cfg(target_os = "linux")]
impl Installed {
    pub(crate) fn read(install: &Path) -> Option<Self> {
        let path = install.canonicalize().ok()?;
        let identity = FileIdentity::of(&path).ok()?;
        Some(Self { path, identity })
    }
}

/// An attacker binary elsewhere gets `Rejected`: only the identity of the very file at the
/// install path, read from disk now, earns `DaemonOutdated`. Whoever can replace that file already
/// has this user's write access to the install, which this check does not claim to stop.
#[cfg(target_os = "linux")]
pub(crate) fn decide(
    own: FileIdentity,
    peer: &PeerCredentials,
    installed: impl FnOnce() -> Option<Installed>,
) -> Verdict {
    let Some(peer_identity) = peer.exe_identity else {
        return Verdict::Rejected;
    };
    if peer_identity == own {
        return Verdict::Accepted;
    }
    match installed() {
        Some(installed)
            if installed.identity == peer_identity && installed.path == peer.executable =>
        {
            Verdict::DaemonOutdated
        }
        _ => Verdict::Rejected,
    }
}

impl SameExecutable {
    pub(crate) fn verdict(&self, peer: &PeerCredentials, install: Option<&Path>) -> Verdict {
        #[cfg(target_os = "linux")]
        {
            decide(self.identity, peer, || install.and_then(Installed::read))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = install;
            if self.verify(peer) {
                Verdict::Accepted
            } else {
                Verdict::Rejected
            }
        }
    }
}

/// Checks a running process against a macOS code-signing requirement.
#[cfg(target_os = "macos")]
pub fn check_pid(pid: i32, requirement: &str) -> io::Result<()> {
    code_identity::check_pid(pid, requirement)
}

/// Whether this process is signed with the macOS hardened runtime.
#[must_use]
pub fn has_hardened_runtime() -> bool {
    #[cfg(target_os = "macos")]
    {
        code_identity::has_hardened_runtime()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// The caller's current parent PID.
#[cfg(unix)]
#[must_use]
pub fn parent_pid() -> i32 {
    // SAFETY: getppid has no preconditions.
    unsafe { libc::getppid() }
}

/// Returns the executable path for diagnostics, not identity verification.
#[cfg(unix)]
pub fn process_executable(pid: i32) -> io::Result<PathBuf> {
    executable_of(pid)
}

#[cfg(unix)]
pub fn own_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "macos")]
pub(crate) fn executable_of(pid: i32) -> io::Result<PathBuf> {
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

#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn executable_of(pid: i32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

#[cfg(target_os = "macos")]
mod code_identity {
    use std::{ffi::c_void, fmt::Write as _, io, path::Path};

    use core_foundation::{
        base::{CFType, TCFType},
        data::CFData,
        dictionary::{CFDictionary, CFDictionaryRef},
        number::CFNumber,
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
        static kSecCodeInfoFlags: CFStringRef;
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

    pub(super) fn has_hardened_runtime() -> bool {
        const CS_RUNTIME: i64 = 0x1_0000;
        let Ok(code) = SecCode::for_self(Flags::NONE) else {
            return false;
        };
        let mut info: CFDictionaryRef = std::ptr::null();
        // SAFETY: code is live and info is a writable out pointer for the returned dictionary.
        let status = unsafe {
            SecCodeCopySigningInformation(code.as_CFTypeRef(), SIGNING_INFORMATION, &raw mut info)
        };
        if status != 0 || info.is_null() {
            return false;
        }
        // SAFETY: a successful copy returned an owned dictionary and a live framework constant.
        let info: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(info) };
        // SAFETY: framework constants remain valid for the life of the process.
        let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoFlags) };
        info.find(&key)
            .and_then(|value| value.downcast::<CFNumber>())
            .and_then(|value| value.to_i64())
            .is_some_and(|flags| flags & CS_RUNTIME != 0)
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

    pub(super) fn check_pid(pid: i32, requirement: &str) -> io::Result<()> {
        let mut attributes = GuestAttributes::new();
        attributes.set_pid(pid);
        let guest = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
            .map_err(|error| os_error("SecCodeCopyGuestWithAttributes", error))?;
        let requirement: SecRequirement = requirement
            .parse()
            .map_err(|error| os_error("SecRequirementCreateWithString", error))?;
        guest
            .check_validity(Flags::NONE, &requirement)
            .map_err(|error| os_error("SecCodeCheckValidity", error))
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

    #[cfg(unix)]
    #[tokio::test]
    async fn reports_our_own_uid_pid_and_executable_for_a_socket_pair() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");
        let peer = crate::transport::unix::credentials(&ours).expect("credentials");
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

    #[cfg(unix)]
    #[tokio::test]
    async fn same_executable_rejects_other_binaries() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");
        let peer = crate::transport::unix::credentials(&ours).expect("credentials");
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
        let peer = crate::transport::unix::credentials(&stream).expect("credentials");
        assert_eq!(peer.uid, own_uid());
        assert_eq!(peer.pid, i32::try_from(nc.id()).expect("pid fits"));
        assert_eq!(peer.executable, PathBuf::from("/usr/bin/nc"));
        assert!(!SameExecutable::current().expect("verifier").verify(&peer));
        let _ = nc.kill();
        let _ = nc.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A same-uid client running another binary: perl, present on the CI image and in Docker.
    #[cfg(target_os = "linux")]
    fn perl_client(socket: &Path, then: &str) -> std::process::Child {
        std::process::Command::new("perl")
            .arg("-MIO::Socket::UNIX")
            .arg("-e")
            .arg(format!(
                "my $s = IO::Socket::UNIX->new(Peer => $ARGV[0]) or die $!; {then}"
            ))
            .arg(socket)
            .spawn()
            .expect("perl")
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn another_binary_is_refused_by_file_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("peer.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind");
        let mut perl = perl_client(&socket, "sleep 5");
        let (stream, _) = listener.accept().await.expect("accept");
        let peer = crate::transport::unix::credentials(&stream).expect("credentials");
        assert_eq!(peer.pid, i32::try_from(perl.id()).expect("pid fits"));
        assert!(peer.exe_identity.is_some(), "a live peer is identified");
        assert!(!SameExecutable::current().expect("verifier").verify(&peer));
        let perl_path = executable_of(peer.pid).expect("perl path");
        assert!(
            SameExecutable::new(&perl_path)
                .expect("verifier")
                .verify(&peer)
        );
        let _ = perl.kill();
        let _ = perl.wait();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_peer_that_exited_before_the_check_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("peer.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind");
        let mut perl = perl_client(&socket, "exit 0");
        let (stream, _) = listener.accept().await.expect("accept");
        perl.wait().expect("perl exits");
        let peer = crate::transport::unix::credentials(&stream).expect("credentials");
        assert_eq!(peer.exe_identity, None);
        let any_binary = SameExecutable::new(Path::new("/proc/self/exe")).expect("verifier");
        assert!(!any_binary.verify(&peer));
    }

    #[cfg(target_os = "linux")]
    mod verdicts {
        use super::*;

        const OLD: FileIdentity = FileIdentity { dev: 1, ino: 10 };
        const NEW: FileIdentity = FileIdentity { dev: 1, ino: 11 };

        fn peer(identity: Option<FileIdentity>, path: &str) -> PeerCredentials {
            PeerCredentials {
                uid: 0,
                pid: 1,
                executable: PathBuf::from(path),
                audit_token: None,
                exe_identity: identity,
            }
        }

        fn installed(identity: FileIdentity) -> Installed {
            Installed {
                path: PathBuf::from("/opt/vk/bin/vaultkeeper"),
                identity,
            }
        }

        #[test]
        fn the_daemons_own_binary_is_accepted() {
            let peer = peer(Some(OLD), "/opt/vk/bin/vaultkeeper");
            assert_eq!(decide(OLD, &peer, || None), Verdict::Accepted);
            assert_eq!(
                decide(OLD, &peer, || Some(installed(NEW))),
                Verdict::Accepted
            );
        }

        #[test]
        fn the_installed_binary_replacing_ours_is_an_outdated_daemon() {
            let peer = peer(Some(NEW), "/opt/vk/bin/vaultkeeper");
            assert_eq!(
                decide(OLD, &peer, || Some(installed(NEW))),
                Verdict::DaemonOutdated
            );
        }

        #[test]
        fn any_other_peer_is_rejected() {
            let elsewhere = peer(Some(NEW), "/tmp/evil");
            assert_eq!(
                decide(OLD, &elsewhere, || Some(installed(NEW))),
                Verdict::Rejected
            );
            let stale = peer(
                Some(FileIdentity { dev: 1, ino: 12 }),
                "/opt/vk/bin/vaultkeeper",
            );
            assert_eq!(
                decide(OLD, &stale, || Some(installed(NEW))),
                Verdict::Rejected
            );
            let installed_peer = peer(Some(NEW), "/opt/vk/bin/vaultkeeper");
            assert_eq!(decide(OLD, &installed_peer, || None), Verdict::Rejected);
            let unknown = peer(None, "/opt/vk/bin/vaultkeeper");
            assert_eq!(
                decide(OLD, &unknown, || Some(installed(NEW))),
                Verdict::Rejected
            );
        }
    }

    #[cfg(target_os = "macos")]
    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-peer-{}", std::process::id()));
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

    #[cfg(windows)]
    #[test]
    fn our_own_process_passes_the_windows_identity_check() {
        let peer = PeerCredentials {
            uid: 0,
            pid: i32::try_from(std::process::id()).expect("pid fits"),
            executable: PathBuf::new(),
            audit_token: None,
            session_id: vk_win::current_session_id().expect("current session"),
        };
        assert!(SameExecutable::current().expect("verifier").verify(&peer));
    }

    #[cfg(windows)]
    #[test]
    fn a_peer_from_another_session_is_rejected() {
        let peer = PeerCredentials {
            uid: 0,
            pid: i32::try_from(std::process::id()).expect("pid fits"),
            executable: PathBuf::new(),
            audit_token: None,
            session_id: u32::MAX,
        };
        assert!(!SameExecutable::current().expect("verifier").verify(&peer));
    }

    #[test]
    fn closures_are_verifiers() {
        let deny_all = |_: &PeerCredentials| false;
        let peer = PeerCredentials {
            uid: 0,
            pid: 1,
            executable: PathBuf::from("/"),
            audit_token: None,
            #[cfg(windows)]
            session_id: 0,
            #[cfg(target_os = "linux")]
            exe_identity: None,
        };
        assert!(!deny_all.verify(&peer));
    }
}
