//! Machine binding for the 2FA-remember token through `systemd-creds --user` (systemd >= 256),
//! chain C1 link 5 (linux-ideas.md §11). The credential key is the TPM2 and/or the root-only host
//! key plus uid and machine id, so a copied disk alone cannot open the blob; any process of the
//! same user still can, which is all the token needs.
//!
//! The tool is a subprocess: the secret goes over stdin and the result comes back over stdout,
//! never through argv or the environment. Its output is untrusted, so it is size-bounded, the exit
//! status is checked, stderr is dropped, and no error message carries secret bytes.
//!
//! Blob format written through [`BlobCodec`]: `MAGIC ‖ systemd-creds output`. A blob without the
//! magic is a token stored before the tool was available and is returned as is, so enabling the
//! wrapper later never loses a token (it is rewrapped the next time it is written). A blob with
//! the magic and no tool is an error, never "undecryptable", so a missing tool cannot delete a
//! token that returns with it.

use std::{
    ffi::OsString,
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::security::{Link, Probe};

const PROGRAM: &str = "systemd-creds";
const CREDENTIAL_NAME: &str = "vaultkeeper.2fa";
const MIN_SYSTEMD_VERSION: u32 = 256;
const MAGIC: &[u8] = b"VKCRED1\0";
/// Tokens are a few hundred bytes; the cap only stops a misbehaving tool from filling memory.
const MAX_INPUT: usize = 32 * 1024;
const MAX_OUTPUT: usize = 64 * 1024;
/// A TPM-backed encrypt can take seconds on slow hardware; a hung tool must not hang the daemon.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const TPM_NODES: [&str; 2] = ["/dev/tpmrm0", "/sys/class/tpm/tpm0"];
const FALLBACK_DIRS: [&str; 2] = ["/usr/bin", "/bin"];
const PROBE_PAYLOAD: &[u8] = b"vaultkeeper probe";
/// A just-written fake or freshly installed binary can be briefly "text file busy" while another
/// thread's fork still holds its write descriptor.
const SPAWN_RETRIES: u32 = 5;
const ETXTBSY: i32 = 26;

#[derive(Debug, Error)]
pub enum CredsError {
    #[error("cannot start systemd-creds: {0}")]
    Spawn(io::Error),
    #[error("systemd-creds io error: {0}")]
    Io(io::Error),
    #[error("systemd-creds failed ({})", describe_status(*.0))]
    Failed(Option<i32>),
    #[error("systemd-creds did not finish in time")]
    Timeout,
    #[error("data exceeds the {0} byte limit for systemd-creds")]
    TooLarge(usize),
    #[error("the token is wrapped by systemd-creds, which is not available")]
    Unavailable,
}

fn describe_status(code: Option<i32>) -> String {
    code.map_or_else(
        || "terminated by a signal".to_owned(),
        |code| format!("exit status {code}"),
    )
}

/// One `systemd-creds` binary; the path is injectable so tests run a fake command.
#[derive(Debug, Clone)]
pub struct Creds {
    program: PathBuf,
    timeout: Duration,
}

impl Creds {
    #[must_use]
    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CredsError> {
        if plaintext.len() > MAX_INPUT {
            return Err(CredsError::TooLarge(MAX_INPUT));
        }
        let output = self.run(&["--user", "encrypt"], &["--with-key=auto"], plaintext)?;
        Ok(output.to_vec())
    }

    pub fn decrypt(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CredsError> {
        if blob.len() > MAX_OUTPUT {
            return Err(CredsError::TooLarge(MAX_OUTPUT));
        }
        self.run(&["--user", "decrypt"], &[], blob)
    }

    fn version(&self) -> Result<u32, CredsError> {
        let output = self.run_args(&["--version"], &[])?;
        parse_version(&output).ok_or(CredsError::Failed(None))
    }

    /// `encrypt|decrypt --name=… [extra] - -`: input from stdin, result to stdout.
    fn run(
        &self,
        head: &[&str],
        extra: &[&str],
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CredsError> {
        let name = format!("--name={CREDENTIAL_NAME}");
        let mut args: Vec<&str> = head.to_vec();
        args.push(&name);
        args.extend_from_slice(extra);
        args.extend_from_slice(&["-", "-"]);
        self.run_args(&args, input)
    }

    fn run_args(&self, args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, CredsError> {
        let mut child = self.spawn(args)?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CredsError::Io(io::Error::other("missing child pipe")));
        };
        let overflow = AtomicBool::new(false);
        thread::scope(|scope| {
            let writer = scope.spawn(move || write_input(stdin, input));
            let reader = scope.spawn(|| read_bounded(stdout, &overflow));
            let waited = wait(&mut child, &overflow, self.timeout);
            let written = writer.join();
            let read = reader.join();
            let status = waited?;
            if !status.success() {
                return Err(CredsError::Failed(status.code()));
            }
            match written {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(CredsError::Io(error)),
                Err(_) => return Err(CredsError::Io(io::Error::other("writer panicked"))),
            }
            match read {
                Ok(Ok(output)) => Ok(output),
                Ok(Err(error)) => Err(CredsError::Io(error)),
                Err(_) => Err(CredsError::Io(io::Error::other("reader panicked"))),
            }
        })
    }

    fn spawn(&self, args: &[&str]) -> Result<Child, CredsError> {
        let mut attempt = 0;
        loop {
            let spawned = Command::new(&self.program)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            match spawned {
                Err(error) if error.raw_os_error() == Some(ETXTBSY) && attempt < SPAWN_RETRIES => {
                    attempt += 1;
                    thread::sleep(POLL_INTERVAL * 4);
                }
                Err(error) => return Err(CredsError::Spawn(error)),
                Ok(child) => return Ok(child),
            }
        }
    }
}

fn write_input(mut stdin: std::process::ChildStdin, input: &[u8]) -> io::Result<()> {
    match stdin.write_all(input) {
        // The tool may exit before reading everything; its exit status explains why.
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

fn read_bounded(
    stdout: std::process::ChildStdout,
    overflow: &AtomicBool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    // Preallocated so the buffer never reallocates and leaves unzeroed copies of a plaintext.
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_OUTPUT + 1));
    stdout
        .take(MAX_OUTPUT as u64 + 1)
        .read_to_end(&mut buffer)?;
    if buffer.len() > MAX_OUTPUT {
        overflow.store(true, Ordering::Release);
    }
    Ok(buffer)
}

fn wait(
    child: &mut Child,
    overflow: &AtomicBool,
    timeout: Duration,
) -> Result<ExitStatus, CredsError> {
    let deadline = Instant::now() + timeout;
    loop {
        if overflow.load(Ordering::Acquire) {
            reap(child);
            return Err(CredsError::TooLarge(MAX_OUTPUT));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if overflow.load(Ordering::Acquire) {
                    return Err(CredsError::TooLarge(MAX_OUTPUT));
                }
                return Ok(status);
            }
            Ok(None) => {}
            Err(error) => {
                reap(child);
                return Err(CredsError::Io(error));
            }
        }
        if Instant::now() >= deadline {
            reap(child);
            return Err(CredsError::Timeout);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// `systemd 258 (258.1-1)` → 258.
fn parse_version(output: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(output).ok()?;
    text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// Wraps and unwraps blobs for the token store; `None` means no tool, so wrapping is the identity.
#[derive(Debug, Clone)]
pub struct BlobCodec {
    creds: Option<Creds>,
}

impl BlobCodec {
    #[must_use]
    pub const fn new(creds: Option<Creds>) -> Self {
        Self { creds }
    }

    pub fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, CredsError> {
        let Some(creds) = &self.creds else {
            return Ok(plaintext.to_vec());
        };
        let encrypted = creds.encrypt(plaintext)?;
        let mut blob = Vec::with_capacity(MAGIC.len() + encrypted.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&encrypted);
        Ok(blob)
    }

    pub fn unwrap(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CredsError> {
        let Some(encrypted) = blob.strip_prefix(MAGIC) else {
            return Ok(Zeroizing::new(blob.to_vec()));
        };
        match &self.creds {
            Some(creds) => creds.decrypt(encrypted),
            None => Err(CredsError::Unavailable),
        }
    }
}

/// Which key the credential is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    TpmAndHost,
    Host,
    Unavailable(String),
}

impl Backend {
    #[must_use]
    pub fn probe(&self) -> Probe {
        match self {
            Self::TpmAndHost => Probe::Available,
            Self::Host => Probe::Degraded("host key only, no TPM2".to_owned()),
            Self::Unavailable(why) => Probe::Unavailable(why.clone()),
        }
    }

    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::TpmAndHost => "tpm2+host",
            Self::Host => "host",
            Self::Unavailable(_) => "none",
        }
    }
}

/// The outcome of looking for a working `systemd-creds`.
#[derive(Debug, Clone)]
pub struct Detection {
    creds: Option<Creds>,
    backend: Backend,
}

impl Detection {
    /// Looks for the tool on `$PATH` and in the standard directories, checks its version, and
    /// proves it works with a round trip, so a container without a systemd manager reports why.
    #[must_use]
    pub fn system() -> Self {
        let tpm = TPM_NODES.iter().any(|node| Path::new(node).exists());
        let program = find_program(std::env::var_os("PATH").as_ref());
        Self::probe(program.as_deref(), tpm)
    }

    #[must_use]
    pub fn probe(program: Option<&Path>, tpm_present: bool) -> Self {
        let Some(program) = program else {
            return Self::unavailable("systemd-creds is not installed".to_owned());
        };
        Self::probe_creds(Creds::with_program(program), tpm_present)
    }

    #[must_use]
    pub fn probe_creds(creds: Creds, tpm_present: bool) -> Self {
        match check(&creds) {
            Ok(()) => Self {
                creds: Some(creds),
                backend: if tpm_present {
                    Backend::TpmAndHost
                } else {
                    Backend::Host
                },
            },
            Err(why) => Self::unavailable(why),
        }
    }

    fn unavailable(why: String) -> Self {
        Self {
            creds: None,
            backend: Backend::Unavailable(why),
        }
    }

    #[must_use]
    pub const fn backend(&self) -> &Backend {
        &self.backend
    }

    #[must_use]
    pub fn into_creds(self) -> Option<Creds> {
        self.creds
    }

    /// Link 5 of chain C1. It stacks: it protects one token on top of the file-level links.
    #[must_use]
    pub fn link(&self) -> Link {
        let backend = self.backend.clone();
        Link::new("systemd-creds", "systemd-creds", move || backend.probe()).stacking()
    }
}

fn check(creds: &Creds) -> Result<(), String> {
    let version = creds
        .version()
        .map_err(|error| format!("systemd-creds --version failed: {error}"))?;
    if version < MIN_SYSTEMD_VERSION {
        return Err(format!(
            "systemd {version} is too old for systemd-creds --user (needs {MIN_SYSTEMD_VERSION})"
        ));
    }
    let blob = creds
        .encrypt(PROBE_PAYLOAD)
        .map_err(|error| format!("systemd-creds cannot encrypt: {error}"))?;
    let back = creds
        .decrypt(&blob)
        .map_err(|error| format!("systemd-creds cannot decrypt: {error}"))?;
    if back.as_slice() == PROBE_PAYLOAD {
        Ok(())
    } else {
        Err("systemd-creds round trip returned different data".to_owned())
    }
}

fn find_program(path: Option<&OsString>) -> Option<PathBuf> {
    let from_path = path
        .into_iter()
        .flat_map(std::env::split_paths)
        .collect::<Vec<_>>();
    from_path
        .into_iter()
        .chain(FALLBACK_DIRS.iter().map(PathBuf::from))
        .map(|dir| dir.join(PROGRAM))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests;
