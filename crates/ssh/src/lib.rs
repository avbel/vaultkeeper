//! SSH agent for vault SSH keys, built on the vendored Bitwarden `ssh_agent` crate.
//!
//! Every sign request goes to the UI through [`ApprovalRequest`]; the UI answers on the oneshot.

use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

pub type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

/// A key as stored in the vault (OpenSSH PEM).
pub struct AgentKey {
    pub cipher_id: String,
    pub name: String,
    pub private_key: Zeroizing<String>,
}

#[derive(Debug)]
pub enum ApprovalKind {
    Sign {
        cipher_id: Option<String>,
        process_name: Option<String>,
        is_forwarding: bool,
        /// e.g. "git" for git commit signing (SSHSIG namespace).
        namespace: Option<String>,
    },
    /// Agent asked to list keys before the first unlock.
    List,
}

/// Sent to the UI; reply `true` to approve. Dropping the sender counts as deny.
#[derive(Debug)]
pub struct ApprovalRequest {
    pub kind: ApprovalKind,
    pub reply: oneshot::Sender<bool>,
}

pub struct SshAgent {
    socket_path: PathBuf,
}

impl SshAgent {
    /// Binds the socket (mode 0600) and serves until [`SshAgent::stop`]. Requests needing approval
    /// are sent on `approvals`; they auto-deny after 30 s without an answer.
    pub fn start(socket_path: PathBuf, approvals: mpsc::Sender<ApprovalRequest>) -> Result<Self> {
        drop((socket_path, approvals));
        todo!("step 5")
    }

    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Atomically replaces the served keys. Unparseable keys are skipped with a warning.
    pub fn replace_keys(&self, keys: Vec<AgentKey>) -> Result<()> {
        drop(keys);
        todo!("step 5")
    }

    /// Stops serving and clears keys.
    pub fn stop(&mut self) {
        todo!("step 5")
    }
}

/// Converts a pasted private key (OpenSSH, PKCS#8 or PEM, optionally passphrase-protected)
/// into the OpenSSH form stored in the vault: `(private_pem, public_openssh, sha256_fingerprint)`.
pub fn import_key(
    input: &str,
    passphrase: Option<&str>,
) -> Result<(Zeroizing<String>, String, String)> {
    let _ = (input, passphrase);
    todo!("step 5")
}

/// Generates a new Ed25519 key for "New SSH key" in the UI; same tuple as [`import_key`].
pub fn generate_ed25519() -> Result<(Zeroizing<String>, String, String)> {
    todo!("step 5")
}
