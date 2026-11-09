//! SSH agent for vault SSH keys, built on the vendored Bitwarden `ssh_agent` crate.
//!
//! Every sign request goes to the UI through [`ApprovalRequest`]; the UI answers on the oneshot.
//!
//! Unix only: the agent listens on a Unix domain socket.

#[cfg(not(unix))]
compile_error!("bwl-ssh serves a Unix domain socket and supports only Unix targets");

mod approver;
mod error;
mod keys;
mod socket;

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use ssh_agent::{BitwardenSSHAgent, InMemoryEncryptedKeyStore, SSHKeyData};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;
use zeroize::Zeroizing;

use approver::ChannelApprover;
pub use error::{AgentError, ImportError};
pub use keys::{KeyMaterial, generate_ed25519, import_key};

pub type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

/// How long a request waits for the UI before it is denied.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(30);

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
///
/// When the request expires the agent drops the receiving end, so `reply.closed()` resolves and
/// the UI can dismiss its window.
#[derive(Debug)]
pub struct ApprovalRequest {
    pub kind: ApprovalKind,
    pub reply: oneshot::Sender<bool>,
}

type Agent = BitwardenSSHAgent<InMemoryEncryptedKeyStore, ChannelApprover>;

/// Dropping the handle stops the agent.
#[must_use = "dropping the handle stops the SSH agent"]
pub struct SshAgent {
    socket_path: PathBuf,
    agent: Agent,
}

impl SshAgent {
    /// Binds the socket (mode 0600) and serves until [`SshAgent::stop`]. Requests needing approval
    /// are sent on `approvals`; they auto-deny after [`APPROVAL_TIMEOUT`] without an answer.
    ///
    /// Must be called from inside a Tokio runtime with the IO and time drivers enabled (the
    /// vendored server spawns its accept loop with `tokio::spawn` and binds a Tokio socket): from
    /// within a task, under `block_on`, or while holding a `Runtime::enter()` guard. A multi-thread
    /// runtime serves connections in the background; a current-thread runtime only while it is
    /// being driven. The agent's tasks live on that runtime, so keep it alive for as long as the
    /// agent runs. Outside a runtime this fails with [`AgentError::NoRuntime`].
    ///
    /// A missing parent directory is created with mode 0700. A stale socket at `socket_path` is
    /// replaced; a socket that still accepts connections yields [`AgentError::AlreadyRunning`] and
    /// any other file type [`AgentError::NotASocket`].
    pub fn start(socket_path: PathBuf, approvals: mpsc::Sender<ApprovalRequest>) -> Result<Self> {
        Self::start_with_approval_timeout(socket_path, approvals, APPROVAL_TIMEOUT)
    }

    /// Like [`SshAgent::start`] with a custom approval timeout.
    pub fn start_with_approval_timeout(
        socket_path: PathBuf,
        approvals: mpsc::Sender<ApprovalRequest>,
        approval_timeout: Duration,
    ) -> Result<Self> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(AgentError::NoRuntime.into());
        }
        socket::prepare(&socket_path)?;
        let approver = ChannelApprover::new(approvals, approval_timeout);
        let mut agent = BitwardenSSHAgent::new(InMemoryEncryptedKeyStore::new(), approver);
        agent.start_at(socket_path.clone())?;
        Ok(Self { socket_path, agent })
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.agent.is_running()
    }

    /// Atomically replaces the served keys. Unparseable keys are skipped with a warning.
    pub fn replace_keys(&self, keys: Vec<AgentKey>) -> Result<()> {
        if !self.is_running() {
            return Err(AgentError::NotRunning.into());
        }
        let served = keys.into_iter().filter_map(parse_key).collect();
        self.agent.replace(served)
    }

    /// Drops every served key and keeps serving. Unlike `replace_keys(vec![])`, the next list
    /// request goes to the approval channel as [`ApprovalKind::List`] again, which is how a
    /// locked vault gets the user to unlock.
    pub fn clear_keys(&self) {
        self.agent.clear();
    }

    /// Stops serving, clears keys and removes the socket file.
    pub fn stop(&mut self) {
        if self.is_running() {
            self.agent.stop();
            socket::remove(&self.socket_path);
        }
    }
}

impl Drop for SshAgent {
    fn drop(&mut self) {
        self.stop();
    }
}

fn parse_key(key: AgentKey) -> Option<SSHKeyData> {
    let AgentKey {
        cipher_id,
        name,
        private_key,
    } = key;
    SSHKeyData::from_private_key_pem(&private_key, name, cipher_id.clone())
        .inspect_err(|error| warn!(%cipher_id, %error, "skipping SSH key the agent cannot serve"))
        .ok()
}
