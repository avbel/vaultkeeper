//! Provides an orchestration between the underlying ssh agent server, the keystore
//! and the upstream approver of server requests.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, MutexGuard, PoisonError,
};

use anyhow::Result;
use tracing::{debug, info};

use crate::{
    approval::ApprovalRequester, authorization::BitwardenAuthPolicy, server::SSHAgentServer,
    storage::keystore::KeyStore,
};

/// vk patch: epochs are drawn process-wide, so an epoch read from one agent never matches a
/// later agent that replaced it (disable and re-enable, account switch).
static NEXT_EPOCH: AtomicU64 = AtomicU64::new(0);

fn fresh_epoch() -> u64 {
    NEXT_EPOCH.fetch_add(1, Ordering::Relaxed)
}

/// - contains the [`KeyStore`] of ssh keys
/// - manages the [`SSHAgentServer`]
/// - provides an Authentication policy for server requests
pub struct BitwardenSSHAgent<K, H>
where
    K: KeyStore,
    H: ApprovalRequester,
{
    /// store of ssh keys. shared with the authorization policy and server.
    keystore: Arc<K>,
    // the agent's server
    server: SSHAgentServer<K, BitwardenAuthPolicy<K, H>>,
    /// vk patch: bumped by every clear. Holding the lock across the compare and the replace (and
    /// across the clear and the bump) is what keeps a stale refresh from landing after a clear.
    epoch: Mutex<u64>,
}

impl<K, H> BitwardenSSHAgent<K, H>
where
    K: KeyStore + Send + Sync + 'static,
    H: ApprovalRequester + 'static,
{
    /// Creates a new [`BitwardenSSHAgent`]
    pub fn new(keystore: K, approval_handler: H) -> Self {
        let keystore = Arc::new(keystore);
        let auth_policy = Arc::new(BitwardenAuthPolicy::new(keystore.clone(), approval_handler));
        let server = SSHAgentServer::new(keystore.clone(), auth_policy);

        Self {
            keystore,
            server,
            epoch: Mutex::new(fresh_epoch()),
        }
    }

    /// Starts the ssh agent server
    pub fn start(&mut self) -> Result<()> {
        debug!("Starting the server.");
        self.server.start_with_default_listeners()
    }

    /// vk patch: starts the ssh agent server on an explicit Unix socket path instead of
    /// `BITWARDEN_SSH_AUTH_SOCK` / `~/.bitwarden-ssh-agent.sock`.
    #[cfg(unix)]
    pub fn start_at(&mut self, socket_path: std::path::PathBuf) -> Result<()> {
        debug!("Starting the server at an explicit socket path.");
        self.server.start_at_socket_path(socket_path)
    }

    /// vk patch: starts the ssh agent server on an explicit pipe name instead of
    /// `\\.\pipe\openssh-ssh-agent`, which the OpenSSH service may own.
    #[cfg(windows)]
    pub fn start_on(&mut self, pipe_name: &str) -> Result<()> {
        debug!("Starting the server on an explicit pipe name.");
        self.server.start_on_pipe(pipe_name)
    }

    /// Stops the server and clears the keystore.
    pub fn stop(&mut self) {
        debug!("Stopping server and clearing keys.");
        self.server.stop();
        self.clear_and_bump();
    }

    /// # Returns
    ///
    /// `true` if the server is running, `false` if it is not.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.server.is_running()
    }

    /// Atomically replaces the keystore contents with the provided keys.
    pub fn replace(&self, keys: Vec<K::KeyData>) -> Result<()> {
        debug!("Replacing key data.");
        let _epoch = self.lock_epoch();
        self.keystore.replace(keys)?;
        info!("Key data replaced.");
        Ok(())
    }

    /// vk patch: the current clear generation. Read it before loading keys and hand it to
    /// [`BitwardenSSHAgent::replace_if`].
    #[must_use]
    pub fn epoch(&self) -> u64 {
        *self.lock_epoch()
    }

    /// vk patch: replaces the keys only if no [`clear`](Self::clear) or [`stop`](Self::stop) ran
    /// since `epoch` was read. Returns `Ok(false)` and drops `keys` when one did.
    pub fn replace_if(&self, epoch: u64, keys: Vec<K::KeyData>) -> Result<bool> {
        let current = self.lock_epoch();
        if *current != epoch {
            info!(
                epoch,
                current = *current,
                "Discarding keys loaded before a clear."
            );
            return Ok(false);
        }
        self.keystore.replace(keys)?;
        info!("Key data replaced.");
        Ok(true)
    }

    fn lock_epoch(&self) -> MutexGuard<'_, u64> {
        self.epoch.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn clear_and_bump(&self) {
        let mut epoch = self.lock_epoch();
        self.keystore.clear();
        *epoch = fresh_epoch();
    }

    /// Drops every key and marks the keystore uninitialized, so the next list request asks for
    /// approval again (the "unlock first" path) instead of answering with an empty list.
    pub fn clear(&self) {
        debug!("Clearing key data.");
        self.clear_and_bump();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{approval::MockApprovalRequester, storage::keystore::MockKeyStore};

    #[test]
    fn stop_clears_the_keystore() {
        let mut keystore = MockKeyStore::new();
        keystore.expect_clear().once().return_const(());
        let approval_handler = MockApprovalRequester::new();

        let mut agent = BitwardenSSHAgent::new(keystore, approval_handler);

        agent.stop();
    }

    #[test]
    fn clear_clears_the_keystore_without_stopping() {
        let mut keystore = MockKeyStore::new();
        keystore.expect_clear().once().return_const(());
        let agent = BitwardenSSHAgent::new(keystore, MockApprovalRequester::new());

        agent.clear();
        assert!(!agent.is_running());
    }

    #[test]
    fn replace_if_with_the_current_epoch_replaces() {
        let mut keystore = MockKeyStore::new();
        keystore.expect_replace().once().returning(|_| Ok(()));
        let agent = BitwardenSSHAgent::new(keystore, MockApprovalRequester::new());

        let epoch = agent.epoch();

        assert!(agent.replace_if(epoch, vec![]).unwrap());
    }

    #[test]
    fn replace_if_after_a_clear_discards_the_keys() {
        let mut keystore = MockKeyStore::new();
        keystore.expect_clear().once().return_const(());
        keystore.expect_replace().never();
        let agent = BitwardenSSHAgent::new(keystore, MockApprovalRequester::new());

        let epoch = agent.epoch();
        agent.clear();

        assert!(!agent.replace_if(epoch, vec![]).unwrap());
        assert_ne!(agent.epoch(), epoch);
    }

    #[test]
    fn replace_if_after_a_stop_discards_the_keys() {
        let mut keystore = MockKeyStore::new();
        keystore.expect_clear().once().return_const(());
        keystore.expect_replace().never();
        let mut agent = BitwardenSSHAgent::new(keystore, MockApprovalRequester::new());

        let epoch = agent.epoch();
        agent.stop();

        assert!(!agent.replace_if(epoch, vec![]).unwrap());
    }

    #[test]
    fn an_epoch_from_another_agent_never_matches() {
        let first = BitwardenSSHAgent::new(MockKeyStore::new(), MockApprovalRequester::new());
        let mut keystore = MockKeyStore::new();
        keystore.expect_replace().never();
        let second = BitwardenSSHAgent::new(keystore, MockApprovalRequester::new());

        assert!(!second.replace_if(first.epoch(), vec![]).unwrap());
    }
}
