//! The daemon's SSH agent: which keys it serves, the labels its prompts show, and the approvals
//! remembered until the vault locks.
//!
//! The agent holds keys only while the active account is unlocked. Lock, log out and account
//! switch clear them and mark the agent's store uninitialized, so the next `ssh-add -l` or
//! connection asks for list approval, which opens the lock screen (`approve_list`).

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use bwl_ssh::{AgentKey, ApprovalRequest, SshAgent};
use bwl_vault::{
    Vault, VaultService,
    model::{Filter, ItemKind, SessionState},
};
use tokio::sync::mpsc;

/// Covers queueing, an unlock (KDF included) and the 30 s prompt; the UI auto-denies its prompt
/// on its own after 30 s.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Serve,
    Clear,
}

/// What the agent should hold for this session state.
#[must_use]
pub const fn key_action(state: &SessionState) -> KeyAction {
    match state {
        SessionState::Unlocked { .. } => KeyAction::Serve,
        SessionState::Locked { .. } | SessionState::LoggedOut => KeyAction::Clear,
    }
}

/// e.g. "git commit signing"; `None` for a plain `ssh` login.
#[must_use]
pub fn purpose(namespace: Option<&str>, is_forwarding: bool) -> Option<String> {
    let text = match namespace {
        Some("git") => "git commit signing",
        Some("file") => "file signing",
        Some(_) => "signing",
        None if is_forwarding => "agent forwarding",
        None => return None,
    };
    Some(text.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLabel {
    pub name: String,
    pub fingerprint: String,
}

pub struct SshControl {
    socket: PathBuf,
    approvals: mpsc::Sender<ApprovalRequest>,
    agent: Mutex<Option<SshAgent>>,
    /// Name and fingerprint per served cipher id, for the approval prompt.
    labels: Mutex<HashMap<String, KeyLabel>>,
    /// Cipher ids approved with "Remember for this key until lock".
    remembered: Mutex<HashSet<String>>,
}

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl SshControl {
    #[must_use]
    pub fn new(socket: PathBuf, approvals: mpsc::Sender<ApprovalRequest>) -> Self {
        Self {
            socket,
            approvals,
            agent: Mutex::new(None),
            labels: Mutex::new(HashMap::new()),
            remembered: Mutex::new(HashSet::new()),
        }
    }

    #[must_use]
    pub fn socket(&self) -> &std::path::Path {
        &self.socket
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        guard(&self.agent)
            .as_ref()
            .is_some_and(SshAgent::is_running)
    }

    /// Starts or stops the agent; must run inside the Tokio runtime. Returns whether it started.
    pub fn set_enabled(&self, enabled: bool) -> anyhow::Result<bool> {
        let mut agent = guard(&self.agent);
        match (enabled, agent.is_some()) {
            (true, false) => {
                *agent = Some(SshAgent::start_with_approval_timeout(
                    self.socket.clone(),
                    self.approvals.clone(),
                    APPROVAL_TIMEOUT,
                )?);
                tracing::info!(socket = %self.socket.display(), "SSH agent started");
                Ok(true)
            }
            (false, true) => {
                if let Some(mut stopped) = agent.take() {
                    stopped.stop();
                }
                guard(&self.labels).clear();
                tracing::info!("SSH agent stopped");
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// Stops serving and removes the socket.
    pub fn stop(&self) {
        if let Some(mut agent) = guard(&self.agent).take() {
            agent.stop();
        }
    }

    /// Brings the served keys in line with the vault; decrypting runs on the blocking pool.
    pub async fn refresh(&self, vault: &Arc<Vault>) {
        if !self.is_running() {
            return;
        }
        match key_action(&vault.state()) {
            KeyAction::Clear => self.clear(),
            KeyAction::Serve => {
                let source = Arc::clone(vault);
                let loaded = tokio::task::spawn_blocking(move || load_keys(&source)).await;
                match loaded {
                    Ok(Ok((keys, labels))) => self.replace(keys, labels),
                    Ok(Err(error)) => tracing::warn!(%error, "cannot read SSH keys from the vault"),
                    Err(error) => tracing::error!(%error, "SSH key task failed"),
                }
            }
        }
    }

    /// Drops every key at once; also called straight from the state loop on lock, so the keys do
    /// not wait for the key refresh task.
    pub fn clear(&self) {
        if let Some(agent) = guard(&self.agent).as_ref() {
            agent.clear_keys();
        }
        guard(&self.labels).clear();
    }

    fn replace(&self, keys: Vec<AgentKey>, labels: HashMap<String, KeyLabel>) {
        let count = keys.len();
        if let Some(agent) = guard(&self.agent).as_ref()
            && let Err(error) = agent.replace_keys(keys)
        {
            tracing::warn!(%error, "cannot update the SSH agent's keys");
            return;
        }
        tracing::debug!(count, "SSH agent keys replaced");
        *guard(&self.labels) = labels;
    }

    #[must_use]
    pub fn label(&self, cipher_id: &str) -> Option<KeyLabel> {
        guard(&self.labels).get(cipher_id).cloned()
    }

    #[must_use]
    pub fn is_remembered(&self, cipher_id: &str) -> bool {
        guard(&self.remembered).contains(cipher_id)
    }

    pub fn remember(&self, cipher_id: String) {
        guard(&self.remembered).insert(cipher_id);
    }

    pub fn forget_approvals(&self) {
        guard(&self.remembered).clear();
    }
}

/// The agent's key list plus a name and fingerprint per cipher, for the approval prompt.
/// The fingerprint is the SSH item's list subtitle, so no key is parsed here.
fn load_keys(vault: &Vault) -> bwl_vault::Result<(Vec<AgentKey>, HashMap<String, KeyLabel>)> {
    let filter = Filter {
        kind: Some(ItemKind::SshKey),
        ..Filter::default()
    };
    let labels = vault
        .search("", &filter)?
        .iter()
        .map(|item| {
            (
                item.id.0.to_string(),
                KeyLabel {
                    name: item.name.to_string(),
                    fingerprint: item.subtitle.to_string(),
                },
            )
        })
        .collect();
    let keys = vault
        .ssh_keys()?
        .into_iter()
        .map(|key| AgentKey {
            cipher_id: key.cipher_id.0.to_string(),
            name: key.name,
            private_key: key.private_key,
        })
        .collect();
    Ok((keys, labels))
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;

    fn locked() -> SessionState {
        SessionState::Locked {
            server: Url::parse("https://vault.example.com").expect("url"),
            email: "a@example.com".to_owned(),
        }
    }

    #[test]
    fn keys_are_served_only_while_unlocked() {
        let unlocked = SessionState::Unlocked {
            server: Url::parse("https://vault.example.com").expect("url"),
            email: "a@example.com".to_owned(),
        };
        assert_eq!(key_action(&unlocked), KeyAction::Serve);
        assert_eq!(key_action(&locked()), KeyAction::Clear, "lock clears them");
        assert_eq!(key_action(&SessionState::LoggedOut), KeyAction::Clear);
    }

    #[test]
    fn clearing_a_stopped_agent_forgets_the_labels() {
        let (approvals, _rx) = mpsc::channel(1);
        let control = SshControl::new(PathBuf::from("/tmp/unused.sock"), approvals);
        control.replace(
            Vec::new(),
            HashMap::from([(
                "c1".to_owned(),
                KeyLabel {
                    name: "deploy".to_owned(),
                    fingerprint: "SHA256:abc".to_owned(),
                },
            )]),
        );
        assert_eq!(
            control.label("c1").map(|label| label.name),
            Some("deploy".to_owned())
        );
        control.clear();
        assert_eq!(control.label("c1"), None);
    }

    #[test]
    fn purposes_name_what_the_signature_is_for() {
        assert_eq!(
            purpose(Some("git"), false).as_deref(),
            Some("git commit signing")
        );
        assert_eq!(
            purpose(Some("file"), false).as_deref(),
            Some("file signing")
        );
        assert_eq!(purpose(Some("other"), true).as_deref(), Some("signing"));
        assert_eq!(purpose(None, true).as_deref(), Some("agent forwarding"));
        assert_eq!(purpose(None, false), None);
    }

    #[test]
    fn remembered_approvals_are_forgotten_together() {
        let (approvals, _rx) = mpsc::channel(1);
        let control = SshControl::new(PathBuf::from("/tmp/unused.sock"), approvals);
        control.remember("c1".to_owned());
        assert!(control.is_remembered("c1"));
        assert!(!control.is_remembered("c2"));
        control.forget_approvals();
        assert!(!control.is_remembered("c1"));
    }
}
