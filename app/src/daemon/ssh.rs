//! The daemon's SSH agent: which keys it serves, the labels its prompts show, and the approvals
//! remembered until the vault locks.
//!
//! Keys stay loaded while the same account is locked: the vendored agent only asks for approval
//! for keys it holds, and a sign request while locked must reach the UI, which unlocks first.
//! Log out and account switch clear them.

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
    Keep,
    Clear,
}

/// What the agent should hold for this session state; `served_for` is the account whose keys it
/// holds now.
#[must_use]
pub fn key_action(
    state: &SessionState,
    active: Option<&str>,
    served_for: Option<&str>,
) -> KeyAction {
    match state {
        SessionState::Unlocked { .. } => KeyAction::Serve,
        SessionState::Locked { .. } if active.is_some() && active == served_for => KeyAction::Keep,
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

#[derive(Default)]
struct Served {
    account: Option<Arc<str>>,
    labels: HashMap<String, KeyLabel>,
}

pub struct SshControl {
    socket: PathBuf,
    approvals: mpsc::Sender<ApprovalRequest>,
    agent: Mutex<Option<SshAgent>>,
    served: Mutex<Served>,
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
            served: Mutex::new(Served::default()),
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
                *guard(&self.served) = Served::default();
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
        let state = vault.state();
        let active = vault.active_account_id();
        let served_for = guard(&self.served).account.clone();
        match key_action(&state, active.as_deref(), served_for.as_deref()) {
            KeyAction::Keep => {}
            KeyAction::Clear => self.replace(Vec::new(), Served::default()),
            KeyAction::Serve => {
                let source = Arc::clone(vault);
                let loaded = tokio::task::spawn_blocking(move || load_keys(&source)).await;
                match loaded {
                    Ok(Ok((keys, labels))) => self.replace(
                        keys,
                        Served {
                            account: active,
                            labels,
                        },
                    ),
                    Ok(Err(error)) => tracing::warn!(%error, "cannot read SSH keys from the vault"),
                    Err(error) => tracing::error!(%error, "SSH key task failed"),
                }
            }
        }
    }

    fn replace(&self, keys: Vec<AgentKey>, served: Served) {
        let count = keys.len();
        if let Some(agent) = guard(&self.agent).as_ref()
            && let Err(error) = agent.replace_keys(keys)
        {
            tracing::warn!(%error, "cannot update the SSH agent's keys");
            return;
        }
        tracing::debug!(count, "SSH agent keys replaced");
        *guard(&self.served) = served;
    }

    #[must_use]
    pub fn label(&self, cipher_id: &str) -> Option<KeyLabel> {
        guard(&self.served).labels.get(cipher_id).cloned()
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

/// The agent's key list plus a name and fingerprint per cipher, for prompts shown while locked.
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
    fn keys_follow_the_session() {
        let unlocked = SessionState::Unlocked {
            server: Url::parse("https://vault.example.com").expect("url"),
            email: "a@example.com".to_owned(),
        };
        assert_eq!(key_action(&unlocked, Some("a"), None), KeyAction::Serve);
        assert_eq!(
            key_action(&locked(), Some("a"), Some("a")),
            KeyAction::Keep,
            "lock keeps them"
        );
        assert_eq!(
            key_action(&locked(), Some("b"), Some("a")),
            KeyAction::Clear,
            "another account became active"
        );
        assert_eq!(key_action(&locked(), Some("a"), None), KeyAction::Clear);
        assert_eq!(
            key_action(&SessionState::LoggedOut, None, Some("a")),
            KeyAction::Clear,
            "log out"
        );
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
