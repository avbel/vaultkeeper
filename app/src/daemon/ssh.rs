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
    time::{Duration, Instant},
};

use tokio::sync::{Notify, mpsc};
use vk_ipc::transport::Endpoint;
use vk_ssh::{AgentError, AgentKey, ApprovalRequest, SshAgent};
use vk_vault::{
    Vault, VaultService,
    model::{Filter, ItemKind, SessionState},
};

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
    pub reprompt: bool,
}

/// What the user sees when the agent cannot start: a typed failure carries its own advice.
#[must_use]
pub fn start_failure_message(error: &anyhow::Error) -> String {
    error.downcast_ref::<AgentError>().map_or_else(
        || format!("The SSH agent could not start: {error:#}"),
        ToString::to_string,
    )
}

/// How often the watchdog looks whether a wanted agent still listens, when nothing woke it.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(30);
const RESTART_FIRST_DELAY: Duration = Duration::from_secs(5);
const RESTART_MAX_DELAY: Duration = Duration::from_mins(10);
/// An agent that served this long since its last restart counts as healthy again.
const STABLE_UPTIME: Duration = Duration::from_mins(5);
/// Consecutive failed restarts before the user is told; a persistent cause tells them at once.
const MAX_FAILED_RESTARTS: u32 = 3;
/// Caps the doubling so the shift cannot overflow; the delay is capped long before.
const MAX_DOUBLINGS: u32 = 16;

/// Whether a restart attempt is due yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Due {
    Now,
    In(Duration),
}

/// Restart pacing for an agent that keeps dying or failing to start.
#[derive(Debug, Default)]
struct RestartBackoff {
    /// Restarts, failed or not, since the agent last served for [`STABLE_UPTIME`].
    attempts: u32,
    /// Consecutive restarts that failed to start.
    failures: u32,
    last_attempt: Option<Instant>,
    /// This failure streak was already shown to the user.
    reported: bool,
}

impl RestartBackoff {
    fn running(&mut self, now: Instant) {
        if self
            .last_attempt
            .is_some_and(|at| now.saturating_duration_since(at) >= STABLE_UPTIME)
        {
            *self = Self::default();
        }
    }

    fn delay(&self) -> Duration {
        let doublings = self.attempts.saturating_sub(1).min(MAX_DOUBLINGS);
        RESTART_FIRST_DELAY
            .saturating_mul(1 << doublings)
            .min(RESTART_MAX_DELAY)
    }

    fn due(&self, now: Instant) -> Due {
        let Some(at) = self.last_attempt else {
            return Due::Now;
        };
        let ready = at + self.delay();
        if now >= ready {
            Due::Now
        } else {
            Due::In(ready - now)
        }
    }

    fn started(&mut self, now: Instant) {
        self.attempts = self.attempts.saturating_add(1);
        self.failures = 0;
        self.reported = false;
        self.last_attempt = Some(now);
    }

    /// Returns whether this failure is the one to show the user.
    fn failed(&mut self, now: Instant, persistent: bool) -> bool {
        self.attempts = self.attempts.saturating_add(1);
        self.failures = self.failures.saturating_add(1);
        self.last_attempt = Some(now);
        let report = !self.reported && (persistent || self.failures >= MAX_FAILED_RESTARTS);
        self.reported |= report;
        report
    }
}

/// A cause that retrying alone will not fix (another program holds the endpoint), so the user
/// hears about it on the first failed restart.
fn is_persistent(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<AgentError>(),
        Some(
            AgentError::PipeTaken { .. }
                | AgentError::AlreadyRunning(_)
                | AgentError::NotASocket(_)
        )
    )
}

/// What one watchdog check did.
#[derive(Debug)]
pub enum Revival {
    Idle,
    Restarted,
    Failed {
        error: anyhow::Error,
        /// Show it to the user: the failures kept coming or their cause is persistent.
        report: bool,
    },
}

#[derive(Default)]
struct AgentSlot {
    agent: Option<SshAgent>,
    /// The setting asks for an agent; shares the lock with `agent`, so a restart can never run
    /// after the user turned the agent off or the daemon stopped it for quit.
    wanted: bool,
    backoff: RestartBackoff,
}

pub struct SshControl {
    endpoint: Endpoint,
    approvals: mpsc::Sender<ApprovalRequest>,
    agent: Mutex<AgentSlot>,
    /// Wakes the watchdog: the agent was toggled or found dead.
    wake: Notify,
    /// Name and fingerprint per served cipher id, for the approval prompt.
    labels: Mutex<HashMap<String, KeyLabel>>,
    /// Cipher ids approved with "Remember for this key until lock".
    remembered: Mutex<HashSet<String>>,
}

/// `SshAgent` takes a `PathBuf` on both platforms: the socket file on Unix, the pipe name on Windows.
#[cfg(unix)]
fn agent_path(endpoint: &Endpoint) -> anyhow::Result<PathBuf> {
    endpoint
        .as_path()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("{endpoint} is not a socket file"))
}

#[cfg(windows)]
fn agent_path(endpoint: &Endpoint) -> anyhow::Result<PathBuf> {
    endpoint
        .as_pipe()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("{endpoint} is not a named pipe"))
}

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl SshControl {
    #[must_use]
    pub fn new(endpoint: Endpoint, approvals: mpsc::Sender<ApprovalRequest>) -> Self {
        Self {
            endpoint,
            approvals,
            agent: Mutex::new(AgentSlot::default()),
            wake: Notify::new(),
            labels: Mutex::new(HashMap::new()),
            remembered: Mutex::new(HashSet::new()),
        }
    }

    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        guard(&self.agent)
            .agent
            .as_ref()
            .is_some_and(SshAgent::is_running)
    }

    /// The setting asks for an agent and no quit stopped it.
    #[must_use]
    pub fn is_wanted(&self) -> bool {
        guard(&self.agent).wanted
    }

    /// Starts or stops the agent; must run inside the Tokio runtime. Returns whether it started.
    /// A failed start stays wanted, so the watchdog retries it with backoff; the caller reports
    /// this first failure itself.
    pub fn set_enabled(&self, enabled: bool) -> anyhow::Result<bool> {
        let mut slot = guard(&self.agent);
        slot.wanted = enabled;
        slot.backoff = RestartBackoff::default();
        self.wake.notify_one();
        match (enabled, slot.agent.is_some()) {
            (true, false) => match self.start(&mut slot) {
                Ok(()) => Ok(true),
                Err(error) => {
                    slot.backoff.failed(Instant::now(), true);
                    Err(error)
                }
            },
            (false, true) => {
                if let Some(mut stopped) = slot.agent.take() {
                    stopped.stop();
                }
                guard(&self.labels).clear();
                tracing::info!("SSH agent stopped");
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    fn start(&self, slot: &mut AgentSlot) -> anyhow::Result<()> {
        slot.agent = Some(SshAgent::start_with_approval_timeout(
            agent_path(&self.endpoint)?,
            self.approvals.clone(),
            APPROVAL_TIMEOUT,
        )?);
        tracing::info!(endpoint = %self.endpoint, "SSH agent started");
        Ok(())
    }

    /// Stops serving and removes the socket; nothing restarts it until `set_enabled(true)`.
    pub fn stop(&self) {
        let mut slot = guard(&self.agent);
        slot.wanted = false;
        if let Some(mut agent) = slot.agent.take() {
            agent.stop();
        }
    }

    /// Resolves when the agent was toggled or a key refresh found it dead.
    pub async fn woken(&self) {
        self.wake.notified().await;
    }

    /// The watchdog's check: restarts a wanted agent that stopped serving on its own (Windows
    /// lost every pipe instance, a fatal accept error on Unix), paced by the backoff. Must run
    /// inside the Tokio runtime. Returns what it did and when to check again.
    pub fn revive(&self, now: Instant) -> (Revival, Duration) {
        let mut slot = guard(&self.agent);
        if !slot.wanted {
            return (Revival::Idle, WATCH_INTERVAL);
        }
        if slot.agent.as_ref().is_some_and(SshAgent::is_running) {
            slot.backoff.running(now);
            return (Revival::Idle, WATCH_INTERVAL);
        }
        if let Due::In(wait) = slot.backoff.due(now) {
            return (Revival::Idle, wait.min(WATCH_INTERVAL));
        }
        let revival = self.restart(&mut slot, now);
        let next = match (&revival, slot.backoff.due(now)) {
            (Revival::Restarted, _) => WATCH_INTERVAL,
            (_, Due::Now) => Duration::ZERO,
            (_, Due::In(wait)) => wait.min(WATCH_INTERVAL),
        };
        (revival, next)
    }

    fn restart(&self, slot: &mut AgentSlot, now: Instant) -> Revival {
        // Stopped before the new one binds: stopping (and dropping) a handle removes the socket
        // file, which would otherwise be the new agent's.
        if let Some(mut dead) = slot.agent.take() {
            dead.stop();
        }
        guard(&self.labels).clear();
        tracing::warn!(
            endpoint = %self.endpoint,
            attempts = slot.backoff.attempts,
            "the SSH agent is not running; restarting it"
        );
        match self.start(slot) {
            Ok(()) => {
                slot.backoff.started(now);
                Revival::Restarted
            }
            Err(error) => {
                let report = slot.backoff.failed(now, is_persistent(&error));
                tracing::warn!(
                    error = format!("{error:#}"),
                    failures = slot.backoff.failures,
                    retry_in = ?slot.backoff.delay(),
                    "cannot restart the SSH agent"
                );
                Revival::Failed { error, report }
            }
        }
    }

    /// Brings the served keys in line with the vault; decrypting runs on the blocking pool.
    pub async fn refresh(&self, vault: &Arc<Vault>) {
        // Read before the vault state: a lock after this point bumps the epoch, so the keys
        // decrypted below are dropped instead of being served on a locked vault.
        let Some(epoch) = self.running_epoch() else {
            return;
        };
        match key_action(&vault.state()) {
            KeyAction::Clear => self.clear(),
            KeyAction::Serve => {
                let source = Arc::clone(vault);
                let loaded = tokio::task::spawn_blocking(move || load_keys(&source)).await;
                match loaded {
                    Ok(Ok((keys, labels))) => self.replace(epoch, keys, labels),
                    Ok(Err(error)) => tracing::warn!(%error, "cannot read SSH keys from the vault"),
                    Err(error) => tracing::error!(%error, "SSH key task failed"),
                }
            }
        }
    }

    /// The live agent's key epoch; `None` while it is off or dead, and a dead wanted agent wakes
    /// the watchdog, which owns restarting it.
    fn running_epoch(&self) -> Option<u64> {
        let slot = guard(&self.agent);
        let epoch = slot
            .agent
            .as_ref()
            .filter(|agent| agent.is_running())
            .map(SshAgent::key_epoch);
        if epoch.is_none() && slot.wanted {
            tracing::debug!("the SSH agent is not running; its keys wait for the restart");
            self.wake.notify_one();
        }
        epoch
    }

    /// Drops every key at once; also called straight from the state loop on lock, so the keys do
    /// not wait for the key refresh task.
    pub fn clear(&self) {
        if let Some(agent) = guard(&self.agent).agent.as_ref() {
            agent.clear_keys();
        }
        guard(&self.labels).clear();
    }

    /// `epoch` is the agent's key epoch read before `keys` were loaded.
    fn replace(&self, epoch: u64, keys: Vec<AgentKey>, labels: HashMap<String, KeyLabel>) {
        let count = keys.len();
        // Held until the labels are set, so a clear cannot run between the two.
        let slot = guard(&self.agent);
        if let Some(agent) = slot.agent.as_ref() {
            match agent.replace_keys_if(epoch, keys) {
                Ok(true) => {}
                Ok(false) => {
                    tracing::debug!("SSH keys were cleared while loading; dropped the stale set");
                    return;
                }
                Err(error) => {
                    tracing::warn!(%error, "cannot update the SSH agent's keys");
                    return;
                }
            }
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
fn load_keys(vault: &Vault) -> vk_vault::Result<(Vec<AgentKey>, HashMap<String, KeyLabel>)> {
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
                    reprompt: item.reprompt,
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
    use std::path::Path;

    use url::Url;

    use super::*;
    use crate::os::layout;

    #[test]
    fn a_pipe_collision_shows_its_own_advice() {
        let error = anyhow::Error::new(AgentError::PipeTaken {
            service_running: true,
        });

        assert!(start_failure_message(&error).contains("Stop-Service ssh-agent"));
    }

    #[test]
    fn other_start_failures_keep_their_cause() {
        let error = anyhow::anyhow!("socket directory is read-only");

        assert_eq!(
            start_failure_message(&error),
            "The SSH agent could not start: socket directory is read-only"
        );
    }

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
        let control = SshControl::new(layout::ssh_endpoint(Path::new("unused")), approvals);
        control.replace(
            0,
            Vec::new(),
            HashMap::from([(
                "c1".to_owned(),
                KeyLabel {
                    name: "deploy".to_owned(),
                    fingerprint: "SHA256:abc".to_owned(),
                    reprompt: false,
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

    #[cfg(unix)]
    #[tokio::test]
    async fn keys_loaded_before_a_lock_are_not_served_after_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (approvals, _rx) = mpsc::channel(1);
        let control = SshControl::new(Endpoint::path(dir.path().join("agent.sock")), approvals);
        assert!(control.set_enabled(true).expect("agent starts"));
        let epoch = guard(&control.agent)
            .agent
            .as_ref()
            .map(SshAgent::key_epoch)
            .expect("agent");
        control.clear();
        control.replace(
            epoch,
            Vec::new(),
            HashMap::from([(
                "c1".to_owned(),
                KeyLabel {
                    name: "deploy".to_owned(),
                    fingerprint: "SHA256:abc".to_owned(),
                    reprompt: false,
                },
            )]),
        );
        assert_eq!(control.label("c1"), None, "the stale refresh is dropped");
        control.stop();
    }

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn a_first_death_restarts_at_once_and_repeats_back_off_to_the_cap() {
        let start = Instant::now();
        let mut backoff = RestartBackoff::default();
        assert_eq!(backoff.due(start), Due::Now);
        let expected_delays = [5, 10, 20, 40, 80, 160, 320, 600, 600];
        let mut at = start;
        for (attempt, delay) in expected_delays.into_iter().enumerate() {
            if attempt % 2 == 0 {
                backoff.started(at);
            } else {
                backoff.failed(at, false);
            }
            let delay = Duration::from_secs(delay);
            assert_eq!(
                backoff.due(at + delay.saturating_sub(SECOND)),
                Due::In(SECOND),
                "{attempt}"
            );
            assert_eq!(backoff.due(at + delay), Due::Now, "{attempt}");
            at += delay;
        }
    }

    #[test]
    fn the_user_hears_once_on_the_third_failure_in_a_row() {
        let now = Instant::now();
        let mut backoff = RestartBackoff::default();
        assert!(!backoff.failed(now, false));
        assert!(!backoff.failed(now, false));
        assert!(backoff.failed(now, false), "the third failure is reported");
        assert!(!backoff.failed(now, false), "once per streak");
        backoff.started(now);
        assert!(!backoff.failed(now, false), "a success starts a new streak");
        assert!(!backoff.failed(now, false));
        assert!(backoff.failed(now, false));
    }

    #[test]
    fn a_persistent_cause_is_reported_on_the_first_failure() {
        let taken = anyhow::Error::new(AgentError::PipeTaken {
            service_running: false,
        });
        let other_agent = anyhow::Error::new(AgentError::AlreadyRunning(PathBuf::from("a.sock")));
        let io = anyhow::Error::new(AgentError::Io {
            path: PathBuf::from("a.sock"),
            source: std::io::Error::other("disk full"),
        });
        assert!(is_persistent(&taken));
        assert!(is_persistent(&other_agent));
        assert!(!is_persistent(&io), "an I/O error may pass on its own");
        assert!(RestartBackoff::default().failed(Instant::now(), is_persistent(&taken)));
    }

    #[test]
    fn an_agent_that_stayed_up_resets_the_backoff() {
        let start = Instant::now();
        let mut backoff = RestartBackoff::default();
        backoff.failed(start, false);
        backoff.failed(start, false);
        backoff.started(start);
        backoff.running(start + Duration::from_secs(299));
        assert_eq!(
            backoff.due(start + Duration::from_secs(299)),
            Due::Now,
            "the 20 s delay has passed, but the count still stands"
        );
        assert_eq!(backoff.attempts, 3);
        backoff.running(start + Duration::from_secs(300));
        assert_eq!(backoff.attempts, 0);
        assert_eq!(backoff.failures, 0);
        assert_eq!(backoff.due(start + Duration::from_secs(300)), Due::Now);
    }

    /// Ends the listener without going through `SshControl`, as a lost pipe pool or a fatal
    /// accept error would.
    #[cfg(unix)]
    fn kill_listener(control: &SshControl) {
        guard(&control.agent).agent.as_mut().expect("agent").stop();
        assert!(!control.is_running());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_dead_agent_with_the_setting_on_is_restarted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agent.sock");
        let (approvals, _rx) = mpsc::channel(1);
        let control = SshControl::new(Endpoint::path(socket.clone()), approvals);
        assert!(control.set_enabled(true).expect("agent starts"));
        let now = Instant::now();
        assert!(matches!(control.revive(now).0, Revival::Idle));
        kill_listener(&control);

        let (revival, next) = control.revive(now);
        assert!(matches!(revival, Revival::Restarted), "{revival:?}");
        assert_eq!(next, WATCH_INTERVAL);
        assert!(control.is_running());
        assert!(
            socket.exists(),
            "the old handle's stop did not take the new socket"
        );

        kill_listener(&control);
        let (revival, next) = control.revive(now + SECOND);
        assert!(matches!(revival, Revival::Idle), "a second death waits");
        assert_eq!(next, Duration::from_secs(4));
        assert!(matches!(
            control.revive(now + Duration::from_secs(5)).0,
            Revival::Restarted
        ));
        control.stop();
    }

    /// A real death leaves the handle unstopped, so dropping it on restart would remove the
    /// socket file; the runtime it ran on going away ends its listener that way.
    #[cfg(unix)]
    #[test]
    fn a_restart_keeps_the_new_socket_when_the_dead_handle_goes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("agent.sock");
        let (approvals, _rx) = mpsc::channel(1);
        let control = SshControl::new(Endpoint::path(socket.clone()), approvals);
        let first = tokio::runtime::Runtime::new().expect("runtime");
        {
            let _entered = first.enter();
            assert!(control.set_enabled(true).expect("agent starts"));
        }
        drop(first);
        assert!(!control.is_running());

        let second = tokio::runtime::Runtime::new().expect("runtime");
        let _entered = second.enter();
        assert!(matches!(
            control.revive(Instant::now()).0,
            Revival::Restarted
        ));
        assert!(control.is_running());
        assert!(socket.exists());
        control.stop();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn turning_the_agent_off_or_quitting_stops_the_restarts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (approvals, _rx) = mpsc::channel(1);
        let control = SshControl::new(Endpoint::path(dir.path().join("agent.sock")), approvals);
        assert!(control.set_enabled(true).expect("agent starts"));
        kill_listener(&control);
        assert!(!control.set_enabled(false).expect("agent stops"));
        assert!(matches!(control.revive(Instant::now()).0, Revival::Idle));
        assert!(!control.is_running());

        assert!(control.set_enabled(true).expect("agent starts"));
        kill_listener(&control);
        control.stop();
        assert!(matches!(control.revive(Instant::now()).0, Revival::Idle));
        assert!(!control.is_running());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn keys_loaded_from_a_dead_agent_are_not_served_by_its_replacement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (approvals, _rx) = mpsc::channel(1);
        let control = SshControl::new(Endpoint::path(dir.path().join("agent.sock")), approvals);
        assert!(control.set_enabled(true).expect("agent starts"));
        let epoch = control.running_epoch().expect("running");
        kill_listener(&control);
        assert!(matches!(
            control.revive(Instant::now()).0,
            Revival::Restarted
        ));
        control.replace(
            epoch,
            Vec::new(),
            HashMap::from([(
                "c1".to_owned(),
                KeyLabel {
                    name: "deploy".to_owned(),
                    fingerprint: "SHA256:abc".to_owned(),
                    reprompt: false,
                },
            )]),
        );
        assert_eq!(control.label("c1"), None);
        control.stop();
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
        let control = SshControl::new(layout::ssh_endpoint(Path::new("unused")), approvals);
        control.remember("c1".to_owned());
        assert!(control.is_remembered("c1"));
        assert!(!control.is_remembered("c2"));
        control.forget_approvals();
        assert!(!control.is_remembered("c1"));
    }

    #[test]
    fn the_agent_starts_on_the_endpoint_the_layout_names() {
        let endpoint = layout::ssh_endpoint(Path::new("unused"));
        let (approvals, _rx) = mpsc::channel(1);
        let control = SshControl::new(endpoint.clone(), approvals);
        assert_eq!(control.endpoint(), &endpoint);
        let path = agent_path(&endpoint).expect("the layout's endpoint suits this platform");
        assert_eq!(path.to_string_lossy(), endpoint.to_string());
        #[cfg(windows)]
        assert_eq!(path, PathBuf::from(r"\\.\pipe\openssh-ssh-agent"));
    }
}
