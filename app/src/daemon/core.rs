//! The headless daemon: vault, IPC server, SSH agent, lock timer, settings and the UI launcher.
//! The main-thread shell (tray, hotkey, power events) sits on top of it; tests drive it directly.
//!
//! Every method may be called from any thread. Background tasks hold an `Arc<Daemon>` until
//! [`Daemon::shutdown`] aborts them.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::Context;
use bwl_ipc::{
    ClipboardHost, DaemonEvent, PeerCredentials, ServeOptions, ServerHandle, SshApprovalKind,
    SshDecision, SshPrompt, TouchIdBackend, UiCommand, UiNotice,
};
use bwl_platform::{network::NetworkEvent, power::PowerEvent};
use bwl_ssh::{ApprovalKind, ApprovalRequest};
use bwl_vault::{SecretStore, Timings, Vault, VaultConfig, VaultService, model::SessionState};
use tokio::{
    runtime::Handle,
    sync::{Notify, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};

use super::{
    device,
    launcher::{Hang, Launcher, judge, restart_after_exit},
    lock::{self, Activity, LockCheck, LockWatch},
    routing::Effect,
    ssh::{SshControl, purpose},
};
use crate::{
    os::{
        ClipboardKeeper, DaemonBiometrics, Keeper, TouchId,
        layout::{SETTINGS_FILE, SSH_SOCKET, UI_SOCKET},
        settings_file::SettingsFile,
    },
    settings::{Settings, SshApproval, ThemeChoice},
};

/// Commands and approvals for the UI process; they wait here while none is connected.
const EVENT_QUEUE: usize = 32;
const NOTICE_QUEUE: usize = 16;
const APPROVAL_QUEUE: usize = 8;
/// A UI whose main loop has not got to a command after this long is killed and restarted. Cold
/// starts measure well under a second; the margin covers a loaded machine.
const UI_HANG_AFTER: Duration = Duration::from_secs(20);

/// Who may connect to the IPC socket besides the uid check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peers {
    /// Production: only this executable.
    SameExecutable,
    /// Tests: any process of this user (the test binary plays the UI).
    AnyOfThisUser,
}

pub struct DaemonConfig {
    pub data_dir: PathBuf,
    pub secrets: Arc<dyn SecretStore>,
    pub timings: Timings,
    /// The binary to start as `--ui`; `None` never starts a UI process.
    pub ui_exe: Option<PathBuf>,
    pub peers: Peers,
    /// Enrolment and unlock for the UI, presence checks for SSH approvals.
    pub touch_id: Arc<dyn DaemonBiometrics>,
    /// The pasteboard the UI copies to; cleared on lock, logout, account switch and quit.
    pub clipboard: Arc<dyn ClipboardKeeper>,
    /// How long a started UI may leave a command unanswered before it is killed.
    pub ui_hang_after: Duration,
}

impl DaemonConfig {
    #[must_use]
    pub fn new(data_dir: PathBuf, secrets: Arc<dyn SecretStore>) -> Self {
        Self {
            touch_id: Arc::new(TouchId::new(data_dir.clone())),
            data_dir,
            secrets,
            timings: Timings::default(),
            ui_exe: None,
            peers: Peers::SameExecutable,
            clipboard: Keeper::system(),
            ui_hang_after: UI_HANG_AFTER,
        }
    }
}

pub struct Daemon {
    vault: Arc<Vault>,
    runtime: Handle,
    data_dir: PathBuf,
    events: mpsc::Sender<DaemonEvent>,
    server: Mutex<Option<ServerHandle>>,
    launcher: Launcher,
    hang: HangWatch,
    settings: watch::Sender<Arc<Settings>>,
    activity: Activity,
    lock_wake: Notify,
    was_unlocked: AtomicBool,
    unlocked_once: AtomicBool,
    quitting: AtomicBool,
    ssh: SshControl,
    touch_id: Arc<dyn DaemonBiometrics>,
    clipboard: Arc<dyn ClipboardKeeper>,
    /// The account the vault was last seen unlocked for; a change means lock, logout or switch.
    unlocked_as: Mutex<Option<Identity>>,
    /// One Touch ID sheet at a time; concurrent sign requests wait their turn.
    presence: tokio::sync::Mutex<()>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Daemon {
    /// Opens the vault, binds `ui.sock` and starts the SSH agent if enabled. Must run inside
    /// the Tokio runtime that will keep serving it.
    pub async fn start(config: DaemonConfig) -> anyhow::Result<Arc<Self>> {
        let DaemonConfig {
            data_dir,
            secrets,
            timings,
            ui_exe,
            peers,
            touch_id,
            clipboard,
            ui_hang_after,
        } = config;
        let runtime = Handle::current();
        let device = device::load_or_create(&data_dir).context("read the device id")?;
        let mut vault_config = VaultConfig::new(data_dir.clone(), device, runtime.clone());
        vault_config.timings = timings;
        let vault = Arc::new(Vault::open(vault_config, secrets).context("open the vault")?);
        let (events, queue) = mpsc::channel(EVENT_QUEUE);
        let (notices, notices_rx) = mpsc::channel(NOTICE_QUEUE);
        let options = match peers {
            Peers::SameExecutable => ServeOptions::new().context("identify this executable")?,
            Peers::AnyOfThisUser => ServeOptions::with_verifier(|_: &PeerCredentials| true),
        }
        .with_notices(notices)
        .with_touch_id(Arc::clone(&touch_id) as Arc<dyn TouchIdBackend>)
        .with_clipboard(Arc::clone(&clipboard) as Arc<dyn ClipboardHost>);
        let server =
            bwl_ipc::serve_with(data_dir.join(UI_SOCKET), Arc::clone(&vault), queue, options)
                .await
                .context("listen on the UI socket")?;
        let settings = read_settings(data_dir.join(SETTINGS_FILE)).await;
        let (approvals, approvals_rx) = mpsc::channel(APPROVAL_QUEUE);
        let daemon = Arc::new(Self {
            ssh: SshControl::new(data_dir.join(SSH_SOCKET), approvals),
            unlocked_once: AtomicBool::new(false),
            was_unlocked: AtomicBool::new(false),
            settings: watch::Sender::new(Arc::new(settings)),
            vault,
            runtime,
            data_dir,
            events,
            server: Mutex::new(Some(server)),
            launcher: Launcher::new(ui_exe),
            hang: HangWatch::new(ui_hang_after),
            activity: Activity::new(),
            lock_wake: Notify::new(),
            quitting: AtomicBool::new(false),
            touch_id,
            clipboard,
            unlocked_as: Mutex::new(None),
            presence: tokio::sync::Mutex::new(()),
            tasks: Mutex::new(Vec::new()),
        });
        if daemon.settings().ssh_agent
            && let Err(error) = daemon.ssh.set_enabled(true)
        {
            tracing::error!(%error, "SSH agent not started");
        }
        daemon.spawn_tasks(notices_rx, approvals_rx);
        Ok(daemon)
    }

    fn spawn_tasks(
        self: &Arc<Self>,
        notices: mpsc::Receiver<UiNotice>,
        approvals: mpsc::Receiver<ApprovalRequest>,
    ) {
        let tasks = [
            self.runtime.spawn(notices_loop(Arc::clone(self), notices)),
            self.runtime
                .spawn(state_loop(Arc::clone(self), self.vault.changes())),
            self.runtime.spawn(ssh_keys_loop(
                Arc::clone(self),
                self.vault.ssh_key_changes(),
            )),
            self.runtime
                .spawn(approvals_loop(Arc::clone(self), approvals)),
            self.runtime.spawn(lock_timer(Arc::clone(self))),
        ];
        guard(&self.tasks).extend(tasks);
    }

    #[must_use]
    pub const fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    #[must_use]
    pub fn settings(&self) -> Arc<Settings> {
        Arc::clone(&self.settings.borrow())
    }

    /// Fires whenever the settings the daemon uses were re-read (hotkey, theme for the tray).
    #[must_use]
    pub fn subscribe_settings(&self) -> watch::Receiver<Arc<Settings>> {
        self.settings.subscribe()
    }

    #[must_use]
    pub fn ui_connected(&self) -> bool {
        guard(&self.server)
            .as_ref()
            .is_some_and(ServerHandle::is_ui_connected)
    }

    #[must_use]
    pub fn ssh_agent_running(&self) -> bool {
        self.ssh.is_running()
    }

    #[must_use]
    pub fn ssh_socket(&self) -> &Path {
        self.ssh.socket()
    }

    /// Runs one routed effect; a user action, so it also counts as activity for the lock timer.
    pub fn apply(self: &Arc<Self>, effect: Effect) {
        self.activity.touch();
        match effect {
            Effect::Show(command) => {
                self.send(DaemonEvent::Command(command));
            }
            Effect::Lock => self.vault.lock(),
            Effect::Sync => self.vault.request_sync(),
            Effect::SwitchAccount(id) => {
                if let Err(error) = self.vault.switch_account(&id) {
                    tracing::warn!(%error, "account switch failed");
                }
            }
            Effect::SetTheme(theme) => self.set_theme(theme),
            // The shell quits its event loop and then calls `shutdown`.
            Effect::Quit => {}
        }
    }

    /// Queues an event for the UI and makes sure a UI process is on its way to read it, and
    /// answers it in time.
    fn send(self: &Arc<Self>, event: DaemonEvent) -> bool {
        if let Err(error) = self.events.try_send(event) {
            tracing::warn!(%error, "UI event dropped");
            return false;
        }
        let seq = self.hang.delivered.fetch_add(1, Ordering::SeqCst) + 1;
        self.ensure_ui();
        if self.launcher.can_start() {
            drop(self.runtime.spawn(watch_answer(Arc::clone(self), seq)));
        }
        true
    }

    /// The UI's main loop got through its first `handled` events.
    fn ui_alive(&self, handled: u64) {
        let base = self.hang.base.load(Ordering::SeqCst);
        self.hang
            .acked
            .fetch_max(base.saturating_add(handled), Ordering::SeqCst);
    }

    fn queued_events(&self) -> u64 {
        let queued = self.events.max_capacity() - self.events.capacity();
        u64::try_from(queued).unwrap_or(u64::MAX)
    }

    fn ensure_ui(self: &Arc<Self>) {
        if self.quitting.load(Ordering::SeqCst) {
            return;
        }
        let _runtime = self.runtime.enter();
        let daemon = Arc::clone(self);
        self.launcher.ensure(
            self.ui_connected(),
            !self.unlocked_once.load(Ordering::SeqCst),
            move |ran_for| daemon.ui_exited(ran_for),
        );
    }

    fn ui_exited(self: &Arc<Self>, ran_for: Duration) {
        // What the old UI received counts as answered; the next one counts from here.
        let queued = self.queued_events();
        let base = self
            .hang
            .delivered
            .load(Ordering::SeqCst)
            .saturating_sub(queued);
        self.hang.base.store(base, Ordering::SeqCst);
        self.hang.acked.fetch_max(base, Ordering::SeqCst);
        self.hang.modal.store(false, Ordering::SeqCst);
        self.launcher.exited();
        let quitting = self.quitting.load(Ordering::SeqCst);
        let killed = self.hang.respawn.swap(false, Ordering::SeqCst);
        if restart_after_exit(queued > 0, ran_for, quitting) || (killed && !quitting) {
            tracing::debug!("starting a new UI process after the last one left");
            self.ensure_ui();
        }
    }

    fn set_theme(self: &Arc<Self>, theme: ThemeChoice) {
        let path = self.data_dir.join(SETTINGS_FILE);
        // Re-read first: the UI may have saved other changes since the daemon last looked.
        let mut fresh = SettingsFile::read(&path);
        fresh.theme = theme;
        if let Err(error) = SettingsFile::write(&path, &fresh) {
            tracing::warn!(%error, "theme not saved");
            return;
        }
        self.apply_settings(fresh);
        if self.ui_connected() {
            self.send(DaemonEvent::Command(UiCommand::ReloadSettings));
        }
    }

    async fn reload_settings(self: &Arc<Self>) {
        let fresh = read_settings(self.data_dir.join(SETTINGS_FILE)).await;
        self.apply_settings(fresh);
    }

    fn apply_settings(self: &Arc<Self>, fresh: Settings) {
        let previous = self.settings.send_replace(Arc::new(fresh));
        let current = self.settings();
        if previous.ssh_agent != current.ssh_agent {
            let _runtime = self.runtime.enter();
            match self.ssh.set_enabled(current.ssh_agent) {
                // `ssh_key_changes` fires only on the next vault change, so load the keys now.
                Ok(true) => {
                    let daemon = Arc::clone(self);
                    drop(
                        self.runtime
                            .spawn(async move { daemon.ssh.refresh(&daemon.vault).await }),
                    );
                }
                Ok(false) => {}
                Err(error) => tracing::error!(%error, "cannot start the SSH agent"),
            }
        }
        if current.ssh_approval == SshApproval::Always {
            self.ssh.forget_approvals();
        }
        if previous.lock_timeout != current.lock_timeout {
            self.lock_wake.notify_one();
        }
    }

    pub fn power_event(&self, event: PowerEvent) {
        match event {
            PowerEvent::WillSleep => self.vault.on_sleep(),
            PowerEvent::DidWake => {
                self.vault.on_wake();
                // Tokio's timers stop while asleep; the wall clock decides on wake.
                self.lock_wake.notify_one();
                self.clipboard.recheck();
            }
            PowerEvent::ScreenLocked | PowerEvent::ScreenUnlocked => {}
        }
        if lock::locks_on(event, self.settings().lock_on_sleep) {
            tracing::info!(?event, "locking on sleep / screen lock");
            self.vault.lock();
        }
    }

    /// A usable path (new connection or another interface) lets an offline vault retry now.
    pub fn network_event(&self, event: NetworkEvent) {
        if retries_on(event) {
            self.vault.on_network_change();
        }
    }

    pub fn note_activity(&self) {
        self.activity.touch();
    }

    /// Tray Quit and SIGTERM: lock, clear our copy, stop the agent, tell the UI to exit, remove
    /// the sockets.
    pub async fn shutdown(&self) {
        self.quitting.store(true, Ordering::SeqCst);
        self.vault.lock();
        self.clipboard.clear_if_ours();
        self.ssh.stop();
        let server = guard(&self.server).take();
        if let Some(server) = server {
            server.shutdown().await;
        }
        // A UI that is hung never reads the Shutdown it was just sent.
        self.launcher.kill();
        for task in guard(&self.tasks).drain(..) {
            task.abort();
        }
    }

    fn on_state(&self) {
        let identity = match self.vault.state() {
            SessionState::Unlocked { server, email } => Some(Identity { server, email }),
            SessionState::Locked { .. } | SessionState::LoggedOut => None,
        };
        let unlocked = identity.is_some();
        let previous = std::mem::replace(&mut *guard(&self.unlocked_as), identity.clone());
        // `changes` is a watch: lock + switch + unlock may arrive as one Unlocked → Unlocked.
        if left_session(previous.as_ref(), identity.as_ref()) {
            self.clipboard.clear_if_ours();
            self.ssh.forget_approvals();
        }
        let was = self.was_unlocked.swap(unlocked, Ordering::SeqCst);
        if unlocked && !was {
            self.unlocked_once.store(true, Ordering::SeqCst);
            self.activity.touch();
            self.lock_wake.notify_one();
        }
        if !unlocked && was {
            self.ssh.forget_approvals();
            self.ssh.clear();
            // Lets the timer see the lock now, so it notices the next unlock as a new session.
            self.lock_wake.notify_one();
        }
    }

    async fn approve(self: &Arc<Self>, request: ApprovalRequest) {
        let ApprovalRequest { kind, mut reply } = request;
        let approved = match kind {
            ApprovalKind::List => self.approve_list(&mut reply).await,
            ApprovalKind::Sign {
                cipher_id,
                process_name,
                is_forwarding,
                namespace,
            } => {
                let prompt = SignPrompt {
                    cipher_id,
                    process: process_name,
                    purpose: purpose(namespace.as_deref(), is_forwarding),
                };
                self.approve_sign(prompt, &mut reply).await
            }
        };
        if reply.send(approved).is_err() {
            tracing::debug!("the SSH agent gave up on the approval");
        }
    }

    /// The agent asks only while it holds no keys (before the first unlock, after a lock, log
    /// out or switch). While locked, unlocking is the consent; logged out there is nothing to
    /// unlock, so the empty list is answered without a prompt.
    async fn approve_list(self: &Arc<Self>, reply: &mut oneshot::Sender<bool>) -> bool {
        match self.vault.state() {
            SessionState::LoggedOut => true,
            // Just unlocked, before the key refresh ran: load them so the list is not empty.
            SessionState::Unlocked { .. } => {
                self.ssh.refresh(&self.vault).await;
                true
            }
            SessionState::Locked { .. } => {
                self.send(DaemonEvent::Command(UiCommand::UnlockInTray));
                self.wait_unlocked(reply).await
            }
        }
    }

    async fn wait_unlocked(&self, reply: &mut oneshot::Sender<bool>) -> bool {
        let mut changes = self.vault.changes();
        loop {
            if matches!(self.vault.state(), SessionState::Unlocked { .. }) {
                // Load the keys before the agent answers the list, instead of racing the
                // `ssh_key_changes` loop.
                self.ssh.refresh(&self.vault).await;
                return true;
            }
            tokio::select! {
                moved = changes.changed() => if moved.is_err() { return false },
                () = reply.closed() => return false,
            }
        }
    }

    async fn approve_sign(
        self: &Arc<Self>,
        request: SignPrompt,
        reply: &mut oneshot::Sender<bool>,
    ) -> bool {
        let Some(cipher_id) = request.cipher_id else {
            return false;
        };
        let unlocked = matches!(self.vault.state(), SessionState::Unlocked { .. });
        if unlocked && self.ssh.is_remembered(&cipher_id) {
            return true;
        }
        let label = self.ssh.label(&cipher_id);
        let prompt = SshPrompt {
            kind: SshApprovalKind::Sign,
            process: request
                .process
                .unwrap_or_else(|| "an unknown process".to_owned()),
            pid: None,
            key_name: label
                .as_ref()
                .map_or_else(|| "SSH key".to_owned(), |label| label.name.clone()),
            fingerprint: label.map(|label| label.fingerprint).unwrap_or_default(),
            purpose: request.purpose,
        };
        let (decision_tx, decision) = oneshot::channel();
        if !self.send(DaemonEvent::SshApproval {
            prompt,
            reply: decision_tx,
        }) {
            return false;
        }
        let decision = tokio::select! {
            decision = decision => decision.unwrap_or(SshDecision::DENY),
            () = reply.closed() => SshDecision::DENY,
        };
        if !decision.approved {
            return false;
        }
        // The UI's "approved" alone cannot sign: with the setting on, the daemon asks for the
        // finger itself, for this request only.
        if self.settings().ssh_touch_id && !self.confirm_presence(reply).await {
            return false;
        }
        // Keys are cleared on lock, but a lock may land while the prompt is up.
        if !matches!(self.vault.state(), SessionState::Unlocked { .. }) {
            tracing::warn!("SSH approval arrived while the vault is locked; denied");
            return false;
        }
        if decision.remember && self.settings().ssh_approval == SshApproval::RememberUntilLock {
            self.ssh.remember(cipher_id);
        }
        true
    }

    /// Touch ID for one approved sign request. Gives up when the agent stops waiting.
    async fn confirm_presence(&self, reply: &mut oneshot::Sender<bool>) -> bool {
        let _turn = tokio::select! {
            turn = self.presence.lock() => turn,
            () = reply.closed() => return false,
        };
        if reply.is_closed() {
            return false;
        }
        let touch_id = Arc::clone(&self.touch_id);
        let checked =
            tokio::task::spawn_blocking(move || touch_id.authenticate("approve an SSH signature"))
                .await;
        match checked {
            Ok(Ok(())) => true,
            Ok(Err(failure)) => {
                tracing::info!(%failure, "Touch ID refused the SSH approval");
                false
            }
            Err(error) => {
                tracing::error!(%error, "Touch ID task failed");
                false
            }
        }
    }
}

/// Losing the network needs nothing: the next request finds out on its own.
const fn retries_on(event: NetworkEvent) -> bool {
    matches!(event, NetworkEvent::Usable)
}

/// Who the vault is unlocked for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    server: url::Url,
    email: String,
}

/// Whether the session that was unlocked ended: locked, logged out or switched to another account.
fn left_session(previous: Option<&Identity>, now: Option<&Identity>) -> bool {
    previous.is_some() && previous != now
}

struct SignPrompt {
    cipher_id: Option<String>,
    process: Option<String>,
    purpose: Option<String>,
}

async fn read_settings(path: PathBuf) -> Settings {
    tokio::task::spawn_blocking(move || SettingsFile::read(&path))
        .await
        .unwrap_or_default()
}

async fn notices_loop(daemon: Arc<Daemon>, mut notices: mpsc::Receiver<UiNotice>) {
    while let Some(notice) = notices.recv().await {
        match notice {
            UiNotice::SettingsChanged => daemon.reload_settings().await,
            UiNotice::Activity => daemon.activity.touch(),
            UiNotice::Alive(handled) => daemon.ui_alive(handled),
            UiNotice::Modal(open) => daemon.hang.modal.store(open, Ordering::SeqCst),
        }
    }
}

async fn state_loop(daemon: Arc<Daemon>, mut changes: watch::Receiver<u64>) {
    loop {
        daemon.on_state();
        if changes.changed().await.is_err() {
            return;
        }
    }
}

async fn ssh_keys_loop(daemon: Arc<Daemon>, mut changes: watch::Receiver<u64>) {
    loop {
        daemon.ssh.refresh(&daemon.vault).await;
        if changes.changed().await.is_err() {
            return;
        }
    }
}

/// Each request waits on the user in its own task; they all end with this loop.
async fn approvals_loop(daemon: Arc<Daemon>, mut approvals: mpsc::Receiver<ApprovalRequest>) {
    let mut waiting = JoinSet::new();
    loop {
        tokio::select! {
            request = approvals.recv() => match request {
                Some(request) => {
                    let daemon = Arc::clone(&daemon);
                    waiting.spawn(async move { daemon.approve(request).await });
                }
                None => return,
            },
            Some(joined) = waiting.join_next() => {
                if let Err(error) = joined && error.is_panic() {
                    tracing::error!(%error, "SSH approval task panicked");
                }
            }
        }
    }
}

/// Sleeps until the lock deadline, never on a periodic tick. Only `lock_wake` makes it look
/// early (unlock, settings change, wake from sleep), always after the activity it needs was
/// recorded; it does not follow vault changes itself, which raced the state loop's activity
/// update and could lock right after an unlock.
async fn lock_timer(daemon: Arc<Daemon>) {
    let mut watch = LockWatch::default();
    loop {
        let unlocked = matches!(daemon.vault.state(), SessionState::Unlocked { .. });
        let check = watch.look(
            unlocked,
            daemon.settings().lock_timeout,
            &daemon.activity,
            SystemTime::now(),
        );
        let wait = match check {
            LockCheck::LockNow => {
                tracing::info!("lock timeout reached");
                daemon.vault.lock();
                watch.locked();
                continue;
            }
            LockCheck::After(wait) => Some(wait),
            LockCheck::Never => None,
        };
        tokio::select! {
            () = sleep_or_forever(wait) => {}
            () = daemon.lock_wake.notified() => {}
        }
    }
}

/// Kills the UI when its main loop has not got to event `seq` in time, then a new one starts.
async fn watch_answer(daemon: Arc<Daemon>, seq: u64) {
    loop {
        tokio::time::sleep(daemon.hang.after).await;
        if daemon.quitting.load(Ordering::SeqCst) {
            return;
        }
        let acked = daemon.hang.acked.load(Ordering::SeqCst);
        match judge(acked, seq, daemon.hang.modal.load(Ordering::SeqCst)) {
            Hang::Answered => return,
            Hang::Wait => {}
            Hang::Kill => {
                daemon.hang.respawn.store(true, Ordering::SeqCst);
                if !daemon.launcher.kill() {
                    daemon.hang.respawn.store(false, Ordering::SeqCst);
                }
                return;
            }
        }
    }
}

/// Counts that tell a hung UI process from a slow one.
struct HangWatch {
    after: Duration,
    /// Events queued for the UI since the daemon started.
    delivered: AtomicU64,
    /// Events some UI's main loop got through (or that went with a UI that exited).
    acked: AtomicU64,
    /// `delivered` minus what was still queued when the last UI exited: where the running UI's
    /// own count starts.
    base: AtomicU64,
    modal: AtomicBool,
    /// The watchdog killed the UI: start a new one when it is reaped.
    respawn: AtomicBool,
}

impl HangWatch {
    const fn new(after: Duration) -> Self {
        Self {
            after,
            delivered: AtomicU64::new(0),
            acked: AtomicU64::new(0),
            base: AtomicU64::new(0),
            modal: AtomicBool::new(false),
            respawn: AtomicBool::new(false),
        }
    }
}

async fn sleep_or_forever(wait: Option<Duration>) {
    match wait {
        Some(wait) => tokio::time::sleep(wait).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who(email: &str) -> Identity {
        Identity {
            server: url::Url::parse("https://vault.example").expect("url"),
            email: email.to_owned(),
        }
    }

    #[test]
    fn only_a_usable_network_triggers_a_retry() {
        assert!(retries_on(NetworkEvent::Usable));
        assert!(!retries_on(NetworkEvent::Unusable));
    }

    #[test]
    fn lock_logout_and_switch_end_the_session_but_unlock_does_not() {
        let alice = who("alice@example.com");
        let bob = who("bob@example.com");
        assert!(left_session(Some(&alice), None), "lock or logout");
        assert!(
            left_session(Some(&alice), Some(&bob)),
            "switch seen as one tick"
        );
        assert!(!left_session(None, Some(&alice)), "unlock");
        assert!(!left_session(Some(&alice), Some(&alice)), "same session");
        assert!(!left_session(None, None), "stays locked");
    }
}
