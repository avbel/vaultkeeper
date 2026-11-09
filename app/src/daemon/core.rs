//! The headless daemon: vault, IPC server, SSH agent, lock timer, settings and the UI launcher.
//! The main-thread shell (tray, hotkey, power events) sits on top of it; tests drive it directly.
//!
//! Every method may be called from any thread. Background tasks hold an `Arc<Daemon>` until
//! [`Daemon::shutdown`] aborts them.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::Context;
use bwl_ipc::{
    DaemonEvent, PeerCredentials, ServeOptions, ServerHandle, SshApprovalKind, SshDecision,
    SshPrompt, TouchIdBackend, UiCommand, UiNotice,
};
use bwl_platform::power::PowerEvent;
use bwl_ssh::{ApprovalKind, ApprovalRequest};
use bwl_vault::{SecretStore, Timings, Vault, VaultConfig, VaultService, model::SessionState};
use tokio::{
    runtime::Handle,
    sync::{Notify, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};

use super::{
    device,
    launcher::{Launcher, restart_after_exit},
    lock::{self, Activity, LockCheck},
    routing::Effect,
    ssh::{SshControl, purpose},
};
use crate::{
    os::{
        DaemonBiometrics, TouchId,
        layout::{SETTINGS_FILE, SSH_SOCKET, UI_SOCKET},
        settings_file::SettingsFile,
    },
    settings::{Settings, SshApproval, ThemeChoice},
};

/// Commands and approvals for the UI process; they wait here while none is connected.
const EVENT_QUEUE: usize = 32;
const NOTICE_QUEUE: usize = 16;
const APPROVAL_QUEUE: usize = 8;

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
    settings: watch::Sender<Arc<Settings>>,
    activity: Activity,
    lock_wake: Notify,
    was_unlocked: AtomicBool,
    unlocked_once: AtomicBool,
    quitting: AtomicBool,
    ssh: SshControl,
    touch_id: Arc<dyn DaemonBiometrics>,
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
        .with_touch_id(Arc::clone(&touch_id) as Arc<dyn TouchIdBackend>);
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
            activity: Activity::new(),
            lock_wake: Notify::new(),
            quitting: AtomicBool::new(false),
            touch_id,
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

    /// Queues an event for the UI and makes sure a UI process is on its way to read it.
    fn send(self: &Arc<Self>, event: DaemonEvent) -> bool {
        if let Err(error) = self.events.try_send(event) {
            tracing::warn!(%error, "UI event dropped");
            return false;
        }
        self.ensure_ui();
        true
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
        self.launcher.exited();
        let queued = self.events.capacity() < self.events.max_capacity();
        if restart_after_exit(queued, ran_for, self.quitting.load(Ordering::SeqCst)) {
            tracing::debug!("commands arrived while the UI was leaving; starting a new one");
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
            }
            PowerEvent::ScreenLocked | PowerEvent::ScreenUnlocked => {}
        }
        if lock::locks_on(event, self.settings().lock_timeout) {
            tracing::info!(?event, "locking on sleep / screen lock");
            self.vault.lock();
        }
    }

    pub fn note_activity(&self) {
        self.activity.touch();
    }

    /// Tray Quit and SIGTERM: lock, stop the agent, tell the UI to exit, remove the sockets.
    pub async fn shutdown(&self) {
        self.quitting.store(true, Ordering::SeqCst);
        self.vault.lock();
        self.ssh.stop();
        let server = guard(&self.server).take();
        if let Some(server) = server {
            server.shutdown().await;
        }
        for task in guard(&self.tasks).drain(..) {
            task.abort();
        }
    }

    fn on_state(&self) {
        let unlocked = matches!(self.vault.state(), SessionState::Unlocked { .. });
        let was = self.was_unlocked.swap(unlocked, Ordering::SeqCst);
        if unlocked && !was {
            self.unlocked_once.store(true, Ordering::SeqCst);
            self.activity.touch();
            self.lock_wake.notify_one();
        }
        if !unlocked && was {
            self.ssh.forget_approvals();
            self.ssh.clear();
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

/// Sleeps until the lock deadline, never on a periodic tick; settings changes, wake-ups and
/// vault changes make it look again.
async fn lock_timer(daemon: Arc<Daemon>) {
    let mut changes = daemon.vault.changes();
    loop {
        let unlocked = matches!(daemon.vault.state(), SessionState::Unlocked { .. });
        let check = if unlocked {
            lock::check(
                daemon.settings().lock_timeout,
                daemon.activity.last(),
                SystemTime::now(),
            )
        } else {
            LockCheck::Never
        };
        let wait = match check {
            LockCheck::LockNow => {
                tracing::info!("lock timeout reached");
                daemon.vault.lock();
                continue;
            }
            LockCheck::After(wait) => Some(wait),
            LockCheck::Never => None,
        };
        tokio::select! {
            () = sleep_or_forever(wait) => {}
            () = daemon.lock_wake.notified() => {}
            moved = changes.changed() => if moved.is_err() { return },
        }
    }
}

async fn sleep_or_forever(wait: Option<Duration>) {
    match wait {
        Some(wait) => tokio::time::sleep(wait).await,
        None => std::future::pending().await,
    }
}
