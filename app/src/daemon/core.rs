//! The headless daemon: vault, IPC server, SSH agent, lock timer, settings and the UI launcher.
//! The main-thread shell (tray, hotkey, power events) sits on top of it; tests drive it directly.
//!
//! Every method may be called from any thread. Background tasks hold an `Arc<Daemon>` until
//! [`Daemon::shutdown`] aborts them.

mod browser_glue;
mod cli_access;

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::Context;
use tokio::{
    runtime::Handle,
    sync::{Notify, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};
use vk_ipc::{
    ClipboardHost, DaemonEvent, PeerCredentials, ServeOptions, ServerHandle, SshApprovalKind,
    SshDecision, SshPrompt, TouchIdBackend, TypingTarget, UiCommand, UiNotice,
};
use vk_platform::{network::NetworkEvent, power::PowerEvent};
use vk_ssh::{ApprovalKind, ApprovalRequest};
use vk_vault::{SecretStore, Timings, Vault, VaultConfig, VaultService, model::SessionState};

use super::{
    device,
    hotkey_pause::{HotkeyPause, PAUSE_LIMIT},
    launcher::{Hang, Launcher, judge, restart_after_exit},
    lock::{self, Activity, LockCheck, LockWatch},
    routing::Effect,
    site_icons::{IconHost, SiteIcons},
    ssh::{SshControl, purpose},
    target::{FrontmostApp, SystemFrontmost, outside},
    tray_sync::{self, TraySync},
};
use crate::{
    os::{
        ClipboardKeeper, DaemonBiometrics, Keeper, TouchId,
        layout::{SETTINGS_FILE, SSH_SOCKET, UI_SOCKET},
        settings_file::SettingsFile,
    },
    settings::{Settings, SshApproval},
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
    /// Where the Quick Panel's auto-type goes, read when the hotkey or tray asks for the panel.
    pub frontmost: Arc<dyn FrontmostApp>,
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
            frontmost: Arc::new(SystemFrontmost),
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
    hotkey_pause: HotkeyPause,
    activity: Activity,
    lock_wake: Notify,
    was_unlocked: AtomicBool,
    unlocked_once: AtomicBool,
    quitting: AtomicBool,
    ssh: SshControl,
    touch_id: Arc<dyn DaemonBiometrics>,
    clipboard: Arc<dyn ClipboardKeeper>,
    frontmost: Arc<dyn FrontmostApp>,
    /// The account the vault was last seen unlocked for; a change means lock, logout or switch.
    unlocked_as: Mutex<Option<Identity>>,
    /// One Touch ID sheet at a time; concurrent sign requests wait their turn.
    presence: tokio::sync::Mutex<()>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    tray_sync: watch::Sender<TraySync>,
    browser: browser_glue::BrowserState,
    cli_access: cli_access::CliAccessState,
    site_icons: Arc<SiteIcons>,
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
            frontmost,
        } = config;
        let runtime = Handle::current();
        let device = device::load_or_create(&data_dir).context("read the device id")?;
        let mut vault_config = VaultConfig::new(data_dir.clone(), device, runtime.clone());
        vault_config.timings = timings;
        let vault = Arc::new(Vault::open(vault_config, secrets).context("open the vault")?);
        let (events, queue) = mpsc::channel(EVENT_QUEUE);
        let (notices, notices_rx) = mpsc::channel(NOTICE_QUEUE);
        let site_icons = SiteIcons::new({
            let vault = Arc::clone(&vault);
            move || match vault.state() {
                SessionState::Unlocked { server, .. } => Some(server),
                SessionState::Locked { .. } | SessionState::LoggedOut => None,
            }
        });
        let options = match peers {
            Peers::SameExecutable => ServeOptions::new().context("identify this executable")?,
            Peers::AnyOfThisUser => ServeOptions::with_verifier(|_: &PeerCredentials| true),
        }
        .with_notices(notices)
        .with_touch_id(Arc::clone(&touch_id) as Arc<dyn TouchIdBackend>)
        .with_clipboard(Arc::clone(&clipboard) as Arc<dyn ClipboardHost>)
        .with_site_icons(Arc::new(IconHost(Arc::clone(&site_icons))));
        let server =
            vk_ipc::serve_with(data_dir.join(UI_SOCKET), Arc::clone(&vault), queue, options)
                .await
                .context("listen on the UI socket")?;
        let settings = read_settings(data_dir.join(SETTINGS_FILE)).await;
        let (approvals, approvals_rx) = mpsc::channel(APPROVAL_QUEUE);
        let daemon = Arc::new(Self {
            ssh: SshControl::new(data_dir.join(SSH_SOCKET), approvals),
            unlocked_once: AtomicBool::new(false),
            was_unlocked: AtomicBool::new(false),
            settings: watch::Sender::new(Arc::new(settings)),
            hotkey_pause: HotkeyPause::new(PAUSE_LIMIT),
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
            frontmost,
            unlocked_as: Mutex::new(None),
            presence: tokio::sync::Mutex::new(()),
            tasks: Mutex::new(Vec::new()),
            tray_sync: watch::Sender::new(TraySync::default()),
            browser: browser_glue::BrowserState::new(),
            cli_access: cli_access::CliAccessState::default(),
            site_icons,
        });
        if daemon.settings().ssh_agent
            && let Err(error) = daemon.ssh.set_enabled(true)
        {
            tracing::error!(%error, "SSH agent not started");
        }
        daemon.spawn_tasks(notices_rx, approvals_rx);
        daemon.reconcile_browser();
        daemon.reconcile_cli_access();
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

    /// `true` while a Settings shortcut recorder waits for a key: the global hotkeys are off.
    #[must_use]
    pub fn subscribe_hotkey_pause(&self) -> watch::Receiver<bool> {
        self.hotkey_pause.subscribe()
    }

    #[must_use]
    pub fn hotkeys_paused(&self) -> bool {
        self.hotkey_pause.is_paused()
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

    /// The app in front now, for auto-type from the Quick Panel; `None` when it is vaultkeeper
    /// (this daemon or its UI process) or unknown. Call it before the effect that starts or
    /// shows the UI, which comes forward.
    #[must_use]
    pub fn typing_target(&self) -> Option<TypingTarget> {
        // 0 for "no child" matches nothing: `outside` never accepts pid 0.
        let own = [std::process::id(), self.launcher.child_pid().unwrap_or(0)];
        outside(self.frontmost.frontmost(), &own)
    }

    /// [`Daemon::typing_target`] from a Tokio task: the system source may wait for the main
    /// thread, so it runs on a blocking thread.
    async fn typing_target_off_main(self: &Arc<Self>) -> Option<TypingTarget> {
        let daemon = Arc::clone(self);
        match tokio::task::spawn_blocking(move || daemon.typing_target()).await {
            Ok(target) => target,
            Err(error) => {
                tracing::warn!(%error, "cannot read the frontmost app");
                None
            }
        }
    }

    /// Runs one routed effect; a user action, so it also counts as activity for the lock timer.
    pub fn apply(self: &Arc<Self>, effect: Effect) {
        self.activity.touch();
        match effect {
            Effect::Show(command) => self.send_command(command),
            Effect::Lock => self.vault.lock(),
            Effect::Sync => self.sync_from_tray(),
            Effect::SwitchAccount(id) => {
                if let Err(error) = self.vault.switch_account(&id) {
                    tracing::warn!(%error, "account switch failed");
                }
            }
            // The shell quits its event loop and then calls `shutdown`.
            Effect::Quit => {}
        }
    }

    /// A UI process already running toasts the result; none is started just for that.
    fn sync_from_tray(self: &Arc<Self>) {
        if !tray_sync::start(&self.tray_sync) {
            return;
        }
        let daemon = Arc::clone(self);
        drop(self.runtime.spawn(async move {
            let account = daemon.vault.active_account_id();
            let result = daemon.vault.sync().await;
            let error = tray_sync::finish(&daemon.tray_sync, account, &result);
            if daemon.ui_connected() {
                daemon.send_command(UiCommand::SyncFinished { error });
            }
        }));
    }

    #[must_use]
    pub fn tray_sync(&self) -> TraySync {
        self.tray_sync.borrow().clone()
    }

    #[must_use]
    pub fn subscribe_tray_sync(&self) -> watch::Receiver<TraySync> {
        self.tray_sync.subscribe()
    }

    fn send_command(self: &Arc<Self>, command: UiCommand) {
        self.send(|seq| DaemonEvent::Command { seq, command });
    }

    /// Queues the event `numbered` builds with its number, makes sure a UI process is on its
    /// way to read it, and that it answers in time.
    fn send(self: &Arc<Self>, numbered: impl FnOnce(u64) -> DaemonEvent) -> bool {
        let (seq, no_activate) = {
            // Numbering and queueing under one lock keeps the queue in number order with no
            // gaps, which `ui_exited` relies on.
            let mut sent = guard(&self.hang.sent);
            let seq = *sent + 1;
            let event = numbered(seq);
            let no_activate = matches!(
                &event,
                DaemonEvent::BrowserPrompt {
                    prompt: vk_ipc::BrowserPrompt::Save { .. }
                        | vk_ipc::BrowserPrompt::AddAddress { .. }
                        | vk_ipc::BrowserPrompt::Passkey { .. },
                    ..
                }
            );
            if let Err(error) = self.events.try_send(event) {
                tracing::warn!(%error, "UI event dropped");
                return false;
            }
            *sent = seq;
            (seq, no_activate)
        };
        self.ensure_ui(no_activate);
        if self.launcher.can_start() {
            drop(self.runtime.spawn(watch_answer(Arc::clone(self), seq)));
        }
        true
    }

    fn queued_events(&self) -> u64 {
        let queued = self.events.max_capacity() - self.events.capacity();
        u64::try_from(queued).unwrap_or(u64::MAX)
    }

    fn ensure_ui(self: &Arc<Self>, no_activate: bool) {
        if self.quitting.load(Ordering::SeqCst) {
            return;
        }
        let _runtime = self.runtime.enter();
        let daemon = Arc::clone(self);
        self.launcher.ensure(
            self.ui_connected(),
            !self.unlocked_once.load(Ordering::SeqCst),
            no_activate,
            move |ran_for| daemon.ui_exited(ran_for),
        );
    }

    fn ui_exited(self: &Arc<Self>, ran_for: Duration) {
        // What the old UI took from the queue went with it and counts as answered; otherwise
        // its watchers would kill the next UI, which never gets those events.
        let queued = {
            let sent = guard(&self.hang.sent);
            let queued = self.queued_events();
            self.hang
                .acked
                .fetch_max(sent.saturating_sub(queued), Ordering::SeqCst);
            queued
        };
        self.hang.modal.store(false, Ordering::SeqCst);
        self.launcher.exited();
        let quitting = self.quitting.load(Ordering::SeqCst);
        let killed = self.hang.respawn.swap(false, Ordering::SeqCst);
        if restart_after_exit(queued > 0, ran_for, quitting) || (killed && !quitting) {
            tracing::debug!("starting a new UI process after the last one left");
            self.ensure_ui(true);
        }
    }

    async fn reload_settings(self: &Arc<Self>) {
        let fresh = read_settings(self.data_dir.join(SETTINGS_FILE)).await;
        self.apply_settings(fresh);
        self.reload_browser_pairings().await;
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
        if previous.cli_access != current.cli_access {
            self.reconcile_cli_access();
        }
        if browser_settings_changed(&previous, &current) {
            self.reconcile_browser();
        }
    }

    pub fn power_event(&self, event: PowerEvent) {
        match event {
            PowerEvent::WillSleep => {
                self.vault.on_sleep();
                self.forget_browser_approvals();
            }
            PowerEvent::DidWake => {
                self.vault.on_wake();
                // Tokio's timers stop while asleep; the wall clock decides on wake.
                self.lock_wake.notify_one();
                self.clipboard.recheck();
            }
            PowerEvent::ScreenLocked => self.forget_browser_approvals(),
            PowerEvent::ScreenUnlocked => {}
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
        self.stop_browser();
        self.cli_access.stop();
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

    fn on_state(self: &Arc<Self>) {
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
            self.forget_browser_approvals();
            self.site_icons.clear();
        }
        if matches!(self.vault.state(), SessionState::LoggedOut) {
            self.clear_browser_saves();
        }
        let was = self.was_unlocked.swap(unlocked, Ordering::SeqCst);
        if unlocked && !was {
            self.unlocked_once.store(true, Ordering::SeqCst);
            self.activity.touch();
            self.lock_wake.notify_one();
            self.browser_unlocked();
        }
        if !unlocked && was {
            self.ssh.forget_approvals();
            self.ssh.clear();
            // Lets the timer see the lock now, so it notices the next unlock as a new session.
            self.lock_wake.notify_one();
        }
    }

    /// Answers one request of the SSH agent; public so tests can stand in for the agent.
    #[doc(hidden)]
    pub async fn approve(self: &Arc<Self>, request: ApprovalRequest) {
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
                self.send_command(UiCommand::UnlockInTray);
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
        let return_to = self.typing_target_off_main().await;
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
            return_to,
        };
        let (decision_tx, decision) = oneshot::channel();
        if !self.send(|seq| DaemonEvent::SshApproval {
            seq,
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

const fn browser_settings_changed(previous: &Settings, current: &Settings) -> bool {
    previous.browser_integration != current.browser_integration
        || previous.browser_chrome != current.browser_chrome
        || previous.browser_firefox != current.browser_firefox
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
            UiNotice::Alive(seq) => {
                daemon.hang.acked.fetch_max(seq, Ordering::SeqCst);
            }
            UiNotice::Modal(open) => daemon.hang.modal.store(open, Ordering::SeqCst),
            UiNotice::ShortcutRecording(_) | UiNotice::Disconnected => {
                daemon.hotkey_pause.on_notice(notice);
            }
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

/// Event numbers that tell a hung UI process from a slow one.
struct HangWatch {
    after: Duration,
    /// The number of the last event queued for the UI; numbers start at 1.
    sent: Mutex<u64>,
    /// Every event up to this number was answered by some UI's main loop, or went with a UI
    /// that exited.
    acked: AtomicU64,
    modal: AtomicBool,
    /// The watchdog killed the UI: start a new one when it is reaped.
    respawn: AtomicBool,
}

impl HangWatch {
    const fn new(after: Duration) -> Self {
        Self {
            after,
            sent: Mutex::new(0),
            acked: AtomicU64::new(0),
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
