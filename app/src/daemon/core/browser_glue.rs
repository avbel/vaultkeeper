//! Joins the browser listener and its sessions to the daemon's UI, Touch ID, clipboard and
//! settings. The protocol and the flows live in `daemon::browser`; this file only owns lifetimes.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::{
    sync::{Mutex as AsyncMutex, Notify, watch},
    task::JoinHandle,
};
use vk_ipc::{
    BrowserPrompt, BrowserReply, DaemonEvent, TypingTarget, UiCommand,
    browser::protocol::{AppView, KnownBrowser, State, Theme},
};
use vk_vault::{VaultService, model::SessionState, uri_match::DefaultMatch};

use super::{Daemon, guard};
use crate::{
    daemon::browser::{
        activity::ActivityLog,
        control::BrowserControl,
        dispatch::{BrowserHost, Candidate, FillRecord, RealFills, serve},
        limits::Limits,
        manifests::{self, ExtensionIds, ManifestBrowser, Outcome},
        pairing::PairingStore,
        save::{Outcome as SaveOutcome, SaveError, SaveManager, SaveSettings},
    },
    os::layout::{BROWSER_PAIRINGS_FILE, BROWSER_SOCKET},
    settings::{BrowserMatch, Settings, ThemeChoice},
};

/// Expired save candidates are wiped within this long even when no request arrives.
const SAVE_SWEEP: Duration = Duration::from_secs(60);
/// A compromised extension must not turn reconnects into a stream of pairing windows.
const PAIR_PROMPTS_PER_MINUTE: usize = 3;

pub(super) struct BrowserState {
    run: std::sync::Mutex<Option<JoinHandle<()>>>,
    store: std::sync::Mutex<Option<Arc<AsyncMutex<PairingStore>>>>,
    /// Moves whenever remembered approvals must be forgotten.
    epoch: std::sync::atomic::AtomicU64,
    /// Pushed to every session on a vault change or a pairing reload.
    changes: watch::Sender<u64>,
    pairings_changed: Notify,
    sessions: std::sync::Mutex<HashMap<&'static str, usize>>,
    sessions_changed: watch::Sender<u64>,
    saves: Arc<AsyncMutex<SaveManager>>,
    /// Moves on every stop, ending save work started for the listener that went away.
    stopped: watch::Sender<u64>,
    /// The run task of the last stop, awaited before the next bind so its socket cleanup cannot
    /// remove the new socket.
    stopping: std::sync::Mutex<Option<JoinHandle<()>>>,
    log: ActivityLog,
    limits: std::sync::Mutex<HashMap<[u8; 65], Arc<std::sync::Mutex<Limits>>>>,
    pair_prompts: std::sync::Mutex<VecDeque<Instant>>,
}

impl BrowserState {
    pub(super) fn new() -> Self {
        Self {
            run: std::sync::Mutex::new(None),
            store: std::sync::Mutex::new(None),
            epoch: std::sync::atomic::AtomicU64::new(0),
            changes: watch::Sender::new(0),
            pairings_changed: Notify::new(),
            sessions: std::sync::Mutex::new(HashMap::new()),
            sessions_changed: watch::Sender::new(0),
            saves: Arc::new(AsyncMutex::new(SaveManager::default())),
            stopped: watch::Sender::new(0),
            stopping: std::sync::Mutex::new(None),
            log: ActivityLog::new(),
            limits: std::sync::Mutex::new(HashMap::new()),
            pair_prompts: std::sync::Mutex::new(VecDeque::new()),
        }
    }
}

const fn default_match(setting: BrowserMatch) -> DefaultMatch {
    match setting {
        BrowserMatch::Domain => DefaultMatch::Domain,
        BrowserMatch::Host => DefaultMatch::Host,
    }
}

/// The folder holding every app's data, as the Settings window sees it: the parent of ours.
fn app_support(data_dir: &std::path::Path) -> PathBuf {
    if cfg!(feature = "vw-it") {
        return data_dir.join("app-support");
    }
    data_dir.parent().map_or_else(
        || data_dir.join("app-support"),
        std::path::Path::to_path_buf,
    )
}

fn enabled_browsers(settings: &Settings) -> Vec<ManifestBrowser> {
    if !settings.browser_integration {
        return Vec::new();
    }
    [
        (settings.browser_chrome, ManifestBrowser::Chrome),
        (settings.browser_firefox, ManifestBrowser::Firefox),
    ]
    .into_iter()
    .filter_map(|(on, browser)| on.then_some(browser))
    .collect()
}

impl Daemon {
    /// Brings the listener and the manifests in line with the settings. Safe to call on every
    /// settings change: it does nothing when nothing relevant moved.
    pub(super) fn reconcile_browser(self: &Arc<Self>) {
        let wanted = self.settings().browser_integration;
        let running = guard(&self.browser.run).is_some();
        if wanted && !running {
            self.start_browser();
        } else if !wanted && running {
            self.stop_browser();
        }
        self.sync_manifests();
    }

    pub(super) fn stop_browser(&self) {
        if let Some(task) = guard(&self.browser.run).take() {
            task.abort();
            *guard(&self.browser.stopping) = Some(task);
        }
        *guard(&self.browser.store) = None;
        guard(&self.browser.sessions).clear();
        self.forget_browser_approvals();
        self.browser
            .stopped
            .send_modify(|value| *value = value.wrapping_add(1));
        // Remembering candidates for a listener that is off would keep passwords for nothing.
        let saves = Arc::clone(&self.browser.saves);
        drop(self.runtime.spawn(async move {
            saves.lock().await.clear();
        }));
    }

    fn start_browser(self: &Arc<Self>) {
        let daemon = Arc::clone(self);
        let previous = guard(&self.browser.stopping).take();
        let task = self.runtime.spawn(async move {
            if let Some(previous) = previous {
                let _ = previous.await;
            }
            let control = match BrowserControl::start(
                daemon.data_dir.join(BROWSER_SOCKET),
                daemon.data_dir.join(BROWSER_PAIRINGS_FILE),
            )
            .await
            {
                Ok(control) => control,
                Err(error) => {
                    tracing::warn!(%error, "browser integration not started");
                    return;
                }
            };
            *guard(&daemon.browser.store) = Some(control.store());
            let fills = Arc::new(RealFills {
                vault: Arc::clone(&daemon.vault),
            });
            let host = Arc::new(DaemonBrowser(Arc::clone(&daemon)));
            let sessions = Arc::clone(&daemon);
            let run = control.run(move |connection, store| {
                sessions.sync_manifests();
                serve(connection, store, Arc::clone(&fills), Arc::clone(&host))
            });
            tokio::select! {
                () = run => {}
                () = forward_changes(Arc::clone(&daemon)) => {}
            }
        });
        *guard(&self.browser.run) = Some(task);
    }

    /// Installs the manifests of the enabled browsers, restores tampered ones and removes the
    /// rest, off the runtime threads because it touches the disk.
    pub(super) fn sync_manifests(self: &Arc<Self>) {
        let enabled = enabled_browsers(&self.settings());
        let root = app_support(&self.data_dir);
        let daemon = Arc::clone(self);
        drop(self.runtime.spawn_blocking(move || {
            for browser in ManifestBrowser::ALL {
                if !enabled.contains(&browser)
                    && let Err(error) = manifests::remove(&root, browser)
                {
                    tracing::warn!(%error, browser = browser.display_name(), "cannot remove the native messaging manifest");
                }
            }
            if enabled.is_empty() {
                return;
            }
            let exe = match manifests::current_exe_path() {
                Ok(exe) => exe,
                Err(error) => {
                    tracing::warn!(%error, "cannot resolve the executable for the manifests");
                    return;
                }
            };
            for (browser, result) in
                manifests::check_and_restore(&root, &enabled, &exe, &ExtensionIds::DEFAULT)
            {
                match result {
                    Ok(Outcome::Restored) => {
                        tracing::warn!(browser = browser.display_name(), "native messaging manifest restored");
                        daemon.browser.log.record(&format!(
                            "manifest_restored browser={}",
                            browser.display_name()
                        ));
                        daemon.send_command(UiCommand::Toast {
                            text: manifests::restored_toast(browser),
                            error: true,
                        });
                    }
                    Ok(Outcome::Written | Outcome::Unchanged | Outcome::NotInstalled) => {}
                    Err(error) => {
                        tracing::warn!(%error, browser = browser.display_name(), "cannot write the native messaging manifest");
                    }
                }
            }
        }));
    }

    /// Lock, logout, account switch, sleep and screen lock end every remembered approval.
    pub(super) fn forget_browser_approvals(&self) {
        self.browser.epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Waits for an open save prompt to finish rather than skipping the wipe.
    pub(super) fn clear_browser_saves(self: &Arc<Self>) {
        let daemon = Arc::clone(self);
        drop(self.runtime.spawn(async move {
            daemon.browser.saves.lock().await.clear();
        }));
    }

    /// Picks up removed pairings written by the Settings window and drops their sessions.
    pub(super) async fn reload_browser_pairings(&self) {
        let store = guard(&self.browser.store).clone();
        let Some(store) = store else {
            return;
        };
        let reloaded = store.lock().await.reload();
        match reloaded {
            Ok(()) => {
                self.browser.log.record("pairings reloaded");
                self.browser.pairings_changed.notify_one();
            }
            Err(error) => tracing::warn!(%error, "cannot reload browser pairings"),
        }
    }

    /// The tray line, empty when no paired browser is connected.
    #[must_use]
    pub fn browser_label(&self) -> String {
        let mut names: Vec<_> = guard(&self.browser.sessions).keys().copied().collect();
        if names.is_empty() {
            return String::new();
        }
        names.sort_unstable();
        format!("Browser connected: {}", names.join(", "))
    }

    #[must_use]
    pub fn subscribe_browser_sessions(&self) -> watch::Receiver<u64> {
        self.browser.sessions_changed.subscribe()
    }

    /// Evaluates the candidates held while the vault was locked.
    pub(super) fn browser_unlocked(self: &Arc<Self>) {
        let daemon = Arc::clone(self);
        drop(self.runtime.spawn(async move {
            let Some(store) = guard(&daemon.browser.store).clone() else {
                return;
            };
            let settings = daemon.save_settings().await;
            let host = DaemonBrowser(Arc::clone(&daemon));
            let results = daemon
                .browser
                .saves
                .lock()
                .await
                .on_unlocked(&daemon.vault, &settings, &*store, |prompt| {
                    host.prompt(prompt)
                })
                .await;
            for result in results {
                daemon.report_save(result);
            }
        }));
    }

    async fn save_settings(self: &Arc<Self>) -> SaveSettings {
        let settings = self.settings();
        let mut save = SaveSettings::new(
            settings.browser_save_prompts,
            default_match(settings.browser_default_match),
        );
        save.return_to = self.typing_target_off_main().await;
        save
    }

    fn report_save(self: &Arc<Self>, result: Result<SaveOutcome, SaveError>) {
        if let Err(error) = result {
            self.send_command(UiCommand::Toast {
                text: error.to_string(),
                error: true,
            });
        }
    }

    fn pair_prompt_allowed(&self) -> bool {
        let now = Instant::now();
        let mut shown = guard(&self.browser.pair_prompts);
        while shown
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= Duration::from_secs(60))
        {
            shown.pop_front();
        }
        if shown.len() >= PAIR_PROMPTS_PER_MINUTE {
            return false;
        }
        shown.push_back(now);
        true
    }

    async fn browser_prompt(self: &Arc<Self>, prompt: BrowserPrompt) -> BrowserReply {
        let is_pair = matches!(prompt, BrowserPrompt::Pair { .. });
        if is_pair && !self.pair_prompt_allowed() {
            self.browser.log.record("pairing refused: too many prompts");
            tracing::warn!("too many browser pairing prompts; refused");
            return BrowserReply::Dismissed;
        }
        let (reply, answer) = tokio::sync::oneshot::channel();
        if !self.send(|seq| DaemonEvent::BrowserPrompt { seq, prompt, reply }) {
            return BrowserReply::Dismissed;
        }
        let reply = answer.await.unwrap_or(BrowserReply::Dismissed);
        if is_pair {
            let outcome = if matches!(reply, BrowserReply::PairApproved) {
                "approved"
            } else {
                "denied"
            };
            self.browser.log.record(&format!("pairing {outcome}"));
        }
        reply
    }

    /// Touch ID for one fill, one sheet at a time.
    async fn browser_presence(&self, reason: String) -> bool {
        let _turn = self.presence.lock().await;
        let touch_id = Arc::clone(&self.touch_id);
        match tokio::task::spawn_blocking(move || touch_id.authenticate(&reason)).await {
            Ok(Ok(())) => true,
            Ok(Err(failure)) => {
                tracing::info!(%failure, "Touch ID refused the browser fill");
                false
            }
            Err(error) => {
                tracing::error!(%error, "Touch ID task failed");
                false
            }
        }
    }

    async fn browser_unlock(self: &Arc<Self>) {
        match self.vault.state() {
            SessionState::Unlocked { .. } | SessionState::LoggedOut => return,
            SessionState::Locked { .. } => {}
        }
        let mut changes = self.vault.changes();
        // Subscribed before the command goes out, so an unlock cannot slip between the two.
        changes.borrow_and_update();
        self.send_command(UiCommand::UnlockInTray);
        while matches!(self.vault.state(), SessionState::Locked { .. }) {
            if changes.changed().await.is_err() {
                return;
            }
        }
    }

    fn browser_status(&self) -> (State, Theme) {
        let state = match self.vault.state() {
            SessionState::Unlocked { .. } => State::Unlocked,
            SessionState::Locked { .. } => State::Locked,
            SessionState::LoggedOut => State::LoggedOut,
        };
        let theme = match self.settings().theme {
            ThemeChoice::System => Theme::System,
            ThemeChoice::Light => Theme::Light,
            ThemeChoice::Dark => Theme::Dark,
        };
        (state, theme)
    }

    fn browser_filled(&self, record: &FillRecord) {
        self.browser.log.record(&format!(
            "fill browser={} host={} item={} via={}",
            record.browser,
            record.host,
            record.item.0,
            if record.from_memory {
                "remembered"
            } else {
                "picker"
            },
        ));
        let settings = self.settings();
        if !record.has_totp || !settings.browser_copy_totp {
            return;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        match self.vault.totp(&record.item, now) {
            Ok(code) => {
                if let Err(error) = self
                    .clipboard
                    .copy(&code.code, settings.clipboard_clear.duration())
                {
                    tracing::warn!(%error, "cannot copy the TOTP code");
                }
            }
            Err(error) => tracing::warn!(%error, "cannot read the TOTP code"),
        }
    }
}

/// One watch for the sessions: it moves on every vault change and on a pairing reload, and each
/// session decides whether anything it cares about changed. Also sweeps expired save candidates.
async fn forward_changes(daemon: Arc<Daemon>) {
    let mut vault_changes = daemon.vault.changes();
    let mut sweep = tokio::time::interval(SAVE_SWEEP);
    loop {
        tokio::select! {
            changed = vault_changes.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            () = daemon.browser.pairings_changed.notified() => {}
            _ = sweep.tick() => {
                if let Ok(mut saves) = daemon.browser.saves.try_lock() {
                    saves.expire(std::time::Instant::now());
                }
                continue;
            }
        }
        daemon
            .browser
            .changes
            .send_modify(|value| *value = value.wrapping_add(1));
    }
}

struct DaemonBrowser(Arc<Daemon>);

impl BrowserHost for DaemonBrowser {
    fn prompt(&self, prompt: BrowserPrompt) -> impl Future<Output = BrowserReply> + Send {
        let daemon = Arc::clone(&self.0);
        async move { daemon.browser_prompt(prompt).await }
    }

    fn presence(&self, reason: &str) -> impl Future<Output = bool> + Send {
        let daemon = Arc::clone(&self.0);
        let reason = reason.to_owned();
        async move { daemon.browser_presence(reason).await }
    }

    fn unlock(&self) -> impl Future<Output = ()> + Send {
        let daemon = Arc::clone(&self.0);
        async move { daemon.browser_unlock().await }
    }

    fn return_to(&self) -> impl Future<Output = Option<TypingTarget>> + Send {
        let daemon = Arc::clone(&self.0);
        async move { daemon.typing_target_off_main().await }
    }

    fn status(&self) -> (State, Theme) {
        self.0.browser_status()
    }

    fn limits(&self, key: &[u8; 65]) -> Arc<std::sync::Mutex<Limits>> {
        Arc::clone(
            guard(&self.0.browser.limits)
                .entry(*key)
                .or_insert_with(|| Arc::new(std::sync::Mutex::new(Limits::new(Instant::now())))),
        )
    }

    fn default_match(&self) -> DefaultMatch {
        default_match(self.0.settings().browser_default_match)
    }

    fn browser_touch_id(&self) -> bool {
        self.0.settings().browser_touch_id
    }

    fn enabled(&self, browser: KnownBrowser) -> bool {
        let settings = self.0.settings();
        let toggled = match browser {
            KnownBrowser::Chrome => settings.browser_chrome,
            KnownBrowser::Firefox => settings.browser_firefox,
        };
        settings.browser_integration && toggled && !self.0.quitting.load(Ordering::SeqCst)
    }

    fn approvals_epoch(&self) -> u64 {
        self.0.browser.epoch.load(Ordering::SeqCst)
    }

    fn candidate(&self, candidate: Candidate) {
        let daemon = Arc::clone(&self.0);
        let mut stopped = daemon.browser.stopped.subscribe();
        drop(self.0.runtime.spawn(async move {
            let Some(store) = guard(&daemon.browser.store).clone() else {
                return;
            };
            let settings = daemon.save_settings().await;
            let host = DaemonBrowser(Arc::clone(&daemon));
            let saves = Arc::clone(&daemon.browser.saves);
            let save = async {
                saves
                    .lock()
                    .await
                    .submit(&daemon.vault, candidate, &settings, &*store, |prompt| {
                        host.prompt(prompt)
                    })
                    .await
            };
            tokio::select! {
                result = save => daemon.report_save(result),
                // Dropping the prompt dismisses it; nothing is written for a stopped listener.
                _ = stopped.changed() => {}
            }
        }));
    }

    fn filled(&self, record: FillRecord) {
        self.0.browser_filled(&record);
    }

    fn open_app(&self, view: AppView) {
        self.0.send_command(match view {
            AppView::Manager => UiCommand::ShowManager,
            AppView::Settings => UiCommand::ShowSettings,
        });
    }

    fn session(&self, browser: &'static str, active: bool) {
        {
            let mut sessions = guard(&self.0.browser.sessions);
            let count = sessions.entry(browser).or_insert(0);
            if active {
                *count += 1;
            } else {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    sessions.remove(browser);
                }
            }
        }
        self.0
            .browser
            .sessions_changed
            .send_modify(|value| *value = value.wrapping_add(1));
    }

    fn note_activity(&self) {
        self.0.activity.touch();
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.0.browser.changes.subscribe()
    }
}
