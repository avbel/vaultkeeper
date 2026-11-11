//! UI controller. Lives on the Slint thread in an `Rc`; every Slint callback holds only a `Weak`
//! to it, so dropping a window's handle really frees the window.
//!
//! Borrow rule: never hold a `RefCell` borrow across `Exec::spawn` (its continuation may run
//! inline) or across `invoke_*` calls into Slint.

mod auth;
mod autotype_ctl;
mod browser;
mod commands;
mod copy;
mod generator;
mod manager;
mod manager_assign;
mod manager_detail;
mod manager_edit;
mod quick;
mod reprompt;
mod settings_browser;
mod settings_ctl;
mod settings_hotkeys;
mod sidebar_ctl;
mod ssh;
mod ticker;
mod tray;
mod unlock;

use std::{
    cell::{Cell, RefCell},
    rc::{Rc, Weak},
    sync::Arc,
    time::Duration,
};

use slint::{ComponentHandle, Global, SharedString};
use vk_vault::{VaultService, model::SessionState};

pub use browser::BrowserPromptRequest;
pub use commands::UiCommand;
pub use ssh::SshApprovalRequest;

use crate::{
    exec::Exec,
    hooks::Hooks,
    settings::{Settings, ThemeChoice},
    ui::{
        BrowserPairPrompt, BrowserPicker, BrowserSavePrompt, GeneratorWindow, LockWindow,
        ManagerWindow, QuickPanel, SettingsWindow, SshPrompt, Theme, ThemeMode, TrayIcon,
    },
};

use self::{
    auth::LoginState, browser::BrowserQueue, generator::GeneratorCore, manager::Manager,
    quick::Quick, ssh::SshQueue, ticker::Ticker,
};

/// Builds a Slint callback that upgrades the app's `Weak` and runs `$body`, or returns
/// `$default` once the app is gone.
macro_rules! handler {
    ($app:expr, $default:expr, |$this:ident $(, $arg:ident)*| $body:expr) => {{
        let weak = ::std::rc::Weak::clone(&$app.me);
        move |$($arg),*| match weak.upgrade() {
            Some($this) => $body,
            None => $default,
        }
    }};
    ($app:expr, |$this:ident $(, $arg:ident)*| $body:expr) => {
        handler!($app, (), |$this $(, $arg)*| $body)
    };
}
pub(crate) use handler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    None,
    Manager,
    QuickPanel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    LoggedOut,
    Locked(SharedString),
    Unlocked(SharedString),
}

impl Phase {
    fn of(state: &SessionState) -> Self {
        match state {
            SessionState::LoggedOut => Self::LoggedOut,
            SessionState::Locked { server, email } => Self::Locked(account_key(server, email)),
            SessionState::Unlocked { server, email } => Self::Unlocked(account_key(server, email)),
        }
    }

    fn account(&self) -> Option<&SharedString> {
        match self {
            Self::LoggedOut => None,
            Self::Locked(account) | Self::Unlocked(account) => Some(account),
        }
    }
}

fn account_key(server: &url::Url, email: &str) -> SharedString {
    format!("{email}@{server}").into()
}

pub const OFFLINE_TOAST: &str = "Offline mode — showing cached vault";
pub const SYNCED_TOAST: &str = "Vault synced";
pub const SETTINGS_RESET_NOTICE: &str =
    "Settings could not be read and were reset; the old file is kept as settings.json.broken";

pub struct App<S: VaultService> {
    vault: Arc<S>,
    exec: Exec,
    hooks: Hooks,
    me: Weak<Self>,
    /// Unix time at start; the UI clock (`Clock.now`) counts seconds from here.
    epoch: u64,
    settings: RefCell<Settings>,
    phase: RefCell<Phase>,
    target: Cell<Target>,
    last_sync: Cell<Option<u64>>,
    /// `(label, clears at unix time, total seconds)` of the last copy.
    clip: RefCell<Option<(SharedString, u64, i32)>>,
    manager: RefCell<Option<Manager>>,
    quick: RefCell<Option<Quick>>,
    lock_window: RefCell<Option<LockWindow>>,
    failed_unlocks: Cell<i32>,
    /// No unlock since the app started: "Require master password on app start" hides Touch ID.
    first_unlock: Cell<bool>,
    /// A Touch ID prompt runs; a second one is never started next to it.
    touch_id_in_flight: Cell<bool>,
    /// A right-away Touch ID prompt runs with no window open, and what to show if it fails.
    right_away: Cell<Option<unlock::UnlockView>>,
    /// A right-away attempt was cancelled or failed and its lock view is still open.
    right_away_declined: Cell<bool>,
    login: RefCell<Option<LoginState>>,
    settings_window: RefCell<Option<SettingsWindow>>,
    generator_window: RefCell<Option<GeneratorWindow>>,
    generator: RefCell<GeneratorCore>,
    ssh: RefCell<SshQueue>,
    ssh_prompt: RefCell<Option<SshPrompt>>,
    browser: RefCell<BrowserQueue>,
    browser_pair_prompt: RefCell<Option<BrowserPairPrompt>>,
    browser_save_prompt: RefCell<Option<BrowserSavePrompt>>,
    browser_picker: RefCell<Option<BrowserPicker>>,
    ticker: Ticker,
    tray: RefCell<Option<TrayIcon>>,
    /// A sync started by the UI is in flight (the list shows skeleton rows while empty).
    syncing: Cell<bool>,
    on_last_window_closed: RefCell<Option<Box<dyn Fn()>>>,
    /// Re-prompt items whose master password was confirmed since the last lock.
    reprompt_verified: RefCell<std::collections::HashSet<vk_vault::model::ItemId>>,
    reprompt_pending: RefCell<Option<(vk_vault::model::ItemId, reprompt::Pending)>>,
    /// The app in front when the daemon last asked for the Quick Panel, until the panel takes it.
    typing_target: RefCell<Option<crate::hooks::TypingTarget>>,
    /// Keystrokes are being typed into another app; counted like a window so the UI process
    /// does not exit under them.
    autotyping: Cell<bool>,
    /// A message for the next window that shows (auto-type outcomes, the Accessibility hint).
    pending_notice: RefCell<Option<String>>,
}

impl<S: VaultService> App<S> {
    pub fn new(vault: Arc<S>, exec: Exec, hooks: Hooks) -> Rc<Self> {
        let settings = hooks.settings.load();
        let settings_generator = settings.generator.clone();
        let epoch = hooks.clock.unix_now();
        let phase = Phase::of(&vault.state());
        Rc::new_cyclic(|me| Self {
            vault,
            exec,
            hooks,
            me: Weak::clone(me),
            epoch,
            settings: RefCell::new(settings),
            phase: RefCell::new(phase),
            target: Cell::new(Target::None),
            last_sync: Cell::new(None),
            clip: RefCell::new(None),
            manager: RefCell::new(None),
            quick: RefCell::new(None),
            lock_window: RefCell::new(None),
            failed_unlocks: Cell::new(0),
            first_unlock: Cell::new(true),
            touch_id_in_flight: Cell::new(false),
            right_away: Cell::new(None),
            right_away_declined: Cell::new(false),
            login: RefCell::new(None),
            settings_window: RefCell::new(None),
            generator_window: RefCell::new(None),
            generator: RefCell::new(GeneratorCore::from_prefs(&settings_generator)),
            ssh: RefCell::new(SshQueue::default()),
            ssh_prompt: RefCell::new(None),
            browser: RefCell::new(BrowserQueue::default()),
            browser_pair_prompt: RefCell::new(None),
            browser_save_prompt: RefCell::new(None),
            browser_picker: RefCell::new(None),
            ticker: Ticker::default(),
            tray: RefCell::new(None),
            syncing: Cell::new(false),
            on_last_window_closed: RefCell::new(None),
            reprompt_verified: RefCell::new(std::collections::HashSet::new()),
            reprompt_pending: RefCell::new(None),
            typing_target: RefCell::new(None),
            autotyping: Cell::new(false),
            pending_notice: RefCell::new(None),
        })
    }

    #[must_use]
    pub fn vault(&self) -> &Arc<S> {
        &self.vault
    }

    /// The `--ui` process learns from the daemon whether an unlock already happened.
    pub fn set_first_unlock(&self, first_unlock: bool) {
        self.first_unlock.set(first_unlock);
        self.refresh_lock_window();
    }

    /// Registers the global hotkey and, unless `tray_only`, shows the window for the current
    /// state. With "Ask to unlock on start" a tray-only start still shows the lock screen.
    pub fn start(&self, tray_only: bool) {
        let hotkey = self.settings.borrow().hotkey.clone();
        if let Err(error) = self.hooks.hotkey.register(&hotkey) {
            tracing::warn!(%error, "global hotkey not registered");
        }
        let ask_unlock = self.settings.borrow().ask_unlock_on_start;
        if matches!(self.vault.state(), SessionState::Unlocked { .. }) {
            self.sync_now();
        }
        let unlocked = matches!(self.vault.state(), SessionState::Unlocked { .. });
        if !tray_only {
            self.open_vault();
        } else if ask_unlock && !unlocked {
            self.ask_unlock_on_start();
        }
    }

    /// Re-reads vault state after any change: production wires `VaultService::changes` here,
    /// and every UI-initiated operation calls it when it finishes.
    pub fn on_vault_changed(&self) {
        let state = self.vault.state();
        let phase = Phase::of(&state);
        let previous = self.phase.replace(phase.clone());
        self.update_tray(&state);
        if previous == phase {
            self.refresh_open_views();
            return;
        }
        let switched = previous.account() != phase.account();
        let had_window = self.manager.borrow().is_some() || self.quick.borrow().is_some();
        if switched || matches!(phase, Phase::LoggedOut) {
            self.clear_account_ui();
        } else if matches!(phase, Phase::Locked(_)) {
            self.on_locked();
        }
        match phase {
            Phase::LoggedOut => self.show_login_for_state(),
            Phase::Locked(_) => self.show_lock_if_needed(had_window || switched),
            Phase::Unlocked(_) => self.on_unlocked(),
        }
    }

    fn refresh_open_views(&self) {
        if matches!(*self.phase.borrow(), Phase::Unlocked(_)) {
            self.refresh_manager();
            self.refresh_quick();
        }
        self.refresh_lock_window();
    }

    fn on_unlocked(&self) {
        self.first_unlock.set(false);
        self.forget_declined_touch_id();
        self.failed_unlocks.set(0);
        self.close_lock_window();
        self.close_login();
        let quick_open = self.quick.borrow().is_some();
        match self.target.replace(Target::None) {
            Target::QuickPanel => self.open_quick_panel(),
            _ if quick_open => self.open_quick_panel(),
            Target::Manager => self.open_manager(),
            // Nothing asked for a window (unlock at login): stay in the tray.
            Target::None => {}
        }
        self.show_next_ssh_prompt();
        self.show_next_browser_prompt();
        self.show_pending_notices();
        self.sync_now();
    }

    /// Lock keeps the account but drops every decrypted view.
    fn on_locked(&self) {
        let had_window = self.manager.borrow().is_some() || self.quick.borrow().is_some();
        self.close_manager();
        self.close_quick_panel();
        self.deny_all_ssh();
        self.deny_all_browser();
        self.forget_reprompts();
        self.hooks.autotype.cancel();
        if had_window && self.target.get() == Target::None {
            self.target.set(Target::Manager);
        }
    }

    /// Logout or account switch: nothing from the previous account may stay in the UI.
    fn clear_account_ui(&self) {
        self.on_locked();
        self.generator.borrow_mut().clear();
        self.refresh_generator_views();
        self.hooks.clipboard.clear_if_ours();
        self.clip.replace(None);
        self.last_sync.set(None);
        self.failed_unlocks.set(0);
        self.close_settings();
    }

    fn show_lock_if_needed(&self, force: bool) {
        if force || self.target.get() != Target::None || self.lock_window.borrow().is_some() {
            self.close_login();
            self.open_lock_window();
        }
    }

    /// Opens what the current state allows: Manager, lock screen or login.
    pub fn open_vault(&self) {
        match self.vault.state() {
            SessionState::Unlocked { .. } => self.open_manager(),
            SessionState::Locked { .. } => {
                self.target.set(Target::Manager);
                self.request_unlock(unlock::UnlockView::LockWindow);
            }
            SessionState::LoggedOut => {
                self.target.set(Target::Manager);
                self.show_login_for_state();
            }
        }
    }

    /// For the global hotkey and the tray's "Quick search".
    pub fn toggle_quick_panel(&self) {
        if self.quick.borrow().is_some() {
            self.dismiss_quick_panel();
            return;
        }
        match self.vault.state() {
            SessionState::Unlocked { .. } => self.open_quick_panel(),
            SessionState::Locked { .. } => {
                self.target.set(Target::QuickPanel);
                self.request_unlock(unlock::UnlockView::QuickPanel);
            }
            SessionState::LoggedOut => {
                self.target.set(Target::QuickPanel);
                self.show_login_for_state();
            }
        }
    }

    /// For ⌘⇧L and the tray. Locking is synchronous in the vault.
    pub fn lock(&self) {
        if matches!(self.vault.state(), SessionState::Unlocked { .. }) {
            self.vault.lock();
        }
        self.on_vault_changed();
    }

    pub fn sync_now(&self) {
        self.syncing.set(true);
        let vault = Arc::clone(&self.vault);
        self.exec.spawn(
            async move { vault.sync().await },
            handler!(self, |app, result| app.on_synced(result)),
        );
    }

    fn on_synced(&self, result: vk_vault::Result<()>) {
        self.syncing.set(false);
        match result {
            Ok(()) => self.last_sync.set(Some(self.hooks.clock.unix_now())),
            Err(error) => {
                tracing::warn!(%error, "sync failed");
                if self.vault.is_offline() {
                    self.toast(OFFLINE_TOAST, false);
                }
            }
        }
        self.on_vault_changed();
    }

    /// ⌘Q and the tray's Quit: ends the event loop (the UI process exits).
    pub fn quit(&self) {
        if let Err(error) = slint::quit_event_loop() {
            tracing::error!(%error, "cannot quit the event loop");
        }
    }

    fn ui_now(&self) -> i32 {
        i32::try_from(self.hooks.clock.unix_now().saturating_sub(self.epoch)).unwrap_or(i32::MAX)
    }

    /// Shows a toast in the most relevant open vault window; errors are also logged.
    pub fn toast(&self, text: &str, error: bool) {
        if error {
            tracing::warn!(text, "error toast");
        }
        if let Some(manager) = self.manager.borrow().as_ref() {
            manager.window.set_toast_text(text.into());
            manager.window.set_toast_error(error);
            manager.window.set_toast_shown(true);
            return;
        }
        if let Some(quick) = self.quick.borrow().as_ref() {
            quick.window.set_toast_text(text.into());
            quick.window.set_toast_error(error);
            quick.window.set_toast_shown(true);
        }
    }

    /// Tells the user once that an unreadable settings file was reset, as soon as a window can
    /// show it.
    pub fn show_pending_notices(&self) {
        let has_window = self.manager.borrow().is_some() || self.quick.borrow().is_some();
        if has_window && self.hooks.settings.take_reset_notice() {
            self.toast(SETTINGS_RESET_NOTICE, true);
        }
        let notice = has_window.then(|| self.pending_notice.take()).flatten();
        if let Some(notice) = notice {
            self.toast(&notice, true);
        }
    }

    /// Applies the theme mode, text size and shortcut hints to a window's `Theme` global. System mode leaves
    /// `Theme.system-dark` bound to the OS scheme, so it keeps following live changes.
    fn apply_theme<C>(&self, component: &C)
    where
        C: ComponentHandle,
        for<'a> Theme<'a>: Global<'a, C>,
    {
        let settings = self.settings.borrow();
        let theme = component.global::<Theme>();
        theme.set_mode(theme_mode(settings.theme));
        theme.set_scale(settings.text_scale.factor());
    }

    fn apply_theme_everywhere(&self) {
        if let Some(manager) = self.manager.borrow().as_ref() {
            self.apply_theme(&manager.window);
        }
        if let Some(quick) = self.quick.borrow().as_ref() {
            self.apply_theme(&quick.window);
        }
        if let Some(window) = self.lock_window.borrow().as_ref() {
            self.apply_theme(window);
        }
        if let Some(login) = self.login.borrow().as_ref() {
            self.apply_theme(&login.window);
        }
        if let Some(window) = self.settings_window.borrow().as_ref() {
            self.apply_theme(window);
        }
        if let Some(window) = self.generator_window.borrow().as_ref() {
            self.apply_theme(window);
        }
        if let Some(window) = self.ssh_prompt.borrow().as_ref() {
            self.apply_theme(window);
        }
        if let Some(window) = self.browser_pair_prompt.borrow().as_ref() {
            self.apply_theme(window);
        }
        if let Some(window) = self.browser_save_prompt.borrow().as_ref() {
            self.apply_theme(window);
        }
        if let Some(window) = self.browser_picker.borrow().as_ref() {
            self.apply_theme(window);
        }
    }

    /// Persists and applies a theme choice from the Settings window.
    pub fn set_theme(&self, theme: ThemeChoice) {
        self.update_settings(|settings| settings.theme = theme);
        self.apply_theme_everywhere();
    }

    // Windows exposed for the integration step and the UI tests.

    #[must_use]
    pub fn manager_window(&self) -> Option<ManagerWindow> {
        self.manager
            .borrow()
            .as_ref()
            .map(|manager| manager.window.clone_strong())
    }

    #[must_use]
    pub fn quick_panel(&self) -> Option<QuickPanel> {
        self.quick
            .borrow()
            .as_ref()
            .map(|quick| quick.window.clone_strong())
    }

    #[must_use]
    pub fn lock_window(&self) -> Option<LockWindow> {
        self.lock_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong)
    }

    #[must_use]
    pub fn login_window(&self) -> Option<crate::ui::LoginWindow> {
        self.login
            .borrow()
            .as_ref()
            .map(|login| login.window.clone_strong())
    }

    #[must_use]
    pub fn settings_window(&self) -> Option<SettingsWindow> {
        self.settings_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong)
    }

    #[must_use]
    pub fn generator_window(&self) -> Option<GeneratorWindow> {
        self.generator_window
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong)
    }

    #[must_use]
    pub fn browser_picker(&self) -> Option<BrowserPicker> {
        self.browser_picker
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong)
    }

    #[must_use]
    pub fn browser_save_prompt(&self) -> Option<BrowserSavePrompt> {
        self.browser_save_prompt
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong)
    }

    #[must_use]
    pub fn browser_pair_prompt(&self) -> Option<BrowserPairPrompt> {
        self.browser_pair_prompt
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong)
    }

    #[must_use]
    pub fn ssh_prompt(&self) -> Option<SshPrompt> {
        self.ssh_prompt
            .borrow()
            .as_ref()
            .map(ComponentHandle::clone_strong)
    }

    #[must_use]
    pub fn totp_timer_running(&self) -> bool {
        self.ticker.running()
    }

    /// Strings currently held by Rust-side view state (rows, sidebar, detail, edit form,
    /// attachments, generator history), for tests that check account data does not leak.
    #[must_use]
    pub fn view_strings(&self) -> Vec<String> {
        let mut strings = Vec::new();
        if let Some(manager) = self.manager.borrow().as_ref() {
            strings.extend(manager.strings());
        }
        if let Some(quick) = self.quick.borrow().as_ref() {
            strings.extend(quick.rows.visible_strings());
        }
        strings.extend(self.generator.borrow().strings());
        strings
    }
}

const fn theme_mode(choice: ThemeChoice) -> ThemeMode {
    match choice {
        ThemeChoice::System => ThemeMode::System,
        ThemeChoice::Light => ThemeMode::Light,
        ThemeChoice::Dark => ThemeMode::Dark,
    }
}

/// Drops a window handle on the next event-loop turn instead of inside its own callback.
fn retire<T: 'static>(handle: T) {
    slint::Timer::single_shot(Duration::ZERO, move || drop(handle));
}

fn show<C: ComponentHandle>(component: &C, what: &str) {
    if let Err(error) = component.show() {
        tracing::error!(%error, what, "cannot show window");
    }
}

fn hide<C: ComponentHandle>(component: &C) {
    if let Err(error) = component.hide() {
        tracing::warn!(%error, "cannot hide window");
    }
}
