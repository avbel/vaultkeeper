//! Headless UI test harness: Slint's testing backend (one per test thread), the mock vault with
//! zero latency, recording hooks and a fixed clock.

#![allow(dead_code)]

use std::{
    path::PathBuf,
    rc::Rc,
    sync::{Arc, LazyLock, Mutex, PoisonError},
    time::Duration,
};

use bw_lite::{
    App,
    autotype::{Stroke, typed_text},
    exec::Exec,
    hooks::{
        AutoType, AutoTypeDone, Biometrics, Clipboard, Clock, DockIcon, FileDialogs, HookError,
        HookResult, Hooks, SettingsStore, SshKeyTool, TypingTarget, WindowPlacement,
    },
    mock::{MockConfig, MockVault},
    settings::Settings,
};
use i_slint_backend_testing::{
    AccessibleRole, ElementHandle, ElementRoot, TestingBackend, TestingBackendOptions,
};
use slint::{
    ComponentHandle,
    platform::{Key, WindowEvent},
};

/// 1_700_000_010 is a multiple of 30, so this is 10 s into a TOTP window (20 s remaining).
pub const NOW: u64 = 1_700_000_020;

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("test runtime")
});

/// Runs vault calls a test makes directly, outside the UI.
pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
    RUNTIME.block_on(future)
}

/// The testing backend is per thread; a thread reused by the test runner already has one.
pub fn init_backend() {
    let backend = TestingBackend::new(TestingBackendOptions {
        mock_time: true,
        threading: false,
    });
    let _ = slint::platform::set_platform(Box::new(backend));
}

#[derive(Default)]
pub struct RecordingClipboard {
    pub copies: Mutex<Vec<(String, Option<Duration>)>>,
    pub clears: Mutex<usize>,
}

impl RecordingClipboard {
    pub fn last(&self) -> Option<String> {
        self.copies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last()
            .map(|(text, _)| text.clone())
    }

    pub fn count(&self) -> usize {
        self.copies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    pub fn clears(&self) -> usize {
        *self.clears.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Clipboard for RecordingClipboard {
    fn copy(&self, text: &str, clear_after: Option<Duration>) -> HookResult<()> {
        self.copies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((text.to_owned(), clear_after));
        Ok(())
    }

    fn clear_if_ours(&self) {
        *self.clears.lock().unwrap_or_else(PoisonError::into_inner) += 1;
    }
}

#[derive(Default)]
pub struct FakeFiles {
    pub save_to: Mutex<Option<PathBuf>>,
    pub open: Mutex<Option<PathBuf>>,
}

impl FileDialogs for FakeFiles {
    fn save_file(&self, _suggested_name: &str) -> Option<PathBuf> {
        self.save_to
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn open_file(&self) -> Option<PathBuf> {
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[derive(Default)]
pub struct RecordingSettings {
    pub saved: Mutex<Option<Settings>>,
    /// An unreadable settings file was reset and the user has not been told yet.
    pub reset_notice: std::sync::atomic::AtomicBool,
}

impl SettingsStore for RecordingSettings {
    fn load(&self) -> Settings {
        self.saved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .unwrap_or_default()
    }

    fn save(&self, settings: &Settings) -> HookResult<()> {
        *self.saved.lock().unwrap_or_else(PoisonError::into_inner) = Some(settings.clone());
        Ok(())
    }

    fn take_reset_notice(&self) -> bool {
        self.reset_notice
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

/// Records the size the Quick Panel asks to be placed with.
#[derive(Default)]
pub struct RecordingPlacement {
    pub requested: Mutex<Option<(f32, f32)>>,
}

impl WindowPlacement for RecordingPlacement {
    fn quick_panel_origin(&self, width: f32, height: f32) -> Option<slint::LogicalPosition> {
        *self
            .requested
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((width, height));
        None
    }
}

pub struct FixedClock(pub Mutex<u64>);

impl Clock for FixedClock {
    fn unix_now(&self) -> u64 {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What the next Touch ID prompt of [`ScriptedTouchId`] answers.
#[derive(Debug, Clone)]
pub enum TouchIdOutcome {
    Unlock,
    Cancel,
    Fail(&'static str),
}

thread_local! {
    /// Runs inside the next prompt, on the test thread (`Exec::blocking` runs it inline), so a
    /// test can look at the app while the system prompt would be on screen.
    static DURING_PROMPT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

pub fn during_next_prompt(probe: impl FnOnce() + 'static) {
    DURING_PROMPT.with(|slot| *slot.borrow_mut() = Some(Box::new(probe)));
}

/// Touch ID enrolled for every account, answering prompts from a script and counting them.
pub struct ScriptedTouchId {
    vault: Arc<MockVault>,
    outcomes: Mutex<std::collections::VecDeque<TouchIdOutcome>>,
    prompts: std::sync::atomic::AtomicUsize,
}

impl ScriptedTouchId {
    pub fn prompts(&self) -> usize {
        self.prompts.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn answer_next(&self, outcome: TouchIdOutcome) {
        self.outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(outcome);
    }
}

impl Biometrics for ScriptedTouchId {
    fn is_available(&self) -> bool {
        true
    }

    fn is_enrolled(&self, _account_id: &str) -> bool {
        true
    }

    fn enroll(&self, _account_id: &str) -> HookResult<()> {
        Ok(())
    }

    fn unlock(&self, account_id: &str) -> HookResult<()> {
        self.prompts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(probe) = DURING_PROMPT.with(|slot| slot.borrow_mut().take()) {
            probe();
        }
        let outcome = self
            .outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .expect("a scripted Touch ID answer");
        match outcome {
            TouchIdOutcome::Unlock => bwl_vault::VaultService::unlock_with_user_key(
                &*self.vault,
                bw_lite::mock::mock_user_key(account_id),
            )
            .map_err(|error| HookError::Failed(error.to_string())),
            TouchIdOutcome::Cancel => Err(HookError::Cancelled),
            TouchIdOutcome::Fail(text) => Err(HookError::Failed(text.to_owned())),
        }
    }

    fn unenroll(&self, _account_id: &str) -> HookResult<()> {
        Ok(())
    }
}

thread_local! {
    /// The `done` of typing that [`FakeAutoType::hold`] keeps running; it is not `Send`.
    static HELD_TYPING: std::cell::RefCell<Option<AutoTypeDone>> = std::cell::RefCell::new(None);
}

/// Auto-type that records what it would type. Safari is in front and Accessibility is granted
/// unless a test says otherwise.
pub struct FakeAutoType {
    pub frontmost: Mutex<Option<TypingTarget>>,
    pub trusted: std::sync::atomic::AtomicBool,
    pub trust_checks: Mutex<Vec<bool>>,
    pub typed: Mutex<Vec<(TypingTarget, String)>>,
    /// Apps a dismissed Quick Panel handed the front back to.
    pub given_back: Mutex<Vec<TypingTarget>>,
    /// The next run reports this instead of success.
    pub fail_with: Mutex<Option<String>>,
    /// Keeps the next run going until [`FakeAutoType::finish`] or a cancel.
    pub hold: std::sync::atomic::AtomicBool,
    pub cancels: std::sync::atomic::AtomicUsize,
}

pub fn safari() -> TypingTarget {
    TypingTarget {
        pid: 501,
        name: "Safari".to_owned(),
    }
}

impl Default for FakeAutoType {
    fn default() -> Self {
        Self {
            frontmost: Mutex::new(Some(safari())),
            trusted: std::sync::atomic::AtomicBool::new(true),
            trust_checks: Mutex::default(),
            typed: Mutex::default(),
            given_back: Mutex::default(),
            fail_with: Mutex::default(),
            hold: std::sync::atomic::AtomicBool::new(false),
            cancels: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl FakeAutoType {
    pub fn typed(&self) -> Vec<(TypingTarget, String)> {
        self.typed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn finish(result: HookResult<()>) {
        if let Some(done) = HELD_TYPING.with(|slot| slot.borrow_mut().take()) {
            done(result);
        }
    }
}

impl AutoType for FakeAutoType {
    fn frontmost(&self) -> Option<TypingTarget> {
        self.frontmost
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn is_trusted(&self, prompt: bool) -> bool {
        self.trust_checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(prompt);
        self.trusted.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn start(&self, target: TypingTarget, strokes: Vec<Stroke>, done: AutoTypeDone) {
        self.typed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((target, typed_text(&strokes).to_string()));
        if self.hold.swap(false, std::sync::atomic::Ordering::SeqCst) {
            HELD_TYPING.with(|slot| *slot.borrow_mut() = Some(done));
            return;
        }
        let failure = self
            .fail_with
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        done(failure.map_or(Ok(()), |text| Err(HookError::Failed(text))));
    }

    fn cancel(&self) {
        self.cancels
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self::finish(Err(HookError::Cancelled));
    }

    fn give_focus_back(&self, target: &TypingTarget) {
        self.given_back
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(target.clone());
    }
}

/// Counts how often the app was activated and hidden.
#[derive(Default)]
pub struct RecordingDock {
    pub activations: std::sync::atomic::AtomicUsize,
    pub hides: std::sync::atomic::AtomicUsize,
}

impl RecordingDock {
    pub fn hides(&self) -> usize {
        self.hides.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl DockIcon for RecordingDock {
    fn set_visible(&self, _visible: bool) {}

    fn activate(&self) {
        self.activations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn hide(&self) {
        self.hides.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub struct Harness {
    pub app: Rc<App<MockVault>>,
    /// Set when [`Setup::scripted_touch_id`] is.
    pub touch_id: Option<Arc<ScriptedTouchId>>,
    pub vault: Arc<MockVault>,
    pub clipboard: Arc<RecordingClipboard>,
    pub files: Arc<FakeFiles>,
    pub settings: Arc<RecordingSettings>,
    pub clock: Arc<FixedClock>,
    pub placement: Arc<RecordingPlacement>,
    pub autotype: Arc<FakeAutoType>,
    pub dock: Arc<RecordingDock>,
}

pub struct Setup {
    pub unlocked: bool,
    pub offline: bool,
    pub settings: Settings,
    /// Replaces the mock SSH key tool (e.g. with the real one).
    pub ssh_keys: Option<Arc<dyn SshKeyTool>>,
    /// Replaces the mock Touch ID with [`ScriptedTouchId`].
    pub scripted_touch_id: bool,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            unlocked: true,
            offline: false,
            settings: Settings::default(),
            ssh_keys: None,
            scripted_touch_id: false,
        }
    }
}

pub fn harness(setup: Setup) -> Harness {
    init_backend();
    let vault = Arc::new(MockVault::new(&MockConfig {
        latency: Duration::ZERO,
        offline: setup.offline,
        unlocked: setup.unlocked,
    }));
    let clipboard = Arc::new(RecordingClipboard::default());
    let files = Arc::new(FakeFiles::default());
    let settings = Arc::new(RecordingSettings {
        saved: Mutex::new(Some(setup.settings)),
        ..RecordingSettings::default()
    });
    let clock = Arc::new(FixedClock(Mutex::new(NOW)));
    let placement = Arc::new(RecordingPlacement::default());
    let autotype = Arc::new(FakeAutoType::default());
    let dock = Arc::new(RecordingDock::default());
    let defaults = Hooks::mock(&vault, &[]);
    let touch_id = setup.scripted_touch_id.then(|| {
        Arc::new(ScriptedTouchId {
            vault: Arc::clone(&vault),
            outcomes: Mutex::default(),
            prompts: std::sync::atomic::AtomicUsize::new(0),
        })
    });
    let hooks = Hooks {
        biometrics: touch_id.as_ref().map_or_else(
            || Arc::clone(&defaults.biometrics),
            |touch_id| Arc::clone(touch_id) as Arc<dyn Biometrics>,
        ),
        clipboard: Arc::clone(&clipboard) as Arc<dyn Clipboard>,
        files: Arc::clone(&files) as Arc<dyn FileDialogs>,
        settings: Arc::clone(&settings) as Arc<dyn SettingsStore>,
        clock: Arc::clone(&clock) as Arc<dyn Clock>,
        placement: Arc::clone(&placement) as Arc<dyn WindowPlacement>,
        autotype: Arc::clone(&autotype) as Arc<dyn AutoType>,
        dock: Arc::clone(&dock) as Arc<dyn DockIcon>,
        ssh_keys: setup
            .ssh_keys
            .unwrap_or_else(|| Arc::clone(&defaults.ssh_keys)),
        ..defaults
    };
    let app = App::new(
        Arc::clone(&vault),
        Exec::blocking(RUNTIME.handle().clone()),
        hooks,
    );
    Harness {
        app,
        touch_id,
        vault,
        clipboard,
        files,
        settings,
        clock,
        placement,
        autotype,
        dock,
    }
}

/// Runs zero-delay timers (deferred window drops) and pending change handlers.
pub fn pump() {
    i_slint_backend_testing::mock_elapsed_time(Duration::ZERO);
}

pub fn elapse(duration: Duration) {
    i_slint_backend_testing::mock_elapsed_time(duration);
}

/// First element with this accessible label. Plain `Text` elements are labelled by their own text,
/// so lookups that act on a control skip them.
pub fn find(root: &impl ElementRoot, label: &str) -> ElementHandle {
    ElementHandle::find_by_accessible_label(root, label)
        .next()
        .unwrap_or_else(|| panic!("no element labelled {label:?}"))
}

fn find_role(
    root: &impl ElementRoot,
    label: &str,
    wanted: impl Fn(AccessibleRole) -> bool,
) -> ElementHandle {
    ElementHandle::find_by_accessible_label(root, label)
        .find(|element| element.accessible_role().is_some_and(&wanted))
        .unwrap_or_else(|| panic!("no control labelled {label:?}"))
}

pub fn exists(root: &impl ElementRoot, label: &str) -> bool {
    ElementHandle::find_by_accessible_label(root, label)
        .next()
        .is_some()
}

pub fn control_exists(root: &impl ElementRoot, label: &str) -> bool {
    ElementHandle::find_by_accessible_label(root, label).any(|element| {
        element
            .accessible_role()
            .is_some_and(|role| role != AccessibleRole::Text)
    })
}

pub fn click(root: &impl ElementRoot, label: &str) {
    find_role(root, label, |role| role != AccessibleRole::Text).invoke_accessible_default_action();
    pump();
}

pub fn type_into(root: &impl ElementRoot, label: &str, text: &str) {
    find_role(root, label, |role| role == AccessibleRole::TextInput).set_accessible_value(text);
    pump();
}

pub fn enabled(root: &impl ElementRoot, label: &str) -> bool {
    find_role(root, label, |role| role != AccessibleRole::Text)
        .accessible_enabled()
        .unwrap_or(true)
}

pub fn value_of(root: &impl ElementRoot, label: &str) -> String {
    find(root, label)
        .accessible_value()
        .map(|value| value.to_string())
        .unwrap_or_default()
}

#[derive(Clone, Copy, Default)]
pub struct Mods {
    pub cmd: bool,
    pub shift: bool,
}

pub const CMD: Mods = Mods {
    cmd: true,
    shift: false,
};
pub const SHIFT: Mods = Mods {
    cmd: false,
    shift: true,
};
pub const CMD_SHIFT: Mods = Mods {
    cmd: true,
    shift: true,
};

fn send(window: &slint::Window, text: slint::SharedString, pressed: bool) {
    let event = if pressed {
        WindowEvent::KeyPressed { text }
    } else {
        WindowEvent::KeyReleased { text }
    };
    window.dispatch_event(event);
}

/// Presses `text` with modifiers. Slint reports ⌘ as `control` on macOS, so ⌘ is `Key::Control`.
pub fn key(component: &impl ComponentHandle, text: &str, mods: Mods) {
    let window = component.window();
    if mods.cmd {
        send(window, Key::Control.into(), true);
    }
    if mods.shift {
        send(window, Key::Shift.into(), true);
    }
    send(window, text.into(), true);
    send(window, text.into(), false);
    if mods.shift {
        send(window, Key::Shift.into(), false);
    }
    if mods.cmd {
        send(window, Key::Control.into(), false);
    }
    pump();
}

pub fn special(key_code: Key) -> String {
    char::from(key_code).to_string()
}

pub fn set_size(component: &impl ComponentHandle, width: f32, height: f32) {
    component
        .window()
        .set_size(slint::LogicalSize::new(width, height));
    pump();
}
