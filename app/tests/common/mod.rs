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
    exec::Exec,
    hooks::{Clipboard, Clock, FileDialogs, HookResult, Hooks, SettingsStore, SshKeyTool},
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
}

pub struct FixedClock(pub Mutex<u64>);

impl Clock for FixedClock {
    fn unix_now(&self) -> u64 {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub struct Harness {
    pub app: Rc<App<MockVault>>,
    pub vault: Arc<MockVault>,
    pub clipboard: Arc<RecordingClipboard>,
    pub files: Arc<FakeFiles>,
    pub settings: Arc<RecordingSettings>,
    pub clock: Arc<FixedClock>,
}

pub struct Setup {
    pub unlocked: bool,
    pub offline: bool,
    pub settings: Settings,
    /// Replaces the mock SSH key tool (e.g. with the real one).
    pub ssh_keys: Option<Arc<dyn SshKeyTool>>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            unlocked: true,
            offline: false,
            settings: Settings::default(),
            ssh_keys: None,
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
    });
    let clock = Arc::new(FixedClock(Mutex::new(NOW)));
    let defaults = Hooks::mock(&vault, &[]);
    let hooks = Hooks {
        clipboard: Arc::clone(&clipboard) as Arc<dyn Clipboard>,
        files: Arc::clone(&files) as Arc<dyn FileDialogs>,
        settings: Arc::clone(&settings) as Arc<dyn SettingsStore>,
        clock: Arc::clone(&clock) as Arc<dyn Clock>,
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
        vault,
        clipboard,
        files,
        settings,
        clock,
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
