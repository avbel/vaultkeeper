//! Global hotkeys off while a Settings shortcut recorder waits for a key. Carbon hands a
//! registered combination to the daemon instead of the focused window, so recording ⇧⌘Space
//! would open the Quick Panel. The pause ends on the UI's stop notice, on its disconnect, or after
//! [`PAUSE_LIMIT`], so the hotkeys never stay off.

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use tokio::{sync::watch, task::JoinHandle};
use vk_ipc::UiNotice;

use super::routing::HotkeySlot;
use crate::settings::Settings;

/// Longer than anyone takes to press a shortcut; a recorder still open after it records with the
/// hotkeys back on.
pub const PAUSE_LIMIT: Duration = Duration::from_secs(30);

pub struct HotkeyPause {
    paused: Arc<watch::Sender<bool>>,
    limit: Duration,
    timer: Mutex<Option<JoinHandle<()>>>,
}

impl HotkeyPause {
    #[must_use]
    pub fn new(limit: Duration) -> Self {
        Self {
            paused: Arc::new(watch::Sender::new(false)),
            limit,
            timer: Mutex::new(None),
        }
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.paused.subscribe()
    }

    #[must_use]
    pub fn is_paused(&self) -> bool {
        *self.paused.borrow()
    }

    /// Takes the notices that start or end a pause; others are ignored. Must run inside Tokio.
    pub fn on_notice(&self, notice: UiNotice) {
        match notice {
            UiNotice::ShortcutRecording(true) => self.start(),
            UiNotice::ShortcutRecording(false) | UiNotice::Disconnected => self.stop(),
            UiNotice::SettingsChanged
            | UiNotice::Activity
            | UiNotice::Alive(_)
            | UiNotice::Modal(_)
            | UiNotice::ConfigureShortcuts => {}
        }
    }

    /// A repeated start renews the limit.
    fn start(&self) {
        let paused = Arc::clone(&self.paused);
        let limit = self.limit;
        let timer = tokio::spawn(async move {
            tokio::time::sleep(limit).await;
            tracing::info!("shortcut recording took too long; global hotkeys back on");
            paused.send_if_modified(|value| std::mem::replace(value, false));
        });
        if let Some(previous) = self.lock_timer().replace(timer) {
            previous.abort();
        }
        self.paused
            .send_if_modified(|value| !std::mem::replace(value, true));
    }

    fn stop(&self) {
        if let Some(timer) = self.lock_timer().take() {
            timer.abort();
        }
        self.paused
            .send_if_modified(|value| std::mem::replace(value, false));
    }

    fn lock_timer(&self) -> std::sync::MutexGuard<'_, Option<JoinHandle<()>>> {
        self.timer.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for HotkeyPause {
    fn drop(&mut self) {
        if let Some(timer) = self.lock_timer().take() {
            timer.abort();
        }
    }
}

/// Why a shortcut was not registered, for the failures the user can fix by picking another one.
#[derive(Debug, thiserror::Error)]
#[error("cannot register {accelerator}: {reason}")]
pub struct Unavailable {
    pub accelerator: String,
    pub reason: String,
}

/// Which shortcuts the OS refused (taken by another app or reserved); a shortcut that does not
/// parse is a different problem and is not counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HotkeyIssues {
    pub quick_panel: bool,
    pub generator: bool,
}

impl HotkeyIssues {
    #[must_use]
    pub const fn any(self) -> bool {
        self.quick_panel || self.generator
    }
}

/// What registers the global shortcuts (the Carbon one in production).
pub trait HotkeyBinder {
    /// An empty `accelerator` removes the slot's binding.
    fn bind(&self, slot: HotkeySlot, accelerator: &str) -> anyhow::Result<()>;
}

/// While paused every slot is unbound; otherwise each gets its saved shortcut. The result says
/// which slots the OS refused, so the caller can tell the user.
#[must_use]
pub fn apply(binder: &impl HotkeyBinder, settings: &Settings, paused: bool) -> HotkeyIssues {
    let mut issues = HotkeyIssues::default();
    for (slot, accelerator) in [
        (HotkeySlot::QuickPanel, &settings.hotkey),
        (HotkeySlot::Generator, &settings.generator_hotkey),
    ] {
        let accelerator = if paused { "" } else { accelerator.as_str() };
        if let Err(error) = binder.bind(slot, accelerator) {
            tracing::warn!(%error, ?slot, "global hotkey not registered");
            if error.downcast_ref::<Unavailable>().is_some() {
                match slot {
                    HotkeySlot::QuickPanel => issues.quick_panel = true,
                    HotkeySlot::Generator => issues.generator = true,
                }
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    struct FakeBinder {
        bound: RefCell<Vec<(HotkeySlot, String)>>,
    }

    impl HotkeyBinder for FakeBinder {
        fn bind(&self, slot: HotkeySlot, accelerator: &str) -> anyhow::Result<()> {
            self.bound.borrow_mut().push((slot, accelerator.to_owned()));
            Ok(())
        }
    }

    impl FakeBinder {
        fn take(&self) -> Vec<(HotkeySlot, String)> {
            std::mem::take(&mut self.bound.borrow_mut())
        }
    }

    fn settings() -> Settings {
        Settings {
            hotkey: "Cmd+Shift+K".to_owned(),
            generator_hotkey: "Cmd+Alt+G".to_owned(),
            ..Settings::default()
        }
    }

    fn bound(quick: &str, generator: &str) -> Vec<(HotkeySlot, String)> {
        vec![
            (HotkeySlot::QuickPanel, quick.to_owned()),
            (HotkeySlot::Generator, generator.to_owned()),
        ]
    }

    /// What the daemon shell does on every pause change.
    fn follow(pause: &HotkeyPause, binder: &FakeBinder, settings: &Settings) {
        let _ = apply(binder, settings, pause.is_paused());
    }

    /// Refuses the given slots the way the OS does.
    struct RefusingBinder(Vec<HotkeySlot>);

    impl HotkeyBinder for RefusingBinder {
        fn bind(&self, slot: HotkeySlot, accelerator: &str) -> anyhow::Result<()> {
            if accelerator.is_empty() || !self.0.contains(&slot) {
                return Ok(());
            }
            Err(Unavailable {
                accelerator: accelerator.to_owned(),
                reason: "already registered".to_owned(),
            }
            .into())
        }
    }

    #[test]
    fn a_refused_shortcut_is_reported_for_its_slot() {
        let binder = RefusingBinder(vec![HotkeySlot::Generator]);
        let issues = apply(&binder, &settings(), false);
        assert_eq!(
            issues,
            HotkeyIssues {
                quick_panel: false,
                generator: true
            }
        );
        assert!(issues.any());
    }

    #[test]
    fn a_pause_reports_nothing_and_a_clean_bind_reports_nothing() {
        let binder = RefusingBinder(vec![HotkeySlot::QuickPanel, HotkeySlot::Generator]);
        assert_eq!(apply(&binder, &settings(), true), HotkeyIssues::default());
        assert!(!apply(&FakeBinder::default(), &settings(), false).any());
    }

    #[test]
    fn a_shortcut_that_does_not_parse_is_not_a_refusal() {
        struct Unparsable;
        impl HotkeyBinder for Unparsable {
            fn bind(&self, _: HotkeySlot, accelerator: &str) -> anyhow::Result<()> {
                Err(anyhow::anyhow!("not a shortcut: {accelerator}"))
            }
        }
        assert!(!apply(&Unparsable, &settings(), false).any());
    }

    #[test]
    fn a_pause_unbinds_every_slot_and_its_end_binds_the_saved_shortcuts() {
        let binder = FakeBinder::default();
        let _ = apply(&binder, &settings(), true);
        assert_eq!(binder.take(), bound("", ""));
        let _ = apply(&binder, &settings(), false);
        assert_eq!(binder.take(), bound("Cmd+Shift+K", "Cmd+Alt+G"));
    }

    #[tokio::test(start_paused = true)]
    async fn the_stop_notice_rebinds_from_the_settings_saved_meanwhile() {
        let pause = HotkeyPause::new(PAUSE_LIMIT);
        let binder = FakeBinder::default();
        let mut changes = pause.subscribe();
        pause.on_notice(UiNotice::ShortcutRecording(true));
        assert!(changes.has_changed().expect("open"));
        changes.mark_unchanged();
        follow(&pause, &binder, &settings());
        assert_eq!(binder.take(), bound("", ""));
        let recorded = Settings {
            generator_hotkey: "Ctrl+Shift+F5".to_owned(),
            ..settings()
        };
        pause.on_notice(UiNotice::ShortcutRecording(false));
        assert!(changes.has_changed().expect("open"));
        follow(&pause, &binder, &recorded);
        assert_eq!(binder.take(), bound("Cmd+Shift+K", "Ctrl+Shift+F5"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_disconnect_ends_the_pause() {
        let pause = HotkeyPause::new(PAUSE_LIMIT);
        pause.on_notice(UiNotice::ShortcutRecording(true));
        assert!(pause.is_paused());
        pause.on_notice(UiNotice::Disconnected);
        assert!(!pause.is_paused());
        let binder = FakeBinder::default();
        follow(&pause, &binder, &settings());
        assert_eq!(binder.take(), bound("Cmd+Shift+K", "Cmd+Alt+G"));
    }

    #[tokio::test(start_paused = true)]
    async fn the_pause_ends_by_itself_after_the_limit() {
        let pause = HotkeyPause::new(PAUSE_LIMIT);
        let mut changes = pause.subscribe();
        pause.on_notice(UiNotice::ShortcutRecording(true));
        changes.mark_unchanged();
        tokio::time::sleep(Duration::from_secs(29)).await;
        assert!(pause.is_paused());
        tokio::time::timeout(Duration::from_secs(2), changes.changed())
            .await
            .expect("ended within the limit")
            .expect("open");
        assert!(!pause.is_paused());
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_start_renews_the_limit() {
        let pause = HotkeyPause::new(PAUSE_LIMIT);
        pause.on_notice(UiNotice::ShortcutRecording(true));
        tokio::time::sleep(Duration::from_secs(20)).await;
        pause.on_notice(UiNotice::ShortcutRecording(true));
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert!(
            pause.is_paused(),
            "40 s after the first start, 20 s after the second"
        );
        tokio::time::sleep(Duration::from_secs(11)).await;
        assert!(!pause.is_paused());
    }

    #[tokio::test(start_paused = true)]
    async fn other_notices_leave_the_hotkeys_alone() {
        let pause = HotkeyPause::new(PAUSE_LIMIT);
        let changes = pause.subscribe();
        for notice in [
            UiNotice::SettingsChanged,
            UiNotice::Activity,
            UiNotice::Alive(3),
            UiNotice::Modal(true),
            UiNotice::Disconnected,
            UiNotice::ShortcutRecording(false),
        ] {
            pause.on_notice(notice);
        }
        assert!(!pause.is_paused());
        assert!(!changes.has_changed().expect("open"), "nothing to rebind");
    }
}
