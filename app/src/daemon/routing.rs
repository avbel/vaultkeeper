//! What each daemon-side trigger (tray menu, global hotkey, a second launch, start-up) asks for,
//! as plain data so the decisions are testable without a tray or a UI process.

use std::sync::Arc;

use vk_ipc::{TypingTarget, UiCommand};
use vk_vault::model::{AccountView, SessionState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    QuickSearch,
    OpenVault,
    Generator,
    Settings,
    LockToggle,
    SyncNow,
    SwitchAccount(i32),
    /// The update item: check, install a staged update, or open the release page.
    Update,
    /// Linux: restart from the install path after a package manager replaced the binary.
    RestartUpdated,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Queue a command for the UI process, starting one if none runs.
    Show(UiCommand),
    Lock,
    Sync,
    SwitchAccount(Arc<str>),
    Update,
    RestartUpdated,
    Quit,
}

/// How the process was launched: autostart (`--tray`/`--daemon`), a plain launch, `--search`
/// or `--generator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    Tray,
    Manager,
    QuickPanel,
    Generator,
}

/// `frontmost` reads the app in front (vaultkeeper excluded); only "Quick search" asks for it.
#[must_use]
pub fn tray(
    action: TrayAction,
    state: &SessionState,
    accounts: &[AccountView],
    frontmost: impl FnOnce() -> Option<TypingTarget>,
) -> Vec<Effect> {
    match action {
        TrayAction::QuickSearch => vec![Effect::Show(UiCommand::ShowQuickPanel {
            target: frontmost(),
        })],
        TrayAction::OpenVault => vec![Effect::Show(UiCommand::ShowManager)],
        TrayAction::Generator => vec![Effect::Show(UiCommand::ShowGenerator)],
        TrayAction::Settings => vec![Effect::Show(UiCommand::ShowSettings)],
        TrayAction::LockToggle => match state {
            SessionState::Unlocked { .. } => vec![Effect::Lock],
            SessionState::Locked { .. } => vec![Effect::Show(UiCommand::ShowUnlock)],
            SessionState::LoggedOut => vec![Effect::Show(UiCommand::ShowLogin)],
        },
        TrayAction::SyncNow => match state {
            SessionState::Unlocked { .. } => vec![Effect::Sync],
            _ => Vec::new(),
        },
        TrayAction::SwitchAccount(index) => switch_account(index, accounts),
        TrayAction::Update => vec![Effect::Update],
        TrayAction::RestartUpdated => vec![Effect::RestartUpdated],
        TrayAction::Quit => vec![Effect::Quit],
    }
}

/// Switching locks the current account and shows the lock screen of the target.
fn switch_account(index: i32, accounts: &[AccountView]) -> Vec<Effect> {
    let Some(account) = usize::try_from(index)
        .ok()
        .and_then(|index| accounts.get(index))
    else {
        return Vec::new();
    };
    if account.active {
        return vec![Effect::Show(UiCommand::ShowManager)];
    }
    vec![
        Effect::SwitchAccount(Arc::clone(&account.id)),
        Effect::Show(UiCommand::ShowUnlock),
    ]
}

/// The two global shortcuts the daemon registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HotkeySlot {
    QuickPanel,
    Generator,
}

/// The Quick Panel hotkey toggles the panel, carrying the app in front for auto-type (read by
/// `frontmost`); the Generator hotkey opens the Generator window.
#[must_use]
pub fn hotkey(slot: HotkeySlot, frontmost: impl FnOnce() -> Option<TypingTarget>) -> Effect {
    match slot {
        HotkeySlot::QuickPanel => Effect::Show(UiCommand::ToggleQuickPanel {
            target: frontmost(),
        }),
        HotkeySlot::Generator => Effect::Show(UiCommand::ShowGenerator),
    }
}

/// A second launch of the app forwards what it was asked to show to the running daemon. A Quick
/// Panel opened this way carries the app in front for auto-type, as the hotkey's does, so
/// `vaultkeeper --search` bound to a launcher or compositor shortcut stands in for the hotkey.
#[must_use]
pub fn second_launch(
    command: vk_platform::single_instance::Command,
    frontmost: impl FnOnce() -> Option<TypingTarget>,
) -> Effect {
    match command {
        vk_platform::single_instance::Command::ShowManager => Effect::Show(UiCommand::ShowManager),
        vk_platform::single_instance::Command::ShowQuickPanel => {
            Effect::Show(UiCommand::ShowQuickPanel {
                target: frontmost(),
            })
        }
        vk_platform::single_instance::Command::ShowGenerator => {
            Effect::Show(UiCommand::ShowGenerator)
        }
        vk_platform::single_instance::Command::Quit => Effect::Quit,
    }
}

/// Runs what a second launch asked for: `Quit` takes the graceful path the tray's Quit takes
/// (`quit`), everything else goes through `apply`.
pub fn dispatch_second_launch(
    command: vk_platform::single_instance::Command,
    frontmost: impl FnOnce() -> Option<TypingTarget>,
    apply: impl FnOnce(Effect),
    quit: impl FnOnce(),
) {
    match second_launch(command, frontmost) {
        Effect::Quit => quit(),
        effect => apply(effect),
    }
}

/// What to show right after start. "Ask to unlock on start" applies to autostart only; a plain
/// launch opens the Manager, which shows the lock or login screen itself. An autostart with no
/// saved account at all (first run) asks to add one, since a bare tray icon gives nothing to do;
/// a logged-out account that is still saved stays quiet. `--search` reads the app in front for
/// auto-type (`frontmost`), as a forwarded one does.
#[must_use]
pub fn startup(
    launch: Launch,
    state: &SessionState,
    has_accounts: bool,
    ask_unlock_on_start: bool,
    frontmost: impl FnOnce() -> Option<TypingTarget>,
) -> Option<Effect> {
    match launch {
        Launch::Manager => Some(Effect::Show(UiCommand::ShowManager)),
        Launch::QuickPanel => Some(Effect::Show(UiCommand::ShowQuickPanel {
            target: frontmost(),
        })),
        Launch::Generator => Some(Effect::Show(UiCommand::ShowGenerator)),
        Launch::Tray if !has_accounts => Some(Effect::Show(UiCommand::ShowLogin)),
        Launch::Tray => (ask_unlock_on_start && matches!(state, SessionState::Locked { .. }))
            .then_some(Effect::Show(UiCommand::UnlockInTray)),
    }
}

/// The command a second launch forwards, by its flags.
#[must_use]
pub const fn forwarded(launch: Launch) -> vk_platform::single_instance::Command {
    match launch {
        Launch::QuickPanel => vk_platform::single_instance::Command::ShowQuickPanel,
        Launch::Generator => vk_platform::single_instance::Command::ShowGenerator,
        Launch::Tray | Launch::Manager => vk_platform::single_instance::Command::ShowManager,
    }
}

#[cfg(test)]
mod tests {
    use url::Url;
    use vk_platform::single_instance::Command;

    use super::*;

    fn server() -> Url {
        Url::parse("https://vault.example.com").expect("url")
    }

    fn unlocked() -> SessionState {
        SessionState::Unlocked {
            server: server(),
            email: "a@example.com".to_owned(),
        }
    }

    fn safari() -> TypingTarget {
        TypingTarget {
            pid: 812,
            name: "Safari".to_owned(),
        }
    }

    fn no_read() -> Option<TypingTarget> {
        panic!("only the Quick Panel reads the frontmost app")
    }

    fn tray_now(action: TrayAction, state: &SessionState, accounts: &[AccountView]) -> Vec<Effect> {
        tray(action, state, accounts, no_read)
    }

    fn locked() -> SessionState {
        SessionState::Locked {
            server: server(),
            email: "a@example.com".to_owned(),
        }
    }

    fn account(id: &str, active: bool) -> AccountView {
        AccountView {
            id: Arc::from(id),
            server: server(),
            email: Arc::from(format!("{id}@example.com").as_str()),
            active,
            logged_in: true,
        }
    }

    #[test]
    fn menu_items_open_their_window() {
        let state = locked();
        assert_eq!(
            tray(TrayAction::QuickSearch, &state, &[], || Some(safari())),
            [Effect::Show(UiCommand::ShowQuickPanel {
                target: Some(safari())
            })],
            "Quick search carries the app in front"
        );
        assert_eq!(
            tray(TrayAction::QuickSearch, &state, &[], || None),
            [Effect::Show(UiCommand::ShowQuickPanel { target: None })]
        );
        assert_eq!(
            tray_now(TrayAction::OpenVault, &state, &[]),
            [Effect::Show(UiCommand::ShowManager)]
        );
        assert_eq!(
            tray_now(TrayAction::Generator, &state, &[]),
            [Effect::Show(UiCommand::ShowGenerator)]
        );
        assert_eq!(
            tray_now(TrayAction::Settings, &state, &[]),
            [Effect::Show(UiCommand::ShowSettings)]
        );
        assert_eq!(tray_now(TrayAction::Quit, &state, &[]), [Effect::Quit]);
        assert_eq!(
            tray_now(TrayAction::RestartUpdated, &state, &[]),
            [Effect::RestartUpdated]
        );
    }

    #[test]
    fn lock_toggle_follows_the_session() {
        assert_eq!(
            tray_now(TrayAction::LockToggle, &unlocked(), &[]),
            [Effect::Lock]
        );
        assert_eq!(
            tray_now(TrayAction::LockToggle, &locked(), &[]),
            [Effect::Show(UiCommand::ShowUnlock)]
        );
        assert_eq!(
            tray_now(TrayAction::LockToggle, &SessionState::LoggedOut, &[]),
            [Effect::Show(UiCommand::ShowLogin)]
        );
    }

    #[test]
    fn sync_needs_an_unlocked_vault() {
        assert_eq!(
            tray_now(TrayAction::SyncNow, &unlocked(), &[]),
            [Effect::Sync]
        );
        assert_eq!(tray_now(TrayAction::SyncNow, &locked(), &[]), []);
    }

    #[test]
    fn switching_shows_the_target_lock_screen() {
        let accounts = [account("alice", true), account("bob", false)];
        assert_eq!(
            tray_now(TrayAction::SwitchAccount(1), &unlocked(), &accounts),
            [
                Effect::SwitchAccount(Arc::from("bob")),
                Effect::Show(UiCommand::ShowUnlock)
            ]
        );
        assert_eq!(
            tray_now(TrayAction::SwitchAccount(0), &unlocked(), &accounts),
            [Effect::Show(UiCommand::ShowManager)],
            "the active account just opens"
        );
        assert_eq!(
            tray_now(TrayAction::SwitchAccount(5), &unlocked(), &accounts),
            []
        );
        assert_eq!(
            tray_now(TrayAction::SwitchAccount(-1), &unlocked(), &accounts),
            []
        );
    }

    #[test]
    fn hotkey_and_second_launch() {
        assert_eq!(
            hotkey(HotkeySlot::QuickPanel, || Some(safari())),
            Effect::Show(UiCommand::ToggleQuickPanel {
                target: Some(safari())
            })
        );
        assert_eq!(
            hotkey(HotkeySlot::QuickPanel, || None),
            Effect::Show(UiCommand::ToggleQuickPanel { target: None }),
            "Vaultkeeper or nothing in front"
        );
        assert_eq!(
            hotkey(HotkeySlot::Generator, no_read),
            Effect::Show(UiCommand::ShowGenerator)
        );
        assert_eq!(
            second_launch(Command::ShowManager, no_read),
            Effect::Show(UiCommand::ShowManager)
        );
        assert_eq!(
            second_launch(Command::ShowQuickPanel, || Some(safari())),
            Effect::Show(UiCommand::ShowQuickPanel {
                target: Some(safari())
            }),
            "`--search` from a launcher types into the app in front, like the hotkey"
        );
        assert_eq!(
            second_launch(Command::ShowQuickPanel, || None),
            Effect::Show(UiCommand::ShowQuickPanel { target: None })
        );
        assert_eq!(
            second_launch(Command::ShowGenerator, no_read),
            Effect::Show(UiCommand::ShowGenerator)
        );
        assert_eq!(forwarded(Launch::QuickPanel), Command::ShowQuickPanel);
        assert_eq!(forwarded(Launch::Generator), Command::ShowGenerator);
        assert_eq!(forwarded(Launch::Tray), Command::ShowManager);
        assert_eq!(second_launch(Command::Quit, no_read), Effect::Quit);
    }

    #[test]
    fn a_forwarded_quit_reaches_the_quit_path_and_nothing_else() {
        use std::cell::Cell;

        let applied = Cell::new(0);
        let quits = Cell::new(0);
        dispatch_second_launch(
            Command::Quit,
            no_read,
            |_| applied.set(applied.get() + 1),
            || quits.set(quits.get() + 1),
        );
        assert_eq!((applied.get(), quits.get()), (0, 1));

        dispatch_second_launch(
            Command::ShowManager,
            no_read,
            |effect| {
                assert_eq!(effect, Effect::Show(UiCommand::ShowManager));
                applied.set(applied.get() + 1);
            },
            || quits.set(quits.get() + 1),
        );
        assert_eq!((applied.get(), quits.get()), (1, 1));
    }

    #[test]
    fn startup_asks_to_unlock_only_for_a_locked_autostart() {
        assert_eq!(
            startup(Launch::Tray, &locked(), true, true, no_read),
            Some(Effect::Show(UiCommand::UnlockInTray))
        );
        assert_eq!(startup(Launch::Tray, &locked(), true, false, no_read), None);
        assert_eq!(
            startup(Launch::Tray, &SessionState::LoggedOut, true, true, no_read),
            None,
            "a saved, logged-out account is not a first run"
        );
        assert_eq!(
            startup(Launch::Tray, &unlocked(), true, true, no_read),
            None
        );
        assert_eq!(
            startup(Launch::Manager, &locked(), true, false, no_read),
            Some(Effect::Show(UiCommand::ShowManager))
        );
        assert_eq!(
            startup(
                Launch::QuickPanel,
                &SessionState::LoggedOut,
                true,
                false,
                || { Some(safari()) }
            ),
            Some(Effect::Show(UiCommand::ShowQuickPanel {
                target: Some(safari())
            }))
        );
        assert_eq!(
            startup(Launch::Generator, &locked(), true, true, no_read),
            Some(Effect::Show(UiCommand::ShowGenerator)),
            "the Generator opens whether or not the vault is unlocked, as from its hotkey"
        );
    }

    #[test]
    fn first_run_autostart_asks_to_add_an_account() {
        for ask_unlock in [true, false] {
            assert_eq!(
                startup(
                    Launch::Tray,
                    &SessionState::LoggedOut,
                    false,
                    ask_unlock,
                    no_read
                ),
                Some(Effect::Show(UiCommand::ShowLogin))
            );
        }
        assert_eq!(
            startup(
                Launch::Manager,
                &SessionState::LoggedOut,
                false,
                false,
                no_read
            ),
            Some(Effect::Show(UiCommand::ShowManager))
        );
    }
}
