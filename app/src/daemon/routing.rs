//! What each daemon-side trigger (tray menu, global hotkey, a second launch, start-up) asks for,
//! as plain data so the decisions are testable without a tray or a UI process.

use std::sync::Arc;

use bwl_ipc::UiCommand;
use bwl_vault::model::{AccountView, SessionState};

use crate::settings::ThemeChoice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    QuickSearch,
    OpenVault,
    Generator,
    LockToggle,
    SyncNow,
    SwitchAccount(i32),
    Theme(i32),
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Queue a command for the UI process, starting one if none runs.
    Show(UiCommand),
    Lock,
    Sync,
    SwitchAccount(Arc<str>),
    SetTheme(ThemeChoice),
    Quit,
}

/// How the process was launched: autostart (`--tray`/`--daemon`), a plain launch or `--quick`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    Tray,
    Manager,
    QuickPanel,
}

#[must_use]
pub fn tray(action: TrayAction, state: &SessionState, accounts: &[AccountView]) -> Vec<Effect> {
    match action {
        TrayAction::QuickSearch => vec![Effect::Show(UiCommand::ShowQuickPanel)],
        TrayAction::OpenVault => vec![Effect::Show(UiCommand::ShowManager)],
        TrayAction::Generator => vec![Effect::Show(UiCommand::ShowGenerator)],
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
        TrayAction::Theme(index) => ThemeChoice::from_index(index)
            .map(|theme| vec![Effect::SetTheme(theme)])
            .unwrap_or_default(),
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

/// The global hotkey toggles the Quick Panel.
#[must_use]
pub const fn hotkey() -> Effect {
    Effect::Show(UiCommand::ToggleQuickPanel)
}

/// A second launch of the app forwards what it was asked to show to the running daemon.
#[must_use]
pub const fn second_launch(command: bwl_platform::single_instance::Command) -> Effect {
    match command {
        bwl_platform::single_instance::Command::ShowManager => Effect::Show(UiCommand::ShowManager),
        bwl_platform::single_instance::Command::ShowQuickPanel => {
            Effect::Show(UiCommand::ShowQuickPanel)
        }
    }
}

/// What to show right after start. "Ask to unlock on start" applies to autostart only; a plain
/// launch opens the Manager, which shows the lock or login screen itself.
#[must_use]
pub fn startup(launch: Launch, state: &SessionState, ask_unlock_on_start: bool) -> Option<Effect> {
    match launch {
        Launch::Manager => Some(Effect::Show(UiCommand::ShowManager)),
        Launch::QuickPanel => Some(Effect::Show(UiCommand::ShowQuickPanel)),
        Launch::Tray => (ask_unlock_on_start && matches!(state, SessionState::Locked { .. }))
            .then_some(Effect::Show(UiCommand::UnlockInTray)),
    }
}

/// The command a second launch forwards, by its flags.
#[must_use]
pub const fn forwarded(launch: Launch) -> bwl_platform::single_instance::Command {
    match launch {
        Launch::QuickPanel => bwl_platform::single_instance::Command::ShowQuickPanel,
        Launch::Tray | Launch::Manager => bwl_platform::single_instance::Command::ShowManager,
    }
}

#[cfg(test)]
mod tests {
    use bwl_platform::single_instance::Command;
    use url::Url;

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
            tray(TrayAction::QuickSearch, &state, &[]),
            [Effect::Show(UiCommand::ShowQuickPanel)]
        );
        assert_eq!(
            tray(TrayAction::OpenVault, &state, &[]),
            [Effect::Show(UiCommand::ShowManager)]
        );
        assert_eq!(
            tray(TrayAction::Generator, &state, &[]),
            [Effect::Show(UiCommand::ShowGenerator)]
        );
        assert_eq!(tray(TrayAction::Quit, &state, &[]), [Effect::Quit]);
    }

    #[test]
    fn lock_toggle_follows_the_session() {
        assert_eq!(
            tray(TrayAction::LockToggle, &unlocked(), &[]),
            [Effect::Lock]
        );
        assert_eq!(
            tray(TrayAction::LockToggle, &locked(), &[]),
            [Effect::Show(UiCommand::ShowUnlock)]
        );
        assert_eq!(
            tray(TrayAction::LockToggle, &SessionState::LoggedOut, &[]),
            [Effect::Show(UiCommand::ShowLogin)]
        );
    }

    #[test]
    fn sync_needs_an_unlocked_vault() {
        assert_eq!(tray(TrayAction::SyncNow, &unlocked(), &[]), [Effect::Sync]);
        assert_eq!(tray(TrayAction::SyncNow, &locked(), &[]), []);
    }

    #[test]
    fn switching_shows_the_target_lock_screen() {
        let accounts = [account("alice", true), account("bob", false)];
        assert_eq!(
            tray(TrayAction::SwitchAccount(1), &unlocked(), &accounts),
            [
                Effect::SwitchAccount(Arc::from("bob")),
                Effect::Show(UiCommand::ShowUnlock)
            ]
        );
        assert_eq!(
            tray(TrayAction::SwitchAccount(0), &unlocked(), &accounts),
            [Effect::Show(UiCommand::ShowManager)],
            "the active account just opens"
        );
        assert_eq!(
            tray(TrayAction::SwitchAccount(5), &unlocked(), &accounts),
            []
        );
        assert_eq!(
            tray(TrayAction::SwitchAccount(-1), &unlocked(), &accounts),
            []
        );
    }

    #[test]
    fn theme_menu_maps_its_index() {
        assert_eq!(
            tray(TrayAction::Theme(2), &locked(), &[]),
            [Effect::SetTheme(ThemeChoice::Dark)]
        );
        assert_eq!(tray(TrayAction::Theme(3), &locked(), &[]), []);
    }

    #[test]
    fn hotkey_and_second_launch() {
        assert_eq!(hotkey(), Effect::Show(UiCommand::ToggleQuickPanel));
        assert_eq!(
            second_launch(Command::ShowManager),
            Effect::Show(UiCommand::ShowManager)
        );
        assert_eq!(
            second_launch(Command::ShowQuickPanel),
            Effect::Show(UiCommand::ShowQuickPanel)
        );
        assert_eq!(forwarded(Launch::QuickPanel), Command::ShowQuickPanel);
        assert_eq!(forwarded(Launch::Tray), Command::ShowManager);
    }

    #[test]
    fn startup_asks_to_unlock_only_for_a_locked_autostart() {
        assert_eq!(
            startup(Launch::Tray, &locked(), true),
            Some(Effect::Show(UiCommand::UnlockInTray))
        );
        assert_eq!(startup(Launch::Tray, &locked(), false), None);
        assert_eq!(startup(Launch::Tray, &SessionState::LoggedOut, true), None);
        assert_eq!(startup(Launch::Tray, &unlocked(), true), None);
        assert_eq!(
            startup(Launch::Manager, &locked(), false),
            Some(Effect::Show(UiCommand::ShowManager))
        );
        assert_eq!(
            startup(Launch::QuickPanel, &SessionState::LoggedOut, false),
            Some(Effect::Show(UiCommand::ShowQuickPanel))
        );
    }
}
