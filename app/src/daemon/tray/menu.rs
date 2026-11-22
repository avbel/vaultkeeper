//! The tray menu as plain data. Slint builds the macOS and Windows menu from `tray.slint`; the
//! Linux StatusNotifierItem has no markup, so this mirrors that file item for item.

use crate::daemon::routing::TrayAction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Item {
        label: String,
        enabled: bool,
        action: TrayAction,
    },
    /// A disabled line of text.
    Note(String),
    Submenu {
        label: String,
        items: Vec<Entry>,
    },
    Separator,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MenuState {
    pub locked: bool,
    pub logged_in: bool,
    pub accounts: Vec<String>,
    pub syncing: bool,
    pub sync_label: String,
    /// Empty hides the update item.
    pub update_label: String,
    pub update_enabled: bool,
    /// A package manager replaced the binary under this daemon (Linux).
    pub restart_to_update: bool,
    /// The daemon cannot start its replacement itself (see `daemon::relaunch`).
    pub restart_by_hand: bool,
}

/// The host reads `_` in a label as an access-key marker, so a literal one is doubled; an
/// account e-mail such as `first_last@example.com` would otherwise lose it.
#[must_use]
pub fn escape_label(label: &str) -> String {
    label.replace('_', "__")
}

const RESTART_BY_HAND: &str = "Quit and start Vaultkeeper again to finish the update";

fn item(label: &str, action: TrayAction) -> Entry {
    Entry::Item {
        label: label.to_owned(),
        enabled: true,
        action,
    }
}

#[must_use]
pub fn build(state: &MenuState) -> Vec<Entry> {
    let accounts = state
        .accounts
        .iter()
        .enumerate()
        .map(|(index, label)| {
            item(
                label,
                TrayAction::SwitchAccount(i32::try_from(index).unwrap_or(i32::MAX)),
            )
        })
        .collect();
    // "Open vault" comes first because it is what a double-click on the icon runs elsewhere.
    let mut entries = vec![
        item("Open vault", TrayAction::OpenVault),
        item("Quick search", TrayAction::QuickSearch),
        item("Generator", TrayAction::Generator),
        item("Settings…", TrayAction::Settings),
        Entry::Submenu {
            label: "Accounts".to_owned(),
            items: accounts,
        },
        Entry::Separator,
        Entry::Item {
            label: if state.locked { "Unlock" } else { "Lock" }.to_owned(),
            enabled: state.logged_in,
            action: TrayAction::LockToggle,
        },
        Entry::Item {
            label: if state.syncing {
                "Syncing…"
            } else {
                "Sync now"
            }
            .to_owned(),
            enabled: !state.locked && !state.syncing,
            action: TrayAction::SyncNow,
        },
    ];
    if !state.sync_label.is_empty() && state.logged_in {
        entries.push(Entry::Note(state.sync_label.clone()));
    }
    entries.push(Entry::Separator);
    if !state.update_label.is_empty() {
        entries.push(Entry::Item {
            label: state.update_label.clone(),
            enabled: state.update_enabled,
            action: TrayAction::Update,
        });
    }
    if state.restart_to_update && state.restart_by_hand {
        entries.push(Entry::Note(RESTART_BY_HAND.to_owned()));
    } else if state.restart_to_update {
        entries.push(item(
            "Restart to finish the update",
            TrayAction::RestartUpdated,
        ));
    }
    entries.push(item("Quit", TrayAction::Quit));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(entries: &[Entry]) -> Vec<&str> {
        entries
            .iter()
            .map(|entry| match entry {
                Entry::Item { label, .. } | Entry::Submenu { label, .. } => label.as_str(),
                Entry::Note(text) => text.as_str(),
                Entry::Separator => "-",
            })
            .collect()
    }

    fn unlocked() -> MenuState {
        MenuState {
            logged_in: true,
            ..MenuState::default()
        }
    }

    #[test]
    fn tray_menu_has_the_slint_items_in_order() {
        let entries = build(&unlocked());
        assert_eq!(
            labels(&entries),
            [
                "Open vault",
                "Quick search",
                "Generator",
                "Settings…",
                "Accounts",
                "-",
                "Lock",
                "Sync now",
                "-",
                "Quit"
            ]
        );
    }

    #[test]
    fn a_restart_the_daemon_cannot_do_is_a_note_not_an_action() {
        let entries = build(&MenuState {
            restart_to_update: true,
            restart_by_hand: true,
            ..unlocked()
        });
        assert!(entries.contains(&Entry::Note(RESTART_BY_HAND.to_owned())));
        assert!(!entries.iter().any(|entry| matches!(
            entry,
            Entry::Item {
                action: TrayAction::RestartUpdated,
                ..
            }
        )));
        let hidden = build(&MenuState {
            restart_by_hand: true,
            ..unlocked()
        });
        assert!(!hidden.contains(&Entry::Note(RESTART_BY_HAND.to_owned())));
    }

    #[test]
    fn tray_restart_item_shows_only_once_updated() {
        assert!(!labels(&build(&unlocked())).contains(&"Restart to finish the update"));
        let entries = build(&MenuState {
            restart_to_update: true,
            ..unlocked()
        });
        let shown = labels(&entries);
        assert_eq!(
            shown[shown.len() - 2..],
            ["Restart to finish the update", "Quit"]
        );
        assert!(entries.iter().any(|entry| matches!(
            entry,
            Entry::Item {
                action: TrayAction::RestartUpdated,
                enabled: true,
                ..
            }
        )));
    }

    #[test]
    fn tray_lock_item_follows_the_session() {
        let state = MenuState {
            locked: true,
            ..unlocked()
        };
        assert_eq!(labels(&build(&state))[6], "Unlock");
        let logged_out = MenuState::default();
        assert!(matches!(
            build(&logged_out)[6],
            Entry::Item { enabled: false, .. }
        ));
    }

    #[test]
    fn tray_sync_is_disabled_while_locked_or_syncing() {
        let sync_enabled = |state: &MenuState| {
            matches!(
                build(state)[7],
                Entry::Item {
                    enabled: true,
                    action: TrayAction::SyncNow,
                    ..
                }
            )
        };
        assert!(sync_enabled(&unlocked()));
        assert!(!sync_enabled(&MenuState {
            locked: true,
            ..unlocked()
        }));
        assert!(!sync_enabled(&MenuState {
            syncing: true,
            ..unlocked()
        }));
        assert_eq!(
            labels(&build(&MenuState {
                syncing: true,
                ..unlocked()
            }))[7],
            "Syncing…"
        );
    }

    #[test]
    fn tray_sync_note_needs_a_login_and_a_label() {
        let state = MenuState {
            sync_label: "Last synced 12:04".to_owned(),
            ..unlocked()
        };
        assert!(build(&state).contains(&Entry::Note("Last synced 12:04".to_owned())));
        let logged_out = MenuState {
            logged_in: false,
            ..state
        };
        assert!(
            !build(&logged_out)
                .iter()
                .any(|e| matches!(e, Entry::Note(_)))
        );
    }

    #[test]
    fn tray_accounts_switch_by_index() {
        let state = MenuState {
            accounts: vec!["✓ a@x @ one".to_owned(), "b@x @ two".to_owned()],
            ..unlocked()
        };
        let Entry::Submenu { items, .. } = &build(&state)[4] else {
            panic!("the fifth entry is the Accounts submenu");
        };
        assert_eq!(
            items[1],
            Entry::Item {
                label: "b@x @ two".to_owned(),
                enabled: true,
                action: TrayAction::SwitchAccount(1)
            }
        );
    }

    #[test]
    fn tray_labels_double_their_underscores() {
        assert_eq!(
            escape_label("first_last@example.com"),
            "first__last@example.com"
        );
        assert_eq!(escape_label("Open vault"), "Open vault");
    }

    #[test]
    fn tray_update_item_appears_only_with_a_label() {
        assert!(!build(&unlocked()).iter().any(|e| matches!(
            e,
            Entry::Item {
                action: TrayAction::Update,
                ..
            }
        )));
        let state = MenuState {
            update_label: "Install Vaultkeeper 0.2.0 and Restart".to_owned(),
            update_enabled: false,
            ..unlocked()
        };
        let entries = build(&state);
        assert!(entries.iter().any(|e| matches!(
            e,
            Entry::Item {
                enabled: false,
                action: TrayAction::Update,
                ..
            }
        )));
        assert_eq!(labels(&entries).last(), Some(&"Quit"));
    }
}
