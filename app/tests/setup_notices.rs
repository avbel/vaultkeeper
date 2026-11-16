//! What the daemon could not set up (an SSH agent whose pipe is taken, shortcuts the OS refused)
//! reaches Settings, including when it was reported before the window existed.

mod common;

use common::{Setup, click, harness, pump, set_size};
use vaultkeeper::{
    UiCommand,
    hooks::SettingsStore as _,
    hotkey_recorder::{ALTGR_WARNING, UNAVAILABLE_NOTICE},
};

const PIPE_TAKEN: &str = "Another program already serves the Windows SSH agent pipe. Close it.";

fn refused(quick_panel: bool, generator: bool) -> UiCommand {
    UiCommand::HotkeyIssues {
        quick_panel,
        generator,
    }
}

#[test]
fn a_refused_shortcut_is_marked_in_settings_opened_later() {
    let h = harness(Setup::default());
    h.app.handle(refused(true, false));
    h.app.open_settings();
    let window = h.app.settings_window().expect("settings window");
    assert_eq!(window.get_hotkey_note(), UNAVAILABLE_NOTICE);
    assert!(window.get_hotkey_note_is_error());
    assert_eq!(window.get_generator_hotkey_note(), "");
}

#[test]
fn a_report_updates_and_clears_an_open_settings_window() {
    let h = harness(Setup::default());
    h.app.open_settings();
    let window = h.app.settings_window().expect("settings window");
    assert_eq!(window.get_generator_hotkey_note(), "");

    h.app.handle(refused(false, true));
    assert_eq!(window.get_generator_hotkey_note(), UNAVAILABLE_NOTICE);

    h.app.handle(refused(false, false));
    assert_eq!(window.get_generator_hotkey_note(), "");
}

#[test]
fn saving_another_shortcut_clears_that_slots_notice_until_the_daemon_says_otherwise() {
    let h = harness(Setup::default());
    h.app.handle(refused(true, false));
    h.app.open_settings();
    let window = h.app.settings_window().expect("settings window");

    window.invoke_hotkey_accepted("Ctrl+Shift+F5".into());
    pump();

    assert_eq!(h.settings.load().hotkey, "Ctrl+Shift+F5");
    assert!(!window.get_hotkey_note_is_error());
    assert_ne!(window.get_hotkey_note(), UNAVAILABLE_NOTICE);
}

#[test]
fn the_altgr_hint_is_not_an_error_and_does_not_block_saving() {
    let h = harness(Setup::default());
    h.app.open_settings();
    let window = h.app.settings_window().expect("settings window");

    window.invoke_generator_hotkey_accepted("Ctrl+Alt+G".into());
    pump();

    assert_eq!(h.settings.load().generator_hotkey, "Ctrl+Alt+G");
    assert!(!window.get_generator_hotkey_note_is_error());
    let expected = if cfg!(windows) { ALTGR_WARNING } else { "" };
    assert_eq!(window.get_generator_hotkey_note(), expected);
}

#[test]
fn a_failed_ssh_agent_turns_the_setting_off_and_says_why() {
    let h = harness(Setup {
        settings: vaultkeeper::settings::Settings {
            ssh_agent: true,
            ..vaultkeeper::settings::Settings::default()
        },
        ..Setup::default()
    });
    h.app
        .handle(UiCommand::SshAgentFailed(PIPE_TAKEN.to_owned()));
    assert!(!h.settings.load().ssh_agent);

    h.app.open_settings();
    let window = h.app.settings_window().expect("settings window");
    set_size(&window, 520.0, 2400.0);
    assert!(!window.get_ssh_agent());
    assert_eq!(window.get_ssh_notice(), PIPE_TAKEN);

    click(&window, "SSH agent");
    assert!(h.settings.load().ssh_agent);
    assert_eq!(window.get_ssh_notice(), "");
}
