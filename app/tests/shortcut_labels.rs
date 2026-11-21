//! Every shortcut label names the keys of its own platform: no ⌘ or Cmd on Windows, no Win key
//! on macOS.

mod common;

use common::{Setup, harness};
use slint::Global;
use vaultkeeper::{
    hotkey_recorder::{self, MODIFIER_HINT},
    settings::{DEFAULT_HOTKEY, hotkey_display},
    ui::Keys,
};

const SAMPLES: [&str; 6] = [
    DEFAULT_HOTKEY,
    "Cmd+Alt+G",
    "Ctrl+Shift+F5",
    "Cmd+Shift+KeyK",
    "Ctrl+Alt+ArrowLeft",
    "Alt+Ctrl+Digit1",
];

fn ctrl_keys_forbidden(text: &str) -> bool {
    text.contains('⌘') || text.contains("Cmd") || text.contains("Command") || text.contains('⌥')
}

fn macos_forbidden(text: &str) -> bool {
    text.contains("Win") || text.contains("Ctrl") || text.contains("Shift+")
}

fn forbidden(text: &str) -> bool {
    if cfg!(not(target_os = "macos")) {
        ctrl_keys_forbidden(text)
    } else {
        macos_forbidden(text)
    }
}

#[test]
fn hotkey_display_and_the_recorder_hint_use_the_platform_keys() {
    for accelerator in SAMPLES {
        let shown = hotkey_display(accelerator);
        assert!(!forbidden(&shown), "{accelerator} shown as {shown}");
    }
    assert!(!forbidden(MODIFIER_HINT), "{MODIFIER_HINT}");
    let error = hotkey_recorder::Reject::NeedsModifier.to_string();
    assert!(!forbidden(&error), "{error}");
    assert!(!forbidden(&hotkey_display(DEFAULT_HOTKEY)));
}

#[test]
fn the_default_hotkey_reads_naturally_on_each_platform() {
    let expected = if cfg!(not(target_os = "macos")) {
        "Ctrl+Shift+Space"
    } else {
        "⇧⌘Space"
    };
    assert_eq!(hotkey_display(DEFAULT_HOTKEY), expected);
}

#[test]
fn the_slint_labels_use_the_platform_keys() {
    let h = harness(Setup::default());
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    let keys = Keys::get(&manager);
    for label in [
        keys.get_cmd(),
        keys.get_shift(),
        keys.get_cmd_shift(),
        keys.get_enter(),
        keys.get_cmd_cap(),
        keys.get_shift_cap(),
        keys.get_cmd_shift_cap(),
    ] {
        assert!(!forbidden(label.as_str()), "{label}");
    }
    assert_eq!(keys.get_ctrl_keys(), cfg!(not(target_os = "macos")));
}
