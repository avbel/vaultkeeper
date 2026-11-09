//! Quick Panel auto-type (⌘⇧↩ and the row button): what reaches the typing hook, and every case
//! that must type nothing. Posting real keystrokes is macOS-only and not exercised here.

mod common;

use std::sync::atomic::Ordering;

use bw_lite::{UiCommand, hooks::TypingTarget, mock::MOCK_MASTER_PASSWORD, settings::Settings};
use bwl_vault::{
    VaultService,
    model::{CopyField, Filter, ItemData, ItemDraft},
};
use common::{
    CMD, CMD_SHIFT, Harness, Mods, Setup, block_on, click, enabled, exists, harness, key, pump,
    safari, special, type_into,
};
use slint::platform::Key;
use zeroize::Zeroizing;

const NO_TARGET: &str = "No app to type into: open the Quick Panel from that app";
const ACCESSIBILITY: &str =
    "Allow bw-lite in System Settings → Privacy & Security → Accessibility, then try again";

/// Opens the panel the way the global hotkey does, with Safari in front.
fn hotkey(h: &Harness) -> bw_lite::ui::QuickPanel {
    hotkey_from(h, Some(safari()))
}

/// The global hotkey with `target` as the app the daemon saw in front.
fn hotkey_from(h: &Harness, target: Option<TypingTarget>) -> bw_lite::ui::QuickPanel {
    h.app.handle(UiCommand::ToggleQuickPanel { target });
    // As the daemon command loop does after every command.
    h.app.show_pending_notices();
    h.app.quick_panel().expect("quick panel")
}

fn secret(h: &Harness, name: &str, field: CopyField) -> String {
    let item = h.vault.search(name, &Filter::default()).expect("search")[0].clone();
    h.vault.reveal(&item.id, field).expect("reveal").to_string()
}

fn auto_type(panel: &bw_lite::ui::QuickPanel) {
    key(panel, &special(Key::Return), CMD_SHIFT);
}

#[test]
fn cmd_shift_enter_types_username_tab_password_into_the_app_behind_and_closes() {
    let h = harness(Setup::default());
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    let expected = format!(
        "alice.smith\t{}",
        secret(&h, "Tailscale", CopyField::Password)
    );
    assert_eq!(h.autotype.typed(), [(safari(), expected)]);
    assert!(h.app.quick_panel().is_none(), "the panel closes first");
    assert_eq!(h.clipboard.count(), 0, "never through the clipboard");
    assert_eq!(*h.autotype.trust_checks.lock().expect("checks"), [true]);
}

#[test]
fn the_row_button_types_the_login_of_its_row() {
    let h = harness(Setup::default());
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    click(&panel, "Auto-type");
    let typed = h.autotype.typed();
    assert_eq!(typed.len(), 1);
    assert!(typed[0].1.starts_with("alice.smith\t"));
    assert!(h.app.quick_panel().is_none());
}

#[test]
fn a_login_without_a_username_types_only_the_password() {
    let h = harness(Setup::default());
    let draft = ItemDraft {
        name: "Router admin".to_owned(),
        notes: Zeroizing::new(String::new()),
        folder_id: None,
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: false,
        reprompt: false,
        fields: Vec::new(),
        data: ItemData::Login {
            username: String::new(),
            password: Zeroizing::new("hunter2!".to_owned()),
            totp: Zeroizing::new(String::new()),
            uris: Vec::new(),
        },
        revision_date: None,
    };
    block_on(h.vault.save(None, draft)).expect("save");
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "router admin");
    auto_type(&panel);
    assert_eq!(h.autotype.typed(), [(safari(), "hunter2!".to_owned())]);
}

#[test]
fn other_kinds_type_nothing_and_their_button_is_off() {
    let h = harness(Setup::default());
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "personal visa");
    assert!(!enabled(&panel, "Auto-type"));
    auto_type(&panel);
    assert_eq!(h.autotype.typed().len(), 0);
    assert!(h.app.quick_panel().is_some(), "nothing happened");
}

#[test]
fn a_reprompt_item_needs_the_master_password_first() {
    let h = harness(Setup::default());
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "paypal");
    auto_type(&panel);
    assert_eq!(h.autotype.typed().len(), 0);
    let panel = h.app.quick_panel().expect("stays open");
    assert_eq!(
        panel.get_toast_text(),
        "Open in Manager (⌘O) to confirm your master password"
    );
    key(&panel, "e", CMD);
    let manager = h.app.manager_window().expect("manager");
    type_into(&manager, "Reprompt master password", MOCK_MASTER_PASSWORD);
    click(&manager, "Confirm master password");
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "paypal");
    auto_type(&panel);
    let typed = h.autotype.typed();
    assert_eq!(typed.len(), 1, "typed once confirmed");
    assert!(
        typed[0]
            .1
            .ends_with(&secret(&h, "PayPal", CopyField::Password))
    );
}

#[test]
fn a_locked_vault_types_nothing() {
    let h = harness(Setup {
        unlocked: false,
        ..Setup::default()
    });
    let panel = hotkey(&h);
    assert!(panel.get_locked());
    auto_type(&panel);
    assert_eq!(h.autotype.typed().len(), 0);
    assert_eq!(h.autotype.trust_checks.lock().expect("checks").len(), 0);
}

#[test]
fn locking_while_typing_stops_it_and_says_so_next_time() {
    let h = harness(Setup::default());
    h.autotype.hold.store(true, Ordering::SeqCst);
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    assert_eq!(h.app.open_window_count(), 1, "typing keeps the process");
    h.app.lock();
    assert_eq!(h.autotype.cancels.load(Ordering::SeqCst), 1);
    pump();
    assert_eq!(h.app.open_window_count(), 0);
    let panel = hotkey(&h);
    assert!(panel.get_locked());
    assert_eq!(
        panel.get_toast_text(),
        "Auto-type stopped: the vault locked"
    );
}

#[test]
fn without_accessibility_macos_is_asked_and_nothing_is_typed() {
    let h = harness(Setup::default());
    h.autotype.trusted.store(false, Ordering::SeqCst);
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    assert_eq!(h.autotype.typed().len(), 0);
    assert_eq!(
        *h.autotype.trust_checks.lock().expect("checks"),
        [true],
        "asked with the system prompt"
    );
    let panel = h.app.quick_panel().expect("stays open");
    assert!(panel.get_toast_shown());
    assert_eq!(panel.get_toast_text(), ACCESSIBILITY);
    // The system dialog takes the focus and the panel closes; the next one repeats the hint.
    h.app.handle(UiCommand::ToggleQuickPanel {
        target: Some(safari()),
    });
    assert!(h.app.quick_panel().is_none());
    let panel = hotkey(&h);
    assert_eq!(panel.get_toast_text(), ACCESSIBILITY);
    panel.invoke_toast_dismissed();
    h.app.handle(UiCommand::ToggleQuickPanel {
        target: Some(safari()),
    });
    let panel = hotkey(&h);
    assert!(!panel.get_toast_shown(), "a read hint is not repeated");
}

#[test]
fn a_typing_failure_is_shown_when_a_window_shows_next() {
    let h = harness(Setup::default());
    *h.autotype.fail_with.lock().expect("fail") =
        Some("Auto-type stopped: another app came to the front".to_owned());
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    assert!(h.app.quick_panel().is_none());
    let panel = hotkey(&h);
    assert!(panel.get_toast_shown());
    assert_eq!(
        panel.get_toast_text(),
        "Auto-type stopped: another app came to the front"
    );
}

#[test]
fn with_bw_lite_in_front_there_is_nothing_to_type_into() {
    let h = harness(Setup::default());
    // The daemon sends no target when bw-lite itself was in front.
    let panel = hotkey_from(&h, None);
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    assert_eq!(h.autotype.typed().len(), 0);
    let panel = h.app.quick_panel().expect("stays open");
    assert!(panel.get_toast_shown());
    assert_eq!(panel.get_toast_text(), NO_TARGET);
}

#[test]
fn no_target_is_said_on_the_panel_even_with_the_manager_open() {
    let h = harness(Setup::default());
    h.app.handle(UiCommand::ShowManager);
    let manager = h.app.manager_window().expect("manager");
    let panel = hotkey_from(&h, None);
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    assert_eq!(h.autotype.typed().len(), 0);
    let panel = h.app.quick_panel().expect("stays open");
    assert!(panel.get_toast_shown(), "where the user pressed ⌘⇧↩");
    assert_eq!(panel.get_toast_text(), NO_TARGET);
    assert!(!manager.get_toast_shown(), "not on the Manager behind");
}

#[test]
fn the_target_from_the_daemon_is_typed_into_although_bw_lite_is_in_front_now() {
    let h = harness(Setup::default());
    // A UI process started on demand, or left active by the last panel, sees only itself.
    *h.autotype.frontmost.lock().expect("frontmost") = None;
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    let typed = h.autotype.typed();
    assert_eq!(typed.len(), 1);
    assert_eq!(typed[0].0, safari());
}

#[test]
fn a_target_naming_this_process_is_dropped() {
    let h = harness(Setup::default());
    let own = TypingTarget {
        pid: i32::try_from(std::process::id()).expect("pid"),
        name: "bw-lite".to_owned(),
    };
    let panel = hotkey_from(&h, Some(own));
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    assert_eq!(h.autotype.typed().len(), 0);
    assert_eq!(panel.get_toast_text(), NO_TARGET);
}

#[test]
fn a_panel_opened_inside_the_app_does_not_reuse_an_old_target() {
    let h = harness(Setup::default());
    hotkey(&h);
    h.app.handle(UiCommand::ToggleQuickPanel {
        target: Some(safari()),
    });
    h.app.toggle_quick_panel();
    let panel = h.app.quick_panel().expect("panel");
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    assert_eq!(h.autotype.typed().len(), 0);
}

#[test]
fn the_shortcut_hint_follows_show_keyboard_shortcuts_and_the_legend_stays() {
    let h = harness(Setup::default());
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    assert!(exists(&panel, "⌘⇧↩"), "the selected row's hint");
    assert!(exists(&panel, "auto-type"), "the footer legend");
    let h = harness(Setup {
        settings: Settings {
            show_shortcuts: false,
            ..Settings::default()
        },
        ..Setup::default()
    });
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    assert!(!exists(&panel, "⌘⇧↩"), "hint hidden");
    assert!(exists(&panel, "Auto-type"), "the button stays");
    assert!(exists(&panel, "auto-type"), "the footer legend stays");
}

#[test]
fn plain_return_and_its_other_variants_still_copy() {
    let h = harness(Setup::default());
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    key(&panel, &special(Key::Return), Mods::default());
    assert_eq!(
        h.clipboard.last(),
        Some(secret(&h, "Tailscale", CopyField::Password))
    );
    assert_eq!(h.autotype.typed().len(), 0);
}

#[test]
fn esc_hands_the_front_back_and_the_windowless_app_steps_aside() {
    let h = harness(Setup::default());
    let panel = hotkey(&h);
    key(&panel, &special(Key::Escape), Mods::default());
    assert!(h.app.quick_panel().is_none());
    assert_eq!(
        *h.autotype.given_back.lock().expect("given back"),
        [safari()]
    );
    pump();
    assert_eq!(h.dock.hides(), 1, "no windowless bw-lite left in front");
    // So the daemon sees Safari again for the next hotkey, and typing goes there.
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    assert_eq!(h.autotype.typed()[0].0, safari());
}

#[test]
fn the_hotkey_on_an_open_panel_closes_it_without_activating_bw_lite() {
    let h = harness(Setup::default());
    hotkey(&h);
    let activations = h.dock.activations.load(Ordering::SeqCst);
    h.app.handle(UiCommand::ToggleQuickPanel {
        target: Some(safari()),
    });
    assert!(h.app.quick_panel().is_none());
    assert_eq!(h.dock.activations.load(Ordering::SeqCst), activations);
    assert_eq!(
        *h.autotype.given_back.lock().expect("given back"),
        [safari()]
    );
}

#[test]
fn a_keyboard_copy_or_lost_focus_also_hands_the_front_back() {
    let h = harness(Setup::default());
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    key(&panel, &special(Key::Return), Mods::default());
    assert!(h.app.quick_panel().is_none());
    let panel = hotkey(&h);
    panel.invoke_focus_lost();
    pump();
    assert!(h.app.quick_panel().is_none());
    assert_eq!(
        *h.autotype.given_back.lock().expect("given back"),
        [safari(), safari()]
    );
}

#[test]
fn opening_the_manager_or_typing_keeps_the_front_and_nothing_hides_under_the_manager() {
    let h = harness(Setup::default());
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    key(&panel, "e", CMD);
    assert!(h.app.manager_window().is_some());
    let panel = hotkey(&h);
    key(&panel, &special(Key::Escape), Mods::default());
    pump();
    assert!(
        h.autotype.given_back.lock().expect("given back").is_empty(),
        "the Manager stays the user's window"
    );
    assert_eq!(h.dock.hides(), 0, "a window is still open");
}

#[test]
fn typing_activates_the_target_itself_and_bw_lite_steps_aside_after() {
    let h = harness(Setup::default());
    let panel = hotkey(&h);
    type_into(&panel, "Quick search", "tailscale");
    auto_type(&panel);
    pump();
    assert!(h.autotype.given_back.lock().expect("given back").is_empty());
    // The panel closing and the typing ending each check; the fake types at once, so both see
    // no window.
    assert!(h.dock.hides() >= 1);
}
