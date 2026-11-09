//! Quick Panel: keyboard copies, dismissal, MRU, locked inline unlock and window lifetime.

mod common;

use bw_lite::mock::MOCK_MASTER_PASSWORD;
use bwl_vault::{
    VaultService,
    model::{CopyField, Filter},
};
use common::{CMD, Harness, Mods, SHIFT, Setup, harness, key, pump, special, type_into};
use slint::{ComponentHandle, Model, platform::Key};

fn open(unlocked: bool) -> (Harness, bw_lite::ui::QuickPanel) {
    let h = harness(Setup {
        unlocked,
        ..Setup::default()
    });
    h.app.toggle_quick_panel();
    let panel = h.app.quick_panel().expect("quick panel");
    (h, panel)
}

#[test]
fn the_panel_is_placed_with_its_real_size_not_the_unshown_zero_size() {
    let (h, panel) = open(true);
    let requested = *h.placement.requested.lock().expect("placement");
    assert_eq!(
        requested,
        Some((panel.get_panel_width(), panel.get_panel_height()))
    );
    assert_eq!(requested.map(|(width, _)| width), Some(560.0));
    assert!(requested.is_some_and(|(_, height)| height > 0.0));
}

fn expected(h: &Harness, name: &str, field: CopyField) -> String {
    let item = h.vault.search(name, &Filter::default()).expect("search")[0].clone();
    h.vault.reveal(&item.id, field).expect("reveal").to_string()
}

#[test]
fn empty_query_lists_the_eight_most_recent_items() {
    let (_h, panel) = open(true);
    let rows = panel.get_rows();
    assert_eq!(rows.row_count(), 8);
    let names: Vec<String> = (0..8)
        .filter_map(|row| rows.row_data(row))
        .map(|row| row.name.to_string())
        .collect();
    assert_eq!(
        &names[..4],
        ["GitHub", "AWS Console", "Gmail", "Personal Visa"]
    );
    assert_eq!(panel.get_selected(), 0);
}

#[test]
fn enter_copies_the_password_and_dismisses() {
    let (h, panel) = open(true);
    type_into(&panel, "Quick search", "gith");
    key(&panel, &special(Key::Return), Mods::default());
    assert_eq!(
        h.clipboard.last(),
        Some(expected(&h, "GitHub", CopyField::Password))
    );
    assert!(
        h.app.quick_panel().is_none(),
        "keyboard copies dismiss the panel"
    );
}

#[test]
fn shift_enter_copies_the_username_and_cmd_enter_the_totp() {
    let (h, panel) = open(true);
    type_into(&panel, "Quick search", "tailscale");
    key(&panel, &special(Key::Return), SHIFT);
    assert_eq!(h.clipboard.last().as_deref(), Some("alice.smith"));
    h.app.toggle_quick_panel();
    let panel = h.app.quick_panel().expect("panel again");
    type_into(&panel, "Quick search", "tailscale");
    key(&panel, &special(Key::Return), CMD);
    assert_eq!(
        h.clipboard.last(),
        Some(expected(&h, "Tailscale", CopyField::Totp))
    );
    assert_eq!(h.clipboard.last().map(|code| code.len()), Some(6));
}

#[test]
fn arrows_move_the_selection_before_copying() {
    let (h, panel) = open(true);
    key(&panel, &special(Key::DownArrow), Mods::default());
    key(&panel, &special(Key::DownArrow), Mods::default());
    assert_eq!(panel.get_selected(), 2);
    key(&panel, &special(Key::UpArrow), Mods::default());
    assert_eq!(panel.get_selected(), 1);
    key(&panel, &special(Key::Return), Mods::default());
    assert_eq!(
        h.clipboard.last(),
        Some(expected(&h, "AWS Console", CopyField::Password))
    );
}

#[test]
fn escape_clears_the_query_then_closes_and_the_panel_is_dropped() {
    let (_h, panel) = open(true);
    type_into(&panel, "Quick search", "slack");
    key(&panel, &special(Key::Escape), Mods::default());
    assert_eq!(panel.get_query(), "");
    assert_eq!(panel.get_rows().row_count(), 8);
    let weak = panel.as_weak();
    key(&panel, &special(Key::Escape), Mods::default());
    drop(panel);
    pump();
    assert!(
        weak.upgrade().is_none(),
        "a closed Quick Panel is dropped, not hidden"
    );
}

#[test]
fn losing_focus_hides_the_panel() {
    let (h, panel) = open(true);
    panel
        .window()
        .dispatch_event(slint::platform::WindowEvent::WindowActiveChanged(true));
    pump();
    panel
        .window()
        .dispatch_event(slint::platform::WindowEvent::WindowActiveChanged(false));
    pump();
    assert!(h.app.quick_panel().is_none());
}

#[test]
fn mouse_copy_keeps_the_panel_open() {
    let (h, panel) = open(true);
    assert!(panel.invoke_copy_row(0, 0));
    assert_eq!(h.clipboard.last().as_deref(), Some("octocat"));
    assert!(h.app.quick_panel().is_some());
}

#[test]
fn locked_panel_unlocks_inline_and_then_searches() {
    let (h, panel) = open(false);
    assert!(panel.get_locked());
    assert_eq!(
        panel.get_rows().row_count(),
        0,
        "no vault data while locked"
    );
    assert!(h.app.lock_window().is_none(), "the panel unlocks inline");
    type_into(&panel, "Master password", "wrong");
    panel.invoke_unlock(panel.get_password());
    pump();
    assert!(panel.get_unlock_error().contains("attempt 1"));
    panel.invoke_unlock(MOCK_MASTER_PASSWORD.into());
    pump();
    let panel = h.app.quick_panel().expect("still open after unlock");
    assert!(!panel.get_locked());
    assert_eq!(panel.get_rows().row_count(), 8);
    assert!(
        h.app.manager_window().is_none(),
        "unlocking from the panel does not open the Manager"
    );
}

#[test]
fn cmd_o_opens_the_item_in_the_manager() {
    let (h, panel) = open(true);
    type_into(&panel, "Quick search", "slack");
    key(&panel, "o", CMD);
    assert!(h.app.quick_panel().is_none());
    let manager = h.app.manager_window().expect("manager");
    assert_eq!(manager.get_detail_header().name, "Slack");
}

#[test]
fn reprompt_items_are_refused_in_the_quick_panel() {
    let (h, panel) = open(true);
    type_into(&panel, "Quick search", "paypal");
    key(&panel, &special(Key::Return), Mods::default());
    assert_eq!(
        h.clipboard.count(),
        0,
        "no secret without the master password"
    );
    let panel = h.app.quick_panel().expect("the panel stays open");
    assert!(panel.get_toast_shown());
    assert_eq!(
        panel.get_toast_text(),
        "Open in Manager (⌘O) to confirm your master password"
    );
    drop(panel);
}

fn selected_name(panel: &bw_lite::ui::QuickPanel) -> String {
    let row = usize::try_from(panel.get_selected()).expect("row");
    panel
        .get_rows()
        .row_data(row)
        .expect("row")
        .name
        .to_string()
}

#[test]
fn a_vault_change_keeps_the_selected_item_not_the_row_number() {
    let (h, panel) = open(true);
    key(&panel, &special(Key::DownArrow), Mods::default());
    key(&panel, &special(Key::DownArrow), Mods::default());
    assert_eq!(selected_name(&panel), "Gmail");
    let visa = h
        .vault
        .search("Personal Visa", &Filter::default())
        .expect("search")[0]
        .clone();
    h.vault
        .reveal(&visa.id, CopyField::CardNumber)
        .expect("used elsewhere");
    h.app.on_vault_changed();
    pump();
    let first = panel.get_rows().row_data(0).expect("row").name.to_string();
    assert_eq!(first, "Personal Visa", "the MRU order changed");
    assert_eq!(selected_name(&panel), "Gmail");
    key(&panel, &special(Key::Return), Mods::default());
    assert_eq!(
        h.clipboard.last(),
        Some(expected(&h, "Gmail", CopyField::Password))
    );
}

#[test]
fn a_new_query_starts_at_the_top_again() {
    let (_h, panel) = open(true);
    key(&panel, &special(Key::DownArrow), Mods::default());
    type_into(&panel, "Quick search", "g");
    assert_eq!(panel.get_selected(), 0);
}

#[test]
fn the_master_password_is_cleared_after_an_inline_unlock() {
    let (h, panel) = open(false);
    type_into(&panel, "Master password", MOCK_MASTER_PASSWORD);
    panel.invoke_unlock(panel.get_password());
    pump();
    let panel = h.app.quick_panel().expect("still open after unlock");
    assert!(!panel.get_locked());
    assert_eq!(panel.get_password(), "");
}

#[test]
fn cmd_e_on_a_reprompt_item_asks_for_the_master_password_first() {
    let (h, panel) = open(true);
    type_into(&panel, "Quick search", "paypal");
    key(&panel, "e", CMD);
    let manager = h.app.manager_window().expect("manager");
    assert_eq!(manager.get_detail_header().name, "PayPal");
    assert_eq!(manager.get_detail_mode(), 1, "no edit form yet");
    assert!(manager.get_reprompt_visible());
    type_into(&manager, "Reprompt master password", MOCK_MASTER_PASSWORD);
    common::click(&manager, "Confirm master password");
    assert_eq!(manager.get_detail_mode(), 2);
}
