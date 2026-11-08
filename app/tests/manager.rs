//! Manager scenarios: search, sidebar filters and folders, one-click copy, edit, delete,
//! attachments, offline mode, TOTP timer and window lifetime.

mod common;

use std::{path::PathBuf, sync::PoisonError, time::Duration};

use bw_lite::{mock::MockCall, ui::ManagerWindow};
use bwl_vault::{
    VaultService,
    model::{CopyField, Filter, ItemData, ItemKind},
};
use common::{
    CMD, Harness, Setup, click, control_exists, elapse, enabled, find, harness, key, pump,
    set_size, special, type_into, value_of,
};
use slint::{ComponentHandle, Model, platform::Key};

fn open() -> (Harness, ManagerWindow) {
    let h = harness(Setup::default());
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    // Element queries skip scrolled-out items, so the window is tall enough for every control.
    set_size(&manager, 1120.0, 1600.0);
    (h, manager)
}

fn row_names(manager: &ManagerWindow) -> Vec<String> {
    let rows = manager.get_rows();
    (0..rows.row_count())
        .filter_map(|row| rows.row_data(row))
        .map(|row| row.name.to_string())
        .collect()
}

fn row_of(manager: &ManagerWindow, name: &str) -> i32 {
    let position = row_names(manager)
        .iter()
        .position(|candidate| candidate == name)
        .unwrap_or_else(|| panic!("{name} not listed"));
    i32::try_from(position).expect("small")
}

fn sidebar_index(manager: &ManagerWindow, label: &str) -> i32 {
    let entries = manager.get_sidebar_entries();
    let index = (0..entries.row_count())
        .find(|row| {
            entries
                .row_data(*row)
                .is_some_and(|entry| entry.label == label)
        })
        .unwrap_or_else(|| panic!("no sidebar entry {label}"));
    i32::try_from(index).expect("small")
}

fn sidebar_count(manager: &ManagerWindow, label: &str) -> String {
    let index = usize::try_from(sidebar_index(manager, label)).expect("index");
    manager
        .get_sidebar_entries()
        .row_data(index)
        .expect("entry")
        .count
        .to_string()
}

fn reveal(h: &Harness, name: &str, field: CopyField) -> String {
    let item = h
        .vault
        .search(name, &Filter::default())
        .expect("search")
        .iter()
        .find(|item| item.name.as_ref() == name)
        .expect("item")
        .clone();
    h.vault.reveal(&item.id, field).expect("reveal").to_string()
}

#[test]
fn search_filters_the_list_and_esc_clears_it() {
    let (_h, manager) = open();
    let all = manager.get_rows().row_count();
    assert!(all > 400 - 20, "{all}");
    type_into(&manager, "Search vault", "github");
    let names = row_names(&manager);
    assert_eq!(names[0], "GitHub");
    assert!(
        names
            .iter()
            .all(|name| name.to_lowercase().contains("github"))
    );
    type_into(&manager, "Search vault", "zzzz-nothing");
    assert_eq!(manager.get_rows().row_count(), 0);
    assert_eq!(manager.get_empty_kind(), 1, "no-results empty state");
    key(&manager, &special(Key::Escape), common::Mods::default());
    assert_eq!(manager.get_query(), "");
    assert_eq!(manager.get_rows().row_count(), all);
}

#[test]
fn sidebar_selection_filters_by_type_folder_and_trash() {
    let (_h, manager) = open();
    click(&manager, "Cards");
    let rows = manager.get_rows();
    assert_eq!(rows.row_count(), 20);
    assert!((0..20).all(|row| rows.row_data(row).is_some_and(|data| data.kind == 2)));
    click(&manager, "Dev");
    assert_eq!(
        manager.get_rows().row_count(),
        sidebar_count(&manager, "Dev")
            .parse::<usize>()
            .expect("count")
    );
    click(&manager, "Trash");
    assert_eq!(row_names(&manager), ["Old router login"]);
    key(&manager, "4", CMD);
    let rows = manager.get_rows();
    assert_eq!(rows.row_count(), 40, "⌘4 = secure notes");
    assert_eq!(
        manager.get_sidebar_selected(),
        sidebar_index(&manager, "Secure notes")
    );
}

#[test]
fn one_click_copy_buttons_put_the_right_value_on_the_clipboard() {
    let (h, manager) = open();
    let github = row_of(&manager, "GitHub");
    // The first row's real "Copy password" button, then the same callback for other fields.
    click(&manager, "Copy password");
    assert_eq!(
        h.clipboard.last().as_deref(),
        Some(reveal(&h, "GitHub", CopyField::Password).as_str())
    );
    assert!(manager.invoke_copy_row(github, 0));
    assert_eq!(h.clipboard.last().as_deref(), Some("octocat"));
    let tailscale = row_of(&manager, "Tailscale");
    assert!(manager.invoke_copy_row(tailscale, 2));
    let expected = h
        .vault
        .totp(
            &h.vault.search("Tailscale", &Filter::default()).expect("s")[0].id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_secs(),
        )
        .expect("totp");
    assert_eq!(h.clipboard.last().as_deref(), Some(expected.code.as_str()));
    assert_eq!(
        value_of(&manager, "Clipboard"),
        "Copied TOTP · clears in 30s"
    );
    let card = row_of(&manager, "Personal Visa");
    assert!(manager.invoke_copy_row(card, 5));
    assert_eq!(h.clipboard.last().as_deref(), Some("4242 4242 4242 4242"));
    let copies = h
        .clipboard
        .copies
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert!(
        copies
            .iter()
            .all(|(_, clear)| *clear == Some(Duration::from_secs(30)))
    );
}

#[test]
fn keyboard_moves_the_selection_and_enter_copies_the_password() {
    let (h, manager) = open();
    key(&manager, &special(Key::DownArrow), common::Mods::default());
    assert_eq!(manager.get_selected(), 0);
    assert!(manager.get_keyboard_nav());
    key(&manager, &special(Key::DownArrow), common::Mods::default());
    assert_eq!(manager.get_selected(), 1);
    key(&manager, &special(Key::Return), common::Mods::default());
    let second = row_names(&manager)[1].clone();
    assert_eq!(
        h.clipboard.last().as_deref(),
        Some(reveal(&h, &second, CopyField::Password).as_str())
    );
    assert_eq!(manager.get_detail_header().name, second.as_str());
}

#[test]
fn row_totp_codes_come_from_one_timer_that_stops_with_the_window() {
    let (h, manager) = open();
    let tailscale = usize::try_from(row_of(&manager, "Tailscale")).expect("row");
    let row = manager.get_rows().row_data(tailscale).expect("row");
    assert!(row.has_totp);
    assert_eq!(
        row.totp_code.len(),
        7,
        "grouped 6 digits: {}",
        row.totp_code
    );
    assert!(h.app.totp_timer_running());
    click(&manager, "Cards");
    assert!(
        !h.app.totp_timer_running(),
        "no visible TOTP rows, no timer"
    );
    click(&manager, "All items");
    assert!(h.app.totp_timer_running());
    let weak = manager.as_weak();
    drop(manager);
    h.app
        .manager_window()
        .expect("manager")
        .window()
        .dispatch_event(slint::platform::WindowEvent::CloseRequested);
    pump();
    assert!(h.app.manager_window().is_none());
    assert!(
        weak.upgrade().is_none(),
        "the closed Manager is dropped, not hidden"
    );
    assert!(!h.app.totp_timer_running());
}

#[test]
fn edit_and_save_sends_the_edited_draft() {
    let (h, manager) = open();
    manager.invoke_row_clicked(row_of(&manager, "GitHub"));
    pump();
    click(&manager, "Edit");
    assert_eq!(manager.get_detail_mode(), 2);
    type_into(&manager, "Password", "correct horse battery");
    type_into(&manager, "Name", "GitHub (personal)");
    click(&manager, "Save");
    let saved = h.vault.last_saved().expect("save called");
    assert_eq!(saved.name, "GitHub (personal)");
    let ItemData::Login {
        password, username, ..
    } = &saved.data
    else {
        panic!("login draft expected");
    };
    assert_eq!(password.as_str(), "correct horse battery");
    assert_eq!(username, "octocat", "untouched fields are kept");
    assert_eq!(manager.get_detail_mode(), 1);
    assert_eq!(manager.get_detail_header().name, "GitHub (personal)");
}

#[test]
fn new_item_requires_a_name_and_saves_into_the_selected_folder() {
    let (h, manager) = open();
    click(&manager, "Dev");
    manager.invoke_new_item(0);
    pump();
    click(&manager, "Save");
    assert_eq!(value_of(&manager, "Edit error"), "Name is required");
    type_into(&manager, "Name", "New service");
    type_into(&manager, "Username", "me");
    click(&manager, "Save");
    let saved = h.vault.last_saved().expect("save");
    assert_eq!(saved.name, "New service");
    assert_eq!(saved.folder_id.as_deref(), Some("f-dev"));
    assert!(row_names(&manager).contains(&"New service".to_owned()));
}

#[test]
fn delete_needs_the_inline_confirm() {
    let (h, manager) = open();
    manager.invoke_row_clicked(row_of(&manager, "Slack"));
    pump();
    click(&manager, "Delete");
    assert!(manager.get_confirm_delete());
    click(&manager, "Cancel delete");
    assert!(!manager.get_confirm_delete());
    assert!(
        !h.vault
            .calls()
            .iter()
            .any(|call| matches!(call, MockCall::Trash(_)))
    );
    click(&manager, "Delete");
    click(&manager, "Confirm delete");
    assert!(
        h.vault
            .calls()
            .iter()
            .any(|call| matches!(call, MockCall::Trash(_)))
    );
    assert!(!row_names(&manager).contains(&"Slack".to_owned()));
    assert_eq!(manager.get_detail_mode(), 0);
    assert_eq!(sidebar_count(&manager, "Trash"), "2");
}

#[test]
fn inline_delete_confirm_cancels_itself_after_six_seconds() {
    let (_h, manager) = open();
    manager.invoke_row_clicked(row_of(&manager, "Slack"));
    pump();
    click(&manager, "Delete");
    assert!(manager.get_confirm_delete());
    elapse(Duration::from_secs(7));
    assert!(!manager.get_confirm_delete());
}

#[test]
fn attachments_list_save_attach_and_delete_with_confirm() {
    let (h, manager) = open();
    manager.invoke_row_clicked(row_of(&manager, "Server runbook"));
    pump();
    let attachments = manager.get_attachments();
    assert_eq!(attachments.row_count(), 1);
    let first = attachments.row_data(0).expect("attachment");
    assert_eq!(
        (first.name.as_str(), first.size.as_str()),
        ("runbook.pdf", "248.0 KB")
    );
    let dest = PathBuf::from("/tmp/runbook-copy.pdf");
    *h.files
        .save_to
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(dest.clone());
    click(&manager, "Save runbook.pdf");
    assert!(
        h.vault.calls().contains(&MockCall::Download {
            item: h
                .vault
                .search("Server runbook", &Filter::default())
                .expect("s")[0]
                .id
                .clone(),
            attachment: "att-runbook".to_owned(),
            dest,
        })
    );
    let source = PathBuf::from("/nonexistent/notes.txt");
    *h.files.open.lock().unwrap_or_else(PoisonError::into_inner) = Some(source.clone());
    click(&manager, "+ Attach file");
    assert!(
        h.vault
            .calls()
            .iter()
            .any(|call| matches!(call, MockCall::Upload { source: s, .. } if *s == source))
    );
    assert_eq!(manager.get_attachments().row_count(), 2);
    assert!(!manager.get_attach_busy());
    click(&manager, "Delete runbook.pdf");
    assert_eq!(manager.get_attachment_confirm(), 0);
    click(&manager, "Confirm delete runbook.pdf");
    assert!(h.vault.calls().iter().any(|call| matches!(call, MockCall::DeleteAttachment { attachment, .. } if attachment == "att-runbook")));
    assert_eq!(manager.get_attachments().row_count(), 1);
}

#[test]
fn offline_shows_the_toast_and_disables_writes() {
    let h = harness(Setup {
        offline: true,
        ..Setup::default()
    });
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    assert!(manager.get_toast_shown());
    assert_eq!(
        manager.get_toast_text(),
        "Offline mode — showing cached vault"
    );
    assert!(!manager.get_online());
    assert!(value_of(&manager, "Status").starts_with("Offline"));
    manager.invoke_row_clicked(row_of(&manager, "Server runbook"));
    pump();
    assert!(!enabled(&manager, "+ Attach file"));
    assert!(!enabled(&manager, "Save runbook.pdf"));
    assert!(!enabled(&manager, "Edit"));
    assert!(!enabled(&manager, "New folder"));
    manager.invoke_create_folder("Ops".into());
    manager.invoke_attach_file();
    pump();
    assert!(
        !h.vault
            .calls()
            .iter()
            .any(|call| matches!(call, MockCall::CreateFolder(_) | MockCall::Upload { .. }))
    );
    elapse(Duration::from_secs(5));
    assert!(!manager.get_toast_shown(), "the toast dismisses itself");
}

#[test]
fn folders_create_rename_and_delete_inline() {
    let (h, manager) = open();
    let no_folder_before: usize = sidebar_count(&manager, "No folder").parse().expect("count");
    click(&manager, "New folder");
    assert!(manager.get_sidebar_adding());
    type_into(&manager, "New folder name", "Ops");
    key(&manager, &special(Key::Return), common::Mods::default());
    assert!(
        h.vault
            .calls()
            .contains(&MockCall::CreateFolder("Ops".to_owned()))
    );
    assert_eq!(sidebar_count(&manager, "Ops"), "0");
    let ops = sidebar_index(&manager, "Ops");
    manager.set_sidebar_renaming(ops);
    pump();
    type_into(&manager, "Folder name", "Operations");
    key(&manager, &special(Key::Return), common::Mods::default());
    let ops_id = h
        .vault
        .folders()
        .expect("folders")
        .iter()
        .find(|folder| folder.name.as_ref() == "Operations")
        .expect("renamed")
        .id
        .to_string();
    assert!(h.vault.calls().contains(&MockCall::RenameFolder {
        id: ops_id,
        name: "Operations".to_owned()
    }));
    let dev_count: usize = sidebar_count(&manager, "Dev").parse().expect("count");
    manager.set_sidebar_confirm_delete(sidebar_index(&manager, "Dev"));
    pump();
    click(&manager, "Cancel delete folder");
    assert!(
        !h.vault
            .calls()
            .contains(&MockCall::DeleteFolder("f-dev".to_owned()))
    );
    manager.set_sidebar_confirm_delete(sidebar_index(&manager, "Dev"));
    pump();
    click(&manager, "Confirm delete folder");
    assert!(
        h.vault
            .calls()
            .contains(&MockCall::DeleteFolder("f-dev".to_owned()))
    );
    assert!(!control_exists(&manager, "Dev"));
    let no_folder_after: usize = sidebar_count(&manager, "No folder").parse().expect("count");
    assert_eq!(
        no_folder_after,
        no_folder_before + dev_count,
        "counts update after the change"
    );
}

#[test]
fn sidebar_collapses_with_cmd_backslash() {
    let (_h, manager) = open();
    assert!(!manager.get_sidebar_collapsed());
    key(&manager, "\\", CMD);
    assert!(manager.get_sidebar_collapsed());
    click(&manager, "Show sidebar");
    assert!(!manager.get_sidebar_collapsed());
}

#[test]
fn move_to_folder_from_the_detail_pane_saves_the_new_folder() {
    let (h, manager) = open();
    manager.invoke_row_clicked(row_of(&manager, "GitHub"));
    pump();
    let options: Vec<String> = manager
        .get_folder_options()
        .iter()
        .map(|option| option.to_string())
        .collect();
    let travel = options
        .iter()
        .position(|option| option == "Travel")
        .expect("Travel option");
    manager.invoke_move_to_folder(i32::try_from(travel).expect("small"));
    pump();
    assert_eq!(
        h.vault.last_saved().expect("save").folder_id.as_deref(),
        Some("f-travel")
    );
}

#[test]
fn reveal_toggles_a_masked_field_from_the_draft() {
    let (h, manager) = open();
    manager.invoke_row_clicked(row_of(&manager, "GitHub"));
    pump();
    let fields = manager.get_detail_fields();
    let password = (0..fields.row_count())
        .find(|row| fields.row_data(*row).is_some_and(|f| f.label == "Password"))
        .expect("password row");
    assert_eq!(fields.row_data(password).expect("f").value, "••••••••");
    manager.invoke_reveal_field(i32::try_from(password).expect("small"));
    assert_eq!(
        fields.row_data(password).expect("f").value.as_str(),
        reveal(&h, "GitHub", CopyField::Password)
    );
    manager.invoke_reveal_field(i32::try_from(password).expect("small"));
    assert_eq!(fields.row_data(password).expect("f").value, "••••••••");
    let _ = find(&manager, "Item name");
    assert_eq!(value_of(&manager, "Item name"), "GitHub");
    assert!(
        h.vault
            .search(
                "",
                &Filter {
                    kind: Some(ItemKind::Login),
                    ..Filter::default()
                }
            )
            .is_ok()
    );
}

#[test]
fn reprompt_items_need_the_master_password_before_secrets_are_copied() {
    let (h, manager) = open();
    type_into(&manager, "Search vault", "paypal");
    let row = row_of(&manager, "PayPal");
    assert!(
        manager.invoke_copy_row(row, 0),
        "the username is not a secret"
    );
    assert!(
        !manager.invoke_copy_row(row, 1),
        "the password is held back"
    );
    assert_eq!(
        h.clipboard.last().as_deref(),
        Some(reveal(&h, "PayPal", CopyField::Username).as_str())
    );
    assert!(manager.get_reprompt_visible());
    assert_eq!(manager.get_detail_header().name, "PayPal");
    type_into(&manager, "Reprompt master password", "wrong");
    click(&manager, "Confirm master password");
    assert_eq!(
        value_of(&manager, "Reprompt error"),
        "Wrong master password · try again"
    );
    assert_eq!(
        h.clipboard.last().as_deref(),
        Some(reveal(&h, "PayPal", CopyField::Username).as_str())
    );
    type_into(
        &manager,
        "Reprompt master password",
        bw_lite::mock::MOCK_MASTER_PASSWORD,
    );
    click(&manager, "Confirm master password");
    assert!(!manager.get_reprompt_visible());
    assert_eq!(
        h.clipboard.last().as_deref(),
        Some(reveal(&h, "PayPal", CopyField::Password).as_str())
    );
    assert!(
        manager.invoke_copy_row(row, 1),
        "confirmed until the next lock"
    );
    h.app.lock();
    pump();
    assert!(h.app.manager_window().is_none());
}

#[test]
fn reprompt_also_guards_reveal_in_the_detail_pane() {
    let (h, manager) = open();
    type_into(&manager, "Search vault", "paypal");
    manager.invoke_row_clicked(row_of(&manager, "PayPal"));
    pump();
    let fields = manager.get_detail_fields();
    let password = (0..fields.row_count())
        .find(|row| fields.row_data(*row).is_some_and(|f| f.label == "Password"))
        .expect("password row");
    let index = i32::try_from(password).expect("small");
    manager.invoke_reveal_field(index);
    assert_eq!(
        fields.row_data(password).expect("f").value,
        "••••••••",
        "still masked"
    );
    assert!(manager.get_reprompt_visible());
    type_into(
        &manager,
        "Reprompt master password",
        bw_lite::mock::MOCK_MASTER_PASSWORD,
    );
    click(&manager, "Confirm master password");
    let fields = manager.get_detail_fields();
    assert_eq!(
        fields.row_data(password).expect("f").value.as_str(),
        reveal(&h, "PayPal", CopyField::Password)
    );
}

#[test]
fn a_collection_lists_only_its_items_not_the_whole_organization() {
    let (_h, manager) = open();
    // The mock organization holds 24 items: every third in Finance, the rest in Engineering.
    click(&manager, "Acme Corp");
    assert_eq!(manager.get_rows().row_count(), 24);
    // A folder is also called "Finance"; the collection is the entry under the organization.
    let entries = manager.get_sidebar_entries();
    let organization = sidebar_index(&manager, "Acme Corp");
    let collection = |label: &str| {
        (usize::try_from(organization).expect("index")..entries.row_count())
            .find(|row| {
                entries
                    .row_data(*row)
                    .is_some_and(|entry| entry.label == label)
            })
            .and_then(|row| i32::try_from(row).ok())
            .unwrap_or_else(|| panic!("no collection {label}"))
    };
    manager.invoke_sidebar_select(collection("Finance"));
    pump();
    let finance = row_names(&manager);
    assert_eq!(finance.len(), 8);
    manager.invoke_sidebar_select(collection("Engineering"));
    pump();
    let engineering = row_names(&manager);
    assert_eq!(engineering.len(), 16);
    assert!(finance.iter().all(|name| !engineering.contains(name)));
    assert!(
        finance
            .iter()
            .chain(&engineering)
            .all(|name| name.starts_with("Acme "))
    );
}

#[test]
fn a_pasted_private_key_is_stored_as_openssh_with_its_public_key() {
    let h = harness(Setup {
        ssh_keys: Some(std::sync::Arc::new(bw_lite::os::SshKeys)),
        ..Setup::default()
    });
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    set_size(&manager, 1120.0, 1600.0);
    let (pasted, public_key, fingerprint) = bwl_ssh::generate_ed25519().expect("key");
    manager.invoke_new_item(4);
    pump();
    type_into(&manager, "Name", "pasted key");
    type_into(&manager, "Private key", &pasted);
    type_into(&manager, "Public key", "stale");
    click(&manager, "Save");
    let saved = h.vault.last_saved().expect("save");
    let ItemData::SshKey {
        public_key: saved_public,
        fingerprint: saved_fingerprint,
        ..
    } = &saved.data
    else {
        panic!("SSH key draft expected");
    };
    assert_eq!(saved_public, &public_key, "derived from the private key");
    assert_eq!(saved_fingerprint, &fingerprint);

    manager.invoke_new_item(4);
    pump();
    type_into(&manager, "Name", "garbage");
    type_into(&manager, "Private key", "-----BEGIN NOTHING-----");
    click(&manager, "Save");
    assert!(value_of(&manager, "Edit error").contains("Not a usable private key"));
}
