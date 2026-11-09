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
    CMD, Harness, Setup, block_on, click, control_exists, elapse, enabled, find, harness, key,
    pump, set_size, special, type_into, value_of,
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

fn edit_name(manager: &ManagerWindow) -> String {
    manager
        .get_edit_fields()
        .row_data(0)
        .expect("name field")
        .value
        .to_string()
}

fn start_dirty_edit(manager: &ManagerWindow) {
    manager.invoke_row_clicked(row_of(manager, "GitHub"));
    pump();
    click(manager, "Edit");
    type_into(manager, "Name", "GitHub (draft)");
    manager.invoke_row_clicked(row_of(manager, "Slack"));
    pump();
}

#[test]
fn clicking_another_row_while_editing_asks_before_discarding() {
    let (h, manager) = open();
    start_dirty_edit(&manager);
    assert!(manager.get_confirm_leave());
    assert_eq!(manager.get_detail_mode(), 2, "the form stays open");
    assert_eq!(edit_name(&manager), "GitHub (draft)");
    click(&manager, "Keep editing");
    assert!(!manager.get_confirm_leave());
    assert_eq!(manager.get_detail_mode(), 2);
    assert_eq!(edit_name(&manager), "GitHub (draft)");
    assert!(h.vault.last_saved().is_none());
}

#[test]
fn discarding_switches_to_the_clicked_row_and_clears_the_edit_model() {
    let (h, manager) = open();
    start_dirty_edit(&manager);
    click(&manager, "Discard changes and switch");
    pump();
    assert_eq!(manager.get_detail_mode(), 1);
    assert_eq!(manager.get_detail_header().name, "Slack");
    assert!(!manager.get_confirm_leave());
    assert_eq!(manager.get_edit_fields().row_count(), 0);
    assert!(h.vault.last_saved().is_none());
}

#[test]
fn saving_from_the_prompt_stores_the_edit_then_switches() {
    let (h, manager) = open();
    start_dirty_edit(&manager);
    click(&manager, "Save changes and switch");
    pump();
    let saved = h.vault.last_saved().expect("saved");
    assert_eq!(saved.name, "GitHub (draft)");
    assert_eq!(manager.get_detail_mode(), 1);
    assert_eq!(manager.get_detail_header().name, "Slack");
    assert_eq!(manager.get_edit_fields().row_count(), 0);
}

#[test]
fn choosing_login_in_the_new_menu_opens_the_new_login_form() {
    let (_h, manager) = open();
    click(&manager, "New item");
    pump();
    click(&manager, "Login");
    pump();
    assert_eq!(manager.get_detail_mode(), 2, "the edit form is open");
    assert_eq!(manager.get_edit_title(), "New login");
}

#[test]
fn add_account_in_the_account_menu_opens_the_login_window() {
    let (h, manager) = open();
    click(&manager, "Accounts");
    pump();
    click(&manager, "Add account");
    pump();
    assert!(h.app.login_window().is_some());
}

#[test]
fn picking_an_account_in_the_account_menu_switches_to_it() {
    let (h, manager) = open();
    click(&manager, "Accounts");
    pump();
    let label = h
        .vault
        .accounts()
        .into_iter()
        .find(|account| &*account.email == "bob@work.example.org")
        .map(|account| {
            format!(
                "{} @ {}",
                account.email,
                bw_lite::viewmodel::host(&account.server)
            )
        })
        .expect("bob");
    click(&manager, &label);
    pump();
    assert!(
        matches!(h.vault.state(), bwl_vault::model::SessionState::Locked { ref email, .. } if email == "bob@work.example.org")
    );
}

#[test]
fn the_password_generate_button_opens_the_generator_whose_use_fills_the_field() {
    let (h, manager) = open();
    click(&manager, "New item");
    pump();
    click(&manager, "Login");
    pump();
    click(&manager, "Generate Password");
    pump();
    assert_eq!(manager.get_detail_mode(), 3, "the generator slide-over");
    let state = manager.global::<bw_lite::ui::GeneratorState>();
    assert!(state.get_can_use());
    let generated = state.get_result().to_string();
    assert_ne!(generated, "");
    click(&manager, "Copy generated value");
    assert_eq!(h.clipboard.last().as_deref(), Some(generated.as_str()));
    click(&manager, "Use this password");
    pump();
    assert_eq!(manager.get_detail_mode(), 2, "back to the form");
    let fields = manager.get_edit_fields();
    let password = (0..fields.row_count())
        .filter_map(|row| fields.row_data(row))
        .find(|field| field.key == "password")
        .expect("password row");
    assert_eq!(password.value.as_str(), generated);
    assert!(
        !state.get_can_use(),
        "no Use button when opened another way"
    );
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
    click(&manager, "Show Private key");
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
    click(&manager, "Show Private key");
    type_into(&manager, "Private key", "-----BEGIN NOTHING-----");
    click(&manager, "Save");
    assert!(value_of(&manager, "Edit error").contains("Not a usable private key"));
}

#[test]
fn editing_the_private_key_recomputes_its_public_key_and_fingerprint_at_once() {
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
    click(&manager, "Show Private key");
    let field = |key: &str| {
        let fields = manager.get_edit_fields();
        (0..fields.row_count())
            .filter_map(|row| fields.row_data(row))
            .find(|field| field.key == key)
            .map(|field| field.value.to_string())
            .expect("field")
    };
    let generated_public = field("public_key");
    type_into(&manager, "Private key", "-----BEGIN OPENSSH PRIVATE");
    assert_eq!(
        field("public_key"),
        generated_public,
        "kept while unreadable"
    );
    type_into(&manager, "Private key", &pasted);
    assert_eq!(field("public_key"), public_key);
    assert_eq!(field("fingerprint"), fingerprint);
    assert_eq!(
        field("private_key"),
        pasted.as_str(),
        "the typed text is left as is"
    );
}

fn item_id(h: &Harness, name: &str) -> bwl_vault::model::ItemId {
    h.vault
        .search(name, &Filter::default())
        .expect("search")
        .iter()
        .find(|item| item.name.as_ref() == name)
        .expect("item")
        .id
        .clone()
}

fn field_row(manager: &ManagerWindow, label: &str) -> usize {
    let fields = manager.get_detail_fields();
    (0..fields.row_count())
        .find(|row| fields.row_data(*row).is_some_and(|f| f.label == label))
        .unwrap_or_else(|| panic!("no {label} row"))
}

/// The value of the text input labelled `label`, if one is shown (its caption is a `Text` with
/// the same label).
fn input_value(manager: &ManagerWindow, label: &str) -> Option<String> {
    i_slint_backend_testing::ElementHandle::find_by_accessible_label(manager, label)
        .find(|element| {
            element.accessible_role() == Some(i_slint_backend_testing::AccessibleRole::TextInput)
        })
        .and_then(|element| element.accessible_value())
        .map(|value| value.to_string())
}

fn confirm_reprompt(manager: &ManagerWindow) {
    type_into(
        manager,
        "Reprompt master password",
        bw_lite::mock::MOCK_MASTER_PASSWORD,
    );
    click(manager, "Confirm master password");
}

#[test]
fn every_way_into_the_editor_asks_for_the_master_password_of_a_reprompt_item() {
    type Start = fn(&ManagerWindow);
    let entries: [(&str, Start); 3] = [
        ("Edit button", |manager| click(manager, "Edit")),
        ("⌘E", |manager| key(manager, "e", CMD)),
        ("double-click", |manager| {
            manager.invoke_row_double_clicked(row_of(manager, "PayPal"));
            pump();
        }),
    ];
    for (entry, start) in entries {
        let (_h, manager) = open();
        type_into(&manager, "Search vault", "paypal");
        manager.invoke_row_clicked(row_of(&manager, "PayPal"));
        pump();
        start(&manager);
        assert_eq!(manager.get_detail_mode(), 1, "{entry}: no form yet");
        assert_eq!(manager.get_edit_fields().row_count(), 0, "{entry}");
        assert!(manager.get_reprompt_visible(), "{entry}");
        confirm_reprompt(&manager);
        assert_eq!(manager.get_detail_mode(), 2, "{entry}: the form opens");
        assert!(manager.get_edit_reprompt(), "{entry}");
    }
}

#[test]
fn reprompt_hides_notes_and_totp_codes_until_the_password_is_confirmed() {
    let (h, manager) = open();
    type_into(&manager, "Search vault", "paypal");
    let row = usize::try_from(row_of(&manager, "PayPal")).expect("row");
    let listed = manager.get_rows().row_data(row).expect("row");
    assert!(listed.has_totp);
    assert_eq!(listed.totp_code, "", "no live code in the list");
    manager.invoke_row_clicked(row_of(&manager, "PayPal"));
    pump();
    assert_eq!(manager.get_detail_totp_code(), "••• •••");
    let notes = field_row(&manager, "Notes");
    let fields = manager.get_detail_fields();
    assert_eq!(fields.row_data(notes).expect("f").value, "••••••••");
    assert!(fields.row_data(notes).expect("f").secret);
    let copies = h.clipboard.count();
    assert!(!manager.invoke_copy_field(i32::try_from(notes).expect("small")));
    assert_eq!(h.clipboard.count(), copies, "notes are not copied");
    assert!(manager.get_reprompt_visible());

    confirm_reprompt(&manager);
    assert_eq!(
        h.clipboard.last().as_deref(),
        Some("Security answer: blue heron")
    );
    assert_eq!(
        manager.get_detail_totp_code().len(),
        7,
        "{}",
        manager.get_detail_totp_code()
    );
    let listed = manager.get_rows().row_data(row).expect("row");
    assert_eq!(listed.totp_code.len(), 7, "{}", listed.totp_code);
    manager.invoke_reveal_field(i32::try_from(notes).expect("small"));
    assert_eq!(
        manager
            .get_detail_fields()
            .row_data(notes)
            .expect("f")
            .value,
        "Security answer: blue heron"
    );
}

#[test]
fn the_ssh_private_key_is_masked_in_the_editor_until_shown() {
    let (h, manager) = open();
    type_into(&manager, "Search vault", "homelab");
    let name = "homelab";
    manager.invoke_row_clicked(row_of(&manager, name));
    pump();
    click(&manager, "Edit");
    assert_eq!(manager.get_detail_mode(), 2);
    let private = reveal(&h, name, CopyField::SshPrivateKey);
    let masked = input_value(&manager, "Private key");
    assert!(
        masked.as_deref().is_none_or(str::is_empty),
        "masked: {masked:?}"
    );
    click(&manager, "Show Private key");
    assert_eq!(input_value(&manager, "Private key"), Some(private));
}

#[test]
fn a_save_after_the_item_changed_elsewhere_is_refused_and_keeps_the_form() {
    let (h, manager) = open();
    manager.invoke_row_clicked(row_of(&manager, "GitHub"));
    pump();
    click(&manager, "Edit");
    type_into(&manager, "Name", "GitHub (desktop)");
    h.vault
        .edit_elsewhere(&item_id(&h, "GitHub"), "GitHub (phone)")
        .expect("remote edit");
    h.app.on_vault_changed();
    pump();
    assert_eq!(
        manager.get_detail_mode(),
        2,
        "the open form is not replaced"
    );

    click(&manager, "Save");
    assert_eq!(manager.get_detail_mode(), 2, "the form stays open");
    assert!(
        value_of(&manager, "Edit error").starts_with(bwl_vault::CONFLICT_MESSAGE),
        "{}",
        value_of(&manager, "Edit error")
    );
    assert_eq!(
        input_value(&manager, "Name").as_deref(),
        Some("GitHub (desktop)"),
        "nothing typed is lost"
    );
    assert!(
        !h.vault
            .calls()
            .iter()
            .any(|call| matches!(call, MockCall::Save { .. })),
        "nothing was written"
    );

    click(&manager, "Cancel");
    assert_eq!(manager.get_detail_mode(), 1);
    assert_eq!(manager.get_detail_header().name, "GitHub (phone)");
    click(&manager, "Edit");
    type_into(&manager, "Name", "GitHub (desktop)");
    click(&manager, "Save");
    assert_eq!(
        h.vault.last_saved().expect("saved").name,
        "GitHub (desktop)",
        "an edit of the latest version saves"
    );
    assert_eq!(manager.get_detail_mode(), 1);
}

#[test]
fn the_edit_form_keeps_the_picked_folder_when_the_folder_list_changes() {
    let (h, manager) = open();
    manager.invoke_row_clicked(row_of(&manager, "GitHub"));
    pump();
    click(&manager, "Edit");
    let options = |manager: &ManagerWindow| -> Vec<String> {
        manager
            .get_folder_options()
            .iter()
            .map(|option| option.to_string())
            .collect()
    };
    let travel = options(&manager)
        .iter()
        .position(|option| option == "Travel")
        .expect("Travel option");
    let travel = i32::try_from(travel).expect("small");
    manager.set_edit_folder_index(travel);
    manager.invoke_edit_folder_selected(travel);
    block_on(h.vault.create_folder("Aardvark")).expect("folder");
    h.app.on_vault_changed();
    pump();
    let index = usize::try_from(manager.get_edit_folder_index()).expect("index");
    assert_eq!(
        options(&manager)[index],
        "Travel",
        "the picker follows the id"
    );
    click(&manager, "Save");
    assert_eq!(
        h.vault.last_saved().expect("save").folder_id.as_deref(),
        Some("f-travel")
    );
}

#[test]
fn a_hidden_custom_field_without_a_visible_value_has_no_reveal_or_copy() {
    let (h, manager) = open();
    let draft = bwl_vault::model::ItemDraft {
        name: "Shared note".to_owned(),
        notes: zeroize::Zeroizing::new(String::new()),
        folder_id: None,
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: false,
        reprompt: false,
        fields: vec![bwl_vault::model::CustomField {
            name: "Locked PIN".to_owned(),
            value: zeroize::Zeroizing::new(String::new()),
            hidden: true,
        }],
        data: ItemData::SecureNote,
        revision_date: None,
    };
    block_on(h.vault.save(None, draft)).expect("save");
    h.app.on_vault_changed();
    pump();
    manager.invoke_row_clicked(row_of(&manager, "Shared note"));
    pump();
    let row = field_row(&manager, "Locked PIN");
    let field = manager.get_detail_fields().row_data(row).expect("field");
    assert!(!field.secret, "no mask, so no reveal control");
    assert_eq!(field.copy, -1, "no copy control");
    assert_eq!(field.value, "");
}
