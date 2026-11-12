//! Manager Send section: list, copy link, reveal, create, edit, remove password, delete, and the
//! guards around the item list.

mod common;

use std::sync::{Arc, PoisonError};

use common::{
    Harness, Mods, Setup, click, harness, key, pump, set_size, special, type_into, value_of,
};
use slint::{Model, platform::Key};
use vaultkeeper::{mock::MockCall, send_view::NEW_SEND_INDEX, ui::ManagerWindow};

const LINK: i32 = 11;
const SEND_VIEW: i32 = 4;
const SEND_EDIT: i32 = 5;

fn open_with(setup: Setup) -> (Harness, ManagerWindow) {
    let h = harness(setup);
    // The mock's Sends are dated from the real clock; so is the list's "Deletes in …".
    *h.clock.0.lock().unwrap_or_else(PoisonError::into_inner) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs();
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    set_size(&manager, 1120.0, 1600.0);
    (h, manager)
}

fn open_sends() -> (Harness, ManagerWindow) {
    let (h, manager) = open_with(Setup::default());
    select_sidebar(&manager, "Send");
    (h, manager)
}

fn select_sidebar(manager: &ManagerWindow, label: &str) {
    let entries = manager.get_sidebar_entries();
    let index = (0..entries.row_count())
        .find(|row| {
            entries
                .row_data(*row)
                .is_some_and(|entry| entry.label == label)
        })
        .unwrap_or_else(|| panic!("no sidebar entry {label}"));
    manager.invoke_sidebar_select(i32::try_from(index).expect("small"));
    pump();
}

fn rows(manager: &ManagerWindow) -> Vec<(String, String)> {
    let rows = manager.get_rows();
    (0..rows.row_count())
        .filter_map(|row| rows.row_data(row))
        .map(|row| (row.name.to_string(), row.subtitle.to_string()))
        .collect()
}

fn names(manager: &ManagerWindow) -> Vec<String> {
    rows(manager).into_iter().map(|(name, _)| name).collect()
}

fn row_of(manager: &ManagerWindow, name: &str) -> i32 {
    let position = names(manager)
        .iter()
        .position(|candidate| candidate == name)
        .unwrap_or_else(|| panic!("{name} not listed"));
    i32::try_from(position).expect("small")
}

fn sends_saved(h: &Harness) -> Vec<(Option<Arc<str>>, String)> {
    h.vault
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            MockCall::SaveSend { id, name } => Some((id, name)),
            _ => None,
        })
        .collect()
}

#[test]
fn the_send_entry_lists_sends_by_name_with_their_state() {
    let (_h, manager) = open_sends();
    assert!(manager.get_send_mode());
    let listed = rows(&manager);
    assert_eq!(
        names(&manager),
        [
            "Door code",
            "Guest Wi-Fi",
            "Quarterly report",
            "Server recovery key"
        ]
    );
    assert!(listed[0].1.contains("1/3 views · password"), "{listed:?}");
    assert!(
        listed[1].1.starts_with("Deletes in 6 days")
            || listed[1].1.starts_with("Deletes in 7 days")
    );
    assert_eq!(listed[3].1, "View limit reached");
    let row = manager.get_rows().row_data(0).expect("row");
    assert_eq!((row.kind, row.b1, row.b2), (6, LINK, -1));

    select_sidebar(&manager, "All items");
    assert!(!manager.get_send_mode());
    assert!(!names(&manager).contains(&"Door code".to_owned()));
}

#[test]
fn the_row_button_and_return_copy_the_link() {
    let (h, manager) = open_sends();
    assert!(manager.invoke_copy_row(row_of(&manager, "Guest Wi-Fi"), LINK));
    let link = h.clipboard.last().expect("copied");
    assert!(link.contains("/#/send/send-wifi/"), "{link}");

    manager.invoke_row_clicked(row_of(&manager, "Door code"));
    pump();
    key(&manager, &special(Key::Return), Mods::default());
    assert!(
        h.clipboard
            .last()
            .is_some_and(|link| link.contains("/#/send/send-door/"))
    );
}

#[test]
fn hidden_text_stays_masked_until_revealed() {
    let (h, manager) = open_sends();
    manager.invoke_row_clicked(row_of(&manager, "Door code"));
    pump();
    assert_eq!(manager.get_detail_mode(), SEND_VIEW);
    let detail = manager.get_send_detail();
    assert_eq!(detail.text, "••••••••");
    assert!(detail.has_password && detail.text_secret);
    assert_eq!(detail.notes, "Given to the plumber");
    manager.invoke_send_toggle_text();
    assert_eq!(manager.get_send_detail().text, "4711#");
    assert!(manager.invoke_send_copy_text());
    assert_eq!(h.clipboard.last().as_deref(), Some("4711#"));
}

#[test]
fn a_new_send_is_saved_selected_and_its_link_copied() {
    let (h, manager) = open_with(Setup::default());
    manager.invoke_new_item(NEW_SEND_INDEX);
    pump();
    assert!(manager.get_send_mode(), "New ▸ Send opens the Send list");
    assert_eq!(manager.get_detail_mode(), SEND_EDIT);
    manager.invoke_send_save();
    assert_eq!(value_of(&manager, "Edit error"), "Give the Send a name");
    assert_eq!(sends_saved(&h), []);

    type_into(&manager, "Send name", "Alarm code");
    manager.set_send_text("1234".into());
    manager.set_send_max_views("zero".into());
    manager.invoke_send_save();
    assert!(manager.get_send_edit_error().contains("Maximum views"));
    manager.set_send_max_views("2".into());
    manager.set_send_password("open sesame".into());
    manager.invoke_send_save();
    pump();

    assert_eq!(sends_saved(&h), [(None, "Alarm code".to_owned())]);
    assert_eq!(manager.get_detail_mode(), SEND_VIEW);
    assert_eq!(manager.get_send_detail().name, "Alarm code");
    assert!(manager.get_send_detail().has_password);
    assert_eq!(manager.get_selected(), row_of(&manager, "Alarm code"));
    assert!(
        h.clipboard
            .last()
            .is_some_and(|link| link.contains("/#/send/send-new-"))
    );
    assert_eq!(
        manager.get_send_password(),
        "",
        "the form's secrets are cleared"
    );
}

#[test]
fn a_new_file_send_requires_a_file_and_copies_its_link_after_upload() {
    let (h, manager) = open_sends();
    manager.invoke_new_item(NEW_SEND_INDEX);
    pump();
    assert_eq!(manager.get_send_type(), 0);
    click(&manager, "File");
    assert_eq!(manager.get_send_type(), 1);
    manager.set_send_name("Report".into());
    manager.invoke_send_save();
    assert_eq!(manager.get_send_edit_error(), "Choose a file to share");

    let dir = tempfile::tempdir().expect("temporary folder");
    let source = dir.path().join("résumé.pdf");
    std::fs::File::create(&source)
        .expect("oversized file")
        .set_len(vk_vault::MAX_SEND_FILE_BYTES + 1)
        .expect("set file size");
    *h.files.open.lock().unwrap_or_else(PoisonError::into_inner) = Some(source.clone());
    click(&manager, "Choose file…");
    assert_eq!(
        manager.get_send_edit_error(),
        "File Sends are limited to 100 MB"
    );
    assert!(manager.get_send_file_name().is_empty());

    std::fs::OpenOptions::new()
        .write(true)
        .open(&source)
        .expect("selected file")
        .set_len(vk_vault::MAX_SEND_FILE_BYTES)
        .expect("set size to the limit");
    click(&manager, "Choose file…");
    assert_eq!(manager.get_send_file_name(), "résumé.pdf");
    assert!(manager.get_send_edit_error().is_empty());
    manager.set_send_password("open sesame".into());
    manager.set_send_notes("Only for my records".into());
    manager.invoke_send_save();
    pump();

    assert!(h.vault.calls().contains(&MockCall::CreateFileSend {
        name: "Report".into(),
        source,
    }));
    assert_eq!(manager.get_detail_mode(), SEND_VIEW);
    let detail = manager.get_send_detail();
    assert_eq!(detail.file_name, "résumé.pdf");
    assert_eq!(detail.notes, "Only for my records");
    assert!(detail.has_password);
    assert_eq!(manager.get_selected(), row_of(&manager, "Report"));
    assert!(
        h.clipboard
            .last()
            .is_some_and(|link| link.contains("/#/send/send-new-"))
    );
}

#[test]
fn an_edit_starts_from_the_send_and_saves_under_its_id() {
    let (h, manager) = open_sends();
    manager.invoke_row_clicked(row_of(&manager, "Guest Wi-Fi"));
    pump();
    manager.invoke_send_edit();
    pump();
    assert_eq!(manager.get_detail_mode(), SEND_EDIT);
    assert_eq!(manager.get_send_name(), "Guest Wi-Fi");
    assert!(manager.get_send_text().contains("correct horse"));
    assert_eq!(
        manager.get_send_deletion_index(),
        0,
        "keeps the current date"
    );
    assert!(
        manager
            .get_send_deletion_options()
            .row_data(0)
            .is_some_and(|label| label.starts_with("Keep"))
    );

    manager.invoke_row_clicked(row_of(&manager, "Door code"));
    assert_eq!(
        manager.get_send_name(),
        "Guest Wi-Fi",
        "the form stays open"
    );

    manager.set_send_name("Guest Wi-Fi (lobby)".into());
    manager.invoke_send_save();
    pump();
    assert_eq!(
        sends_saved(&h),
        [(
            Some(Arc::from("send-wifi")),
            "Guest Wi-Fi (lobby)".to_owned()
        )]
    );
    assert!(names(&manager).contains(&"Guest Wi-Fi (lobby)".to_owned()));
}

#[test]
fn escape_closes_the_form_without_saving() {
    let (h, manager) = open_sends();
    manager.invoke_row_clicked(row_of(&manager, "Guest Wi-Fi"));
    pump();
    manager.invoke_send_edit();
    manager.set_send_text("changed".into());
    key(&manager, &special(Key::Escape), Mods::default());
    assert_eq!(manager.get_detail_mode(), SEND_VIEW);
    assert_eq!(sends_saved(&h), []);
    assert_eq!(manager.get_send_text(), "");
}

#[test]
fn a_form_is_never_dropped_by_switching_lists() {
    let (_h, manager) = open_sends();
    manager.invoke_new_item(NEW_SEND_INDEX);
    pump();
    select_sidebar(&manager, "All items");
    assert!(manager.get_send_mode());
    assert_eq!(manager.get_detail_mode(), SEND_EDIT);
    assert_eq!(manager.get_toast_text(), "Save or cancel the edit first");
}

#[test]
fn remove_password_and_delete_go_to_the_vault() {
    let (h, manager) = open_sends();
    manager.invoke_row_clicked(row_of(&manager, "Door code"));
    pump();
    manager.invoke_send_remove_password_confirmed();
    pump();
    assert!(!manager.get_send_detail().has_password);
    manager.invoke_send_delete_confirmed();
    pump();
    let calls = h.vault.calls();
    assert!(calls.contains(&MockCall::RemoveSendPassword("send-door".to_owned())));
    assert!(calls.contains(&MockCall::DeleteSend("send-door".to_owned())));
    assert!(!names(&manager).contains(&"Door code".to_owned()));
    assert_eq!(manager.get_detail_mode(), 0);
}

#[test]
fn file_sends_can_be_linked_but_not_edited() {
    let (_h, manager) = open_sends();
    manager.invoke_row_clicked(row_of(&manager, "Quarterly report"));
    pump();
    let detail = manager.get_send_detail();
    assert!(!detail.is_text);
    assert_eq!(detail.file_name, "q3-report.pdf");
    manager.invoke_send_edit();
    assert_eq!(manager.get_detail_mode(), SEND_VIEW);
}

#[test]
fn search_filters_sends_by_name() {
    let (_h, manager) = open_sends();
    manager.set_query("wi-fi".into());
    manager.invoke_search_edited("wi-fi".into());
    assert_eq!(names(&manager), ["Guest Wi-Fi"]);
    manager.set_query("nothing like it".into());
    manager.invoke_search_edited("nothing like it".into());
    assert_eq!(names(&manager), [""; 0]);
    assert_eq!(manager.get_empty_kind(), 1);
}

#[test]
fn offline_sends_stay_readable_but_no_form_opens() {
    let (h, manager) = open_with(Setup {
        offline: true,
        ..Setup::default()
    });
    select_sidebar(&manager, "Send");
    assert_eq!(names(&manager).len(), 4);
    manager.invoke_new_item(NEW_SEND_INDEX);
    pump();
    assert_ne!(manager.get_detail_mode(), SEND_EDIT);
    assert_eq!(
        manager.get_toast_text(),
        "Sends can't be changed while offline"
    );
    assert!(manager.invoke_copy_row(0, LINK));
    assert!(h.clipboard.last().is_some());
}

#[test]
fn locking_closes_the_manager_and_its_send_pane() {
    let (h, manager) = open_sends();
    manager.invoke_row_clicked(row_of(&manager, "Door code"));
    manager.invoke_send_toggle_text();
    h.app.lock();
    pump();
    assert!(h.app.manager_window().is_none());
    assert!(
        !h.app
            .view_strings()
            .iter()
            .any(|text| text.contains("4711#"))
    );
}
