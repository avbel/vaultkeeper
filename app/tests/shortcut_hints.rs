//! Inline shortcut hints are always shown; the icon-only New and Lock buttons keep their shortcuts
//! as descriptions.

mod common;

use common::{Mods, Setup, exists, harness, key};

#[test]
fn the_manager_shows_its_hints() {
    let h = harness(Setup::default());
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    assert!(exists(&manager, "New item"), "the icon-only New button");
    assert!(exists(&manager, "⌘F"), "the search field's key cap");
    assert!(exists(&manager, "Lock"), "the icon-only Lock button");
}

#[test]
fn the_lock_shortcut_locks() {
    let h = harness(Setup::default());
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    key(
        &manager,
        "l",
        Mods {
            cmd: true,
            shift: true,
        },
    );
    assert!(h.app.lock_window().is_some(), "⌘⇧L locks");
}
