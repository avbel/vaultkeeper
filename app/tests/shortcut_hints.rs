//! Inline shortcut hints are always shown; the Lock button keeps its shortcut as a description.

mod common;

use common::{Mods, Setup, exists, harness, key};

#[test]
fn the_manager_shows_its_hints() {
    let h = harness(Setup::default());
    h.app.start(false);
    let manager = h.app.manager_window().expect("manager");
    assert!(exists(&manager, "⌘N"), "the New button's hint");
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
