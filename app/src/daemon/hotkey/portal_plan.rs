//! What the portal backend binds and how it reads the answers: plain functions over the saved
//! accelerators, so the rules test on any host.

use crate::{daemon::routing::HotkeySlot, shortcut_syntax::portal_trigger};

pub const QUICK_PANEL_ID: &str = "quick-panel";
pub const GENERATOR_ID: &str = "generator";

pub const fn shortcut_id(slot: HotkeySlot) -> &'static str {
    match slot {
        HotkeySlot::QuickPanel => QUICK_PANEL_ID,
        HotkeySlot::Generator => GENERATOR_ID,
    }
}

pub fn slot_for_id(id: &str) -> Option<HotkeySlot> {
    match id {
        QUICK_PANEL_ID => Some(HotkeySlot::QuickPanel),
        GENERATOR_ID => Some(HotkeySlot::Generator),
        _ => None,
    }
}

/// The preferred trigger per slot; slots without an accelerator, or with one that has no portal
/// spelling, are left out.
pub fn desired(accelerators: &[(HotkeySlot, String)]) -> Vec<(HotkeySlot, String)> {
    accelerators
        .iter()
        .filter_map(|(slot, accelerator)| {
            if accelerator.trim().is_empty() {
                return None;
            }
            let trigger = portal_trigger(accelerator);
            if trigger.is_none() {
                tracing::warn!(?slot, accelerator, "no portal trigger for this shortcut");
            }
            trigger.map(|trigger| (*slot, trigger))
        })
        .collect()
}

/// A portal keeps the bindings it was given, so only something new or changed is sent again.
pub fn needs_bind(bound: &[(HotkeySlot, String)], desired: &[(HotkeySlot, String)]) -> bool {
    desired.iter().any(|entry| !bound.contains(entry))
}

/// The desktop's own wording of the Quick Panel and Generator triggers, from `(id, description)`
/// pairs; a shortcut the desktop does not list has none.
pub fn trigger_descriptions<'a>(
    shortcuts: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> (String, String) {
    let (mut quick_panel, mut generator) = (String::new(), String::new());
    for (id, trigger) in shortcuts {
        match slot_for_id(id) {
            Some(HotkeySlot::QuickPanel) => trigger.clone_into(&mut quick_panel),
            Some(HotkeySlot::Generator) => trigger.clone_into(&mut generator),
            None => {}
        }
    }
    (quick_panel, generator)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Wanted = Vec<(HotkeySlot, String)>;

    fn wanted(quick: &str, generator: &str) -> Vec<(HotkeySlot, String)> {
        vec![
            (HotkeySlot::QuickPanel, quick.to_owned()),
            (HotkeySlot::Generator, generator.to_owned()),
        ]
    }

    #[test]
    fn ids_round_trip_and_strangers_are_ignored() {
        for slot in [HotkeySlot::QuickPanel, HotkeySlot::Generator] {
            assert_eq!(slot_for_id(shortcut_id(slot)), Some(slot));
        }
        assert_eq!(slot_for_id("other"), None);
        assert_eq!(shortcut_id(HotkeySlot::QuickPanel), "quick-panel");
        assert_eq!(shortcut_id(HotkeySlot::Generator), "generator");
    }

    #[test]
    fn only_slots_with_a_usable_accelerator_are_wanted() {
        assert_eq!(
            desired(&wanted("Ctrl+Shift+Space", "")),
            vec![(HotkeySlot::QuickPanel, "CTRL+SHIFT+space".to_owned())]
        );
        assert_eq!(desired(&wanted("", "Ctrl+Alt+G")).len(), 1);
        assert_eq!(desired(&wanted("Ctrl+", "  ")), Wanted::new());
    }

    #[test]
    fn a_new_or_changed_trigger_is_bound_again_and_a_removed_one_is_not() {
        let both = desired(&wanted("Ctrl+Shift+Space", "Ctrl+Alt+G"));
        let quick_only = desired(&wanted("Ctrl+Shift+Space", ""));
        assert!(needs_bind(&[], &quick_only));
        assert!(!needs_bind(&both, &quick_only));
        assert!(!needs_bind(&quick_only, &quick_only));
        assert!(needs_bind(&quick_only, &both));
        let moved = desired(&wanted("Ctrl+Shift+K", ""));
        assert!(needs_bind(&quick_only, &moved));
    }

    #[test]
    fn descriptions_come_from_the_listed_shortcuts() {
        let listed = [
            ("quick-panel", "Press Ctrl+Shift+Space"),
            ("unrelated", "x"),
            ("generator", ""),
        ];
        assert_eq!(
            trigger_descriptions(listed),
            ("Press Ctrl+Shift+Space".to_owned(), String::new())
        );
    }
}
