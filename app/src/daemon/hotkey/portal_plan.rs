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

/// What to do with the portal session after the wanted shortcuts changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Nothing,
    /// Only new or changed triggers: send them again on the same session.
    Bind,
    /// A shortcut was dropped. The portal cannot unbind one, so the session is closed and made
    /// again with what remains.
    Rebuild,
}

/// A recorder pause empties every slot for a moment; the session stays as it is then, and
/// [`is_active`] keeps the presses out.
pub fn plan(
    bound: &[(HotkeySlot, String)],
    desired: &[(HotkeySlot, String)],
    paused: bool,
) -> Plan {
    if paused {
        return Plan::Nothing;
    }
    let dropped = bound
        .iter()
        .any(|(slot, _)| !desired.iter().any(|(wanted, _)| wanted == slot));
    if dropped {
        Plan::Rebuild
    } else if needs_bind(bound, desired) {
        Plan::Bind
    } else {
        Plan::Nothing
    }
}

/// Whether a press of `slot` should open anything: the slot has a trigger the portal was given,
/// and no recorder is waiting for a key.
pub fn is_active(accelerators: &[(HotkeySlot, String)], slot: HotkeySlot, paused: bool) -> bool {
    !paused
        && desired(accelerators)
            .iter()
            .any(|(wanted, _)| *wanted == slot)
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
    fn a_dropped_shortcut_rebuilds_the_session_unless_a_recorder_paused_everything() {
        let both = desired(&wanted("Ctrl+Shift+Space", "Ctrl+Alt+G"));
        let quick_only = desired(&wanted("Ctrl+Shift+Space", ""));
        assert_eq!(plan(&both, &quick_only, false), Plan::Rebuild);
        assert_eq!(
            plan(&both, &[], true),
            Plan::Nothing,
            "paused: keep the session"
        );
        assert_eq!(plan(&both, &[], false), Plan::Rebuild);
        assert_eq!(plan(&quick_only, &both, false), Plan::Bind);
        assert_eq!(plan(&both, &both, false), Plan::Nothing);
        assert_eq!(plan(&[], &quick_only, false), Plan::Bind);
    }

    #[test]
    fn a_press_opens_something_only_for_a_slot_with_a_portal_trigger_and_no_pause() {
        let quick = HotkeySlot::QuickPanel;
        let generator = HotkeySlot::Generator;
        let saved = wanted("Ctrl+Shift+Space", "Hyper+G");
        assert!(is_active(&saved, quick, false));
        assert!(!is_active(&saved, generator, false), "no portal spelling");
        assert!(!is_active(&saved, quick, true), "recorder pause");
        assert!(!is_active(&wanted("", ""), quick, false), "all cleared");
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
