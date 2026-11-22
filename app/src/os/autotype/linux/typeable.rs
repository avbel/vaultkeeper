//! Decides, before the first key, whether the RemoteDesktop portal can type a text at all. The
//! desktop resolves every keysym in the layout that is active and drops what that layout lacks
//! without telling the sender (see [`super::xkb`]), so a password would arrive with characters
//! missing. The portal offers no way to pick the layout, and neither does libei, whose keyboard
//! takes key codes while the layout stays under the compositor's control. So the text is typed
//! only when the keymap says that every character comes out right, and refused otherwise.
//!
//! KWin is the exception: it resolves a keysym in any layout of the session, and even builds a
//! key for a character no layout has, so there the layout never refuses a text ([`Desktop`]).

use zeroize::Zeroizing;

use super::xkb::{Keymap, layout_name};
use crate::os::autotype::keysym;

/// The desktop behind the RemoteDesktop portal, which decides how it resolves keysyms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Desktop {
    Kde,
    /// GNOME and everything else: only the active layout resolves a keysym.
    Other,
}

impl Desktop {
    /// `current_desktop` is `XDG_CURRENT_DESKTOP`, a colon-separated list.
    pub(super) fn detect(current_desktop: &str) -> Self {
        if current_desktop
            .split(':')
            .any(|entry| entry.eq_ignore_ascii_case("kde"))
        {
            Self::Kde
        } else {
            Self::Other
        }
    }

    pub(super) fn current() -> Self {
        Self::detect(&std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default())
    }
}

/// `Mod2` of the core modifiers: Num Lock.
const NUM_LOCK: u32 = 1 << 4;
/// How long a layout name may be to go into a toast.
const MAX_NAME_CHARS: usize = 40;

/// What the compositor told the focused Quick Panel about the keyboard.
pub(super) struct Seen {
    pub keymap: Vec<u8>,
    /// The active layout; `None` when the compositor sent the keymap without it.
    pub layout: Option<u32>,
    pub locked_modifiers: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The keymap could not be read, so nothing is known about what would be typed.
    Unchecked(String),
    Missing,
    /// The active layout lacks characters that the named other layout of the keymap has.
    SwitchTo(String),
    /// Some layout lacks a character and the active one is not known.
    LayoutUnknown,
    /// Some layout lacks a character and every window has a layout of its own, so the one seen
    /// in the Quick Panel says nothing about the target window.
    LayoutPerWindow,
    LockedModifier,
}

impl Refusal {
    /// Kept short: the Quick Panel's toast wraps, but a few lines is all it should take, and what
    /// to do must be in them. Names no character: the text goes to the log.
    pub(super) fn reason(&self) -> String {
        match self {
            Self::Unchecked(why) => {
                format!("cannot check the keyboard layout; copy instead ({why})")
            }
            Self::Missing => {
                "the active keyboard layout lacks some characters; switch it or copy".to_owned()
            }
            Self::SwitchTo(name) => {
                format!("switch the keyboard layout to {name} to type this login, or copy it")
            }
            Self::LayoutUnknown => {
                "not every keyboard layout has all the characters; copy instead".to_owned()
            }
            Self::LayoutPerWindow => {
                "with per-window layouts every layout must have all characters; copy".to_owned()
            }
            Self::LockedModifier => {
                "a locked modifier such as Caps Lock would change the text; turn it off".to_owned()
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// The keysyms to send, one per stroke.
    Type(Zeroizing<Vec<u32>>),
    /// Right in the layout the Quick Panel saw but not in every layout of the session: only safe
    /// when all windows share one layout.
    TypeUnlessLayoutPerWindow(Zeroizing<Vec<u32>>),
    Refuse(Refusal),
}

/// `keysyms` are those of [`keysym::keysyms_of`].
pub(super) fn examine(desktop: Desktop, seen: Result<&Seen, &str>, keysyms: &[u32]) -> Verdict {
    let seen = match seen {
        Ok(seen) => seen,
        Err(why) => return Verdict::Refuse(Refusal::Unchecked(why.to_owned())),
    };
    if desktop == Desktop::Kde {
        return examine_kde(seen, keysyms);
    }
    let keymap = match Keymap::parse(&seen.keymap) {
        Ok(keymap) => keymap,
        Err(why) => return Verdict::Refuse(Refusal::Unchecked(why.to_owned())),
    };
    let layouts = keymap.layouts();
    if layouts == 0 {
        return Verdict::Refuse(Refusal::Unchecked("the keymap has no layout".to_owned()));
    }
    let locked = seen.locked_modifiers;
    let every: Vec<u32> = (0..layouts).collect();
    if let Some(plan) = plan(&keymap, &every, locked, keysyms) {
        return Verdict::Type(plan);
    }
    let active = if layouts == 1 {
        Some(0)
    } else {
        seen.layout.filter(|layout| *layout < layouts)
    };
    let Some(active) = active else {
        return Verdict::Refuse(Refusal::LayoutUnknown);
    };
    match plan(&keymap, &[active], locked, keysyms) {
        Some(plan) => Verdict::TypeUnlessLayoutPerWindow(plan),
        None if locked != 0 && plan(&keymap, &[active], 0, keysyms).is_some() => {
            Verdict::Refuse(Refusal::LockedModifier)
        }
        None => Verdict::Refuse(switch_target(
            &keymap,
            active,
            locked,
            keysyms,
            &seen.keymap,
        )),
    }
}

/// KWin types any keysym whatever the layout, so only what the focused app does with a locked
/// modifier is left to check; its keymap is not needed. A cased letter changes with Caps Lock.
fn examine_kde(seen: &Seen, keysyms: &[u32]) -> Verdict {
    let cased = keysyms
        .iter()
        .filter_map(|keysym| keysym::char_of(*keysym))
        .any(|ch| ch.is_lowercase() || ch.is_uppercase());
    if seen.locked_modifiers & !NUM_LOCK != 0 && cased {
        return Verdict::Refuse(Refusal::LockedModifier);
    }
    Verdict::Type(Zeroizing::new(
        keysyms.iter().copied().map(keysym::portal_keysym).collect(),
    ))
}

/// Names another layout of the keymap that types the whole text, so the user knows what to
/// switch to; `Missing` when none does or the keymap does not name it.
fn switch_target(
    keymap: &Keymap,
    active: u32,
    locked: u32,
    keysyms: &[u32],
    text: &[u8],
) -> Refusal {
    (0..keymap.layouts())
        .filter(|layout| *layout != active)
        .filter(|layout| plan(keymap, &[*layout], locked, keysyms).is_some())
        .find_map(|layout| layout_name(text, layout))
        .filter(|name| name.chars().count() <= MAX_NAME_CHARS)
        .map_or(Refusal::Missing, Refusal::SwitchTo)
}

/// The keysym to send for each of `keysyms` so that it comes out right in every one of
/// `layouts`; `None` when one of them cannot.
fn plan(
    keymap: &Keymap,
    layouts: &[u32],
    locked: u32,
    keysyms: &[u32],
) -> Option<Zeroizing<Vec<u32>>> {
    // Each lookup walks the whole keymap, and a text repeats its characters.
    let mut known = Zeroizing::new(Vec::<(u32, u32)>::with_capacity(keysyms.len()));
    let mut plan = Zeroizing::new(Vec::with_capacity(keysyms.len()));
    for wanted in keysyms {
        let sent = if let Some((_, sent)) = known.iter().find(|(keysym, _)| keysym == wanted) {
            *sent
        } else {
            let sent = sendable(keymap, layouts, locked, *wanted)?;
            known.push((*wanted, sent));
            sent
        };
        plan.push(sent);
    }
    Some(plan)
}

/// A layout carries a character under its legacy keysym (`Cyrillic_zhe`) or its Unicode one
/// (xkeyboard-config's `de` has U+2026 as `U2026`, not `ellipsis`), and the desktop compares
/// keysyms, not characters; so both are tried.
fn sendable(keymap: &Keymap, layouts: &[u32], locked: u32, wanted: u32) -> Option<u32> {
    let expected = keysym::char_of(wanted);
    [keysym::portal_keysym(wanted), wanted]
        .into_iter()
        .find(|candidate| {
            layouts
                .iter()
                .all(|layout| keymap.types(*layout, locked, *candidate, expected))
        })
}

#[cfg(test)]
mod tests {
    use super::super::xkb::tests::{CAPS_LOCK, DE, NUM_LOCK, RU_US, US};
    use super::*;
    use crate::autotype::{Stroke, login_strokes};

    /// The login of the live test that found the dropped characters.
    const USERNAME: &str = "alice@example.com";
    const PASSWORD: &str = "Pa55-€Ж-wörd!";

    fn seen(keymap: &[u8], layout: Option<u32>, locked_modifiers: u32) -> Seen {
        Seen {
            keymap: keymap.to_vec(),
            layout,
            locked_modifiers,
        }
    }

    fn keysyms(strokes: &[Stroke]) -> Zeroizing<Vec<u32>> {
        keysym::keysyms_of(strokes).expect("typeable")
    }

    fn login(username: &str, password: &str) -> Zeroizing<Vec<u32>> {
        keysyms(&login_strokes(username, password))
    }

    fn text(text: &str) -> Zeroizing<Vec<u32>> {
        keysyms(&[Stroke::Text(Zeroizing::new(text.encode_utf16().collect()))])
    }

    fn refused(seen: &Seen, keysyms: &[u32]) -> Refusal {
        match examine(Desktop::Other, Ok(seen), keysyms) {
            Verdict::Refuse(refusal) => refusal,
            other => panic!("typed: {other:?}"),
        }
    }

    #[test]
    fn the_login_that_lost_characters_is_refused_in_both_layouts() {
        let login = login(USERNAME, PASSWORD);
        assert_eq!(refused(&seen(US, Some(0), 0), &login), Refusal::Missing);
        assert_eq!(refused(&seen(RU_US, Some(0), 0), &login), Refusal::Missing);
        assert_eq!(refused(&seen(RU_US, Some(1), 0), &login), Refusal::Missing);
    }

    #[test]
    fn a_login_the_layout_has_is_typed_with_the_keysyms_of_its_characters() {
        let verdict = examine(
            Desktop::Other,
            Ok(&seen(US, Some(0), 0)),
            &login("al@x.io", "Pa55-€!"),
        );
        // a l @ x . i o Tab P a 5 5 - EuroSign !
        let sent = [
            0x61, 0x6c, 0x40, 0x78, 0x2e, 0x69, 0x6f, 0xff09, 0x50, 0x61, 0x35, 0x35, 0x2d, 0x20ac,
            0x21,
        ];
        assert_eq!(verdict, Verdict::Type(Zeroizing::new(sent.to_vec())));
    }

    #[test]
    fn the_layout_decides_between_the_legacy_and_the_unicode_keysym() {
        // `de` has EuroSign (0x20ac) on <AD03> and U+2026 as the Unicode keysym on <AB09>, whose
        // legacy keysym `ellipsis` (0xaae) the fixture does not contain.
        let verdict = examine(Desktop::Other, Ok(&seen(DE, Some(0), 0)), &text("€…ö@"));
        let sent = [0x20ac, 0x0100_2026, 0xf6, 0x40];
        assert_eq!(verdict, Verdict::Type(Zeroizing::new(sent.to_vec())));
    }

    #[test]
    fn a_character_above_the_third_level_is_refused() {
        assert_eq!(
            refused(&seen(DE, Some(0), 0), &text("a›")),
            Refusal::Missing
        );
    }

    #[test]
    fn with_two_layouts_text_of_the_active_one_depends_on_per_window_layouts() {
        let latin = login("alice@example.com", "Pa55-word!");
        let sent = Zeroizing::new(latin.to_vec());
        assert_eq!(
            examine(Desktop::Other, Ok(&seen(RU_US, Some(1), 0)), &latin),
            Verdict::TypeUnlessLayoutPerWindow(sent)
        );
        assert_eq!(
            refused(&seen(RU_US, Some(0), 0), &latin),
            Refusal::SwitchTo("English (US)".to_owned())
        );
        let cyrillic = text("Жж");
        assert_eq!(
            examine(Desktop::Other, Ok(&seen(RU_US, Some(0), 0)), &cyrillic),
            Verdict::TypeUnlessLayoutPerWindow(Zeroizing::new(vec![0x6f6, 0x6d6]))
        );
    }

    #[test]
    fn text_every_layout_has_needs_no_active_layout() {
        // Digits, `!` and `-` are on the same keys of the Russian and the English group.
        let digits = text("5-1!");
        for layout in [None, Some(0), Some(1), Some(7)] {
            assert_eq!(
                examine(Desktop::Other, Ok(&seen(RU_US, layout, 0)), &digits),
                Verdict::Type(Zeroizing::new(digits.to_vec()))
            );
        }
    }

    #[test]
    fn an_unknown_active_layout_refuses_what_only_some_layout_has() {
        let latin = text("abc");
        for layout in [None, Some(2)] {
            assert_eq!(
                refused(&seen(RU_US, layout, 0), &latin),
                Refusal::LayoutUnknown
            );
        }
    }

    #[test]
    fn a_text_only_another_layout_has_names_that_layout() {
        let latin = text("alice@example.com");
        let refusal = refused(&seen(RU_US, Some(0), 0), &latin);
        assert_eq!(refusal, Refusal::SwitchTo("English (US)".to_owned()));
        assert_eq!(
            refusal.reason(),
            "switch the keyboard layout to English (US) to type this login, or copy it"
        );
        assert_eq!(
            refused(&seen(RU_US, Some(1), 0), &text("Жж")),
            Refusal::SwitchTo("Russian".to_owned())
        );
    }

    #[test]
    fn a_text_no_layout_has_keeps_the_plain_refusal() {
        assert_eq!(
            refused(&seen(RU_US, Some(0), 0), &text("wörd")),
            Refusal::Missing
        );
        assert_eq!(
            refused(&seen(RU_US, Some(1), 0), &text("Жö")),
            Refusal::Missing
        );
    }

    #[test]
    fn kde_detection_reads_the_desktop_list() {
        assert_eq!(Desktop::detect("KDE"), Desktop::Kde);
        assert_eq!(Desktop::detect("ubuntu:KDE"), Desktop::Kde);
        assert_eq!(Desktop::detect("kde"), Desktop::Kde);
        assert_eq!(Desktop::detect("GNOME"), Desktop::Other);
        assert_eq!(Desktop::detect("ubuntu:GNOME"), Desktop::Other);
        assert_eq!(Desktop::detect(""), Desktop::Other);
        assert_eq!(Desktop::detect("X-KDE-Plasma"), Desktop::Other);
    }

    #[test]
    fn on_kde_the_layout_never_refuses_and_the_legacy_keysyms_are_sent() {
        let login = login(USERNAME, PASSWORD);
        for layout in [Some(0), Some(1), None] {
            for keymap in [US, RU_US, DE] {
                assert!(
                    matches!(
                        examine(Desktop::Kde, Ok(&seen(keymap, layout, 0)), &login),
                        Verdict::Type(_)
                    ),
                    "{layout:?}"
                );
            }
        }
        // EuroSign, Cyrillic_ZHE and odiaeresis.
        assert_eq!(
            examine(Desktop::Kde, Ok(&seen(RU_US, Some(0), 0)), &text("€Жö")),
            Verdict::Type(Zeroizing::new(vec![0x20ac, 0x6f6, 0xf6]))
        );
    }

    #[test]
    fn on_kde_caps_lock_still_refuses_letters_and_num_lock_does_not() {
        let word = text("Word1");
        assert_eq!(
            examine(Desktop::Kde, Ok(&seen(RU_US, Some(0), CAPS_LOCK)), &word),
            Verdict::Refuse(Refusal::LockedModifier)
        );
        assert!(matches!(
            examine(Desktop::Kde, Ok(&seen(RU_US, Some(0), NUM_LOCK)), &word),
            Verdict::Type(_)
        ));
        assert!(matches!(
            examine(
                Desktop::Kde,
                Ok(&seen(RU_US, Some(0), CAPS_LOCK)),
                &text("12-!")
            ),
            Verdict::Type(_)
        ));
        assert_eq!(
            examine(Desktop::Kde, Err("no keyboard"), &word),
            Verdict::Refuse(Refusal::Unchecked("no keyboard".to_owned()))
        );
    }

    #[test]
    fn caps_lock_is_named_and_num_lock_is_harmless() {
        let word = text("Word1");
        assert_eq!(
            refused(&seen(US, Some(0), CAPS_LOCK), &word),
            Refusal::LockedModifier
        );
        assert!(matches!(
            examine(Desktop::Other, Ok(&seen(US, Some(0), NUM_LOCK)), &word),
            Verdict::Type(_)
        ));
        assert!(matches!(
            examine(
                Desktop::Other,
                Ok(&seen(US, Some(0), CAPS_LOCK)),
                &text("12-!")
            ),
            Verdict::Type(_)
        ));
        // Missing wins over Caps Lock: turning it off would not help.
        assert_eq!(
            refused(&seen(US, Some(0), CAPS_LOCK), &text("Wörd")),
            Refusal::Missing
        );
    }

    #[test]
    fn a_keymap_that_was_not_read_or_does_not_compile_is_refused() {
        let word = text("a");
        assert_eq!(
            examine(Desktop::Other, Err("no keyboard"), &word),
            Verdict::Refuse(Refusal::Unchecked("no keyboard".to_owned()))
        );
        assert!(matches!(
            refused(&seen(b"xkb_keymap {", Some(0), 0), &word),
            Refusal::Unchecked(_)
        ));
    }

    #[test]
    fn nothing_to_type_is_typed() {
        assert_eq!(
            examine(Desktop::Other, Ok(&seen(US, Some(0), 0)), &[]),
            Verdict::Type(Zeroizing::new(Vec::new()))
        );
    }

    #[test]
    fn refusals_say_what_to_do_and_fit_the_panel_toast() {
        for refusal in [
            Refusal::Missing,
            Refusal::LayoutUnknown,
            Refusal::LayoutPerWindow,
            Refusal::LockedModifier,
            Refusal::SwitchTo("English (United Kingdom, extended, Windows)".to_owned()),
        ] {
            let reason = refusal.reason();
            if !matches!(refusal, Refusal::SwitchTo(_)) {
                assert!(reason.chars().count() <= 70, "{reason}");
            }
            assert!(
                reason.contains("copy") || reason.contains("turn it off"),
                "{reason}"
            );
        }
        assert_eq!(
            Refusal::Unchecked("no keyboard".to_owned()).reason(),
            "cannot check the keyboard layout; copy instead (no keyboard)"
        );
    }
}
