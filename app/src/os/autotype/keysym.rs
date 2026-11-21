//! What a stroke becomes on Linux: an X11 keysym, and for the Wayland virtual keyboard a generated
//! XKB keymap that puts exactly the typed keysyms on keys of their own. Plain functions over
//! numbers and text, so every host tests them; the buffers hold the password, so they are
//! zeroized.
//!
//! The keymap lists the distinct characters of the text, sorted, so the compositor and the
//! focused client can see which characters a secret uses (not their order); accepted, since they
//! receive the keystrokes anyway.

use std::fmt::Write as _;

use zeroize::Zeroizing;

use crate::autotype::Stroke;

pub const TAB: u32 = 0xff09;
pub const RETURN: u32 = 0xff0d;
/// Keysyms of characters outside Latin-1 are the code point plus this (X11 protocol, "Unicode
/// keysyms").
const UNICODE_BASE: u32 = 0x0100_0000;
const UNICODE_MASK: u32 = 0x00ff_ffff;
/// Keys per keymap. Not measured: far below every compositor's limit (XKB keycodes go to 255 in
/// X11-era clients), and a typed secret rarely has this many different characters.
const MAX_KEYS_PER_KEYMAP: usize = 128;
/// XKB keycodes are evdev codes plus 8; evdev 0 is reserved, so keys start at 1.
const XKB_KEYCODE_OFFSET: u32 = 8;
const FIRST_EVDEV_KEY: u32 = 1;
const KEYMAP_MIDDLE: &str = r#"};
xkb_types "vk" {
type "ONE_LEVEL" {
modifiers = None;
map[None] = Level1;
level_name[Level1] = "Any";
};
};
xkb_compatibility "vk" {
};
xkb_symbols "vk" {
"#;

/// The keysym the portal route sends for a keysym from [`keysyms_of`]. Mutter and KWin look it
/// up in the layout that is active, and layouts carry the legacy keysym of a character
/// (`EuroSign`, `Cyrillic_ZHE`), so characters outside Latin-1 take it when it exists
/// (`xkb_utf32_to_keysym`). A character the active layout lacks is dropped by the desktop and
/// cannot be detected from here.
#[cfg(target_os = "linux")]
#[must_use]
pub fn portal_keysym(keysym: u32) -> u32 {
    let unicode = keysym.checked_sub(UNICODE_BASE).and_then(char::from_u32);
    match unicode.map(|ch| xkeysym::Keysym::from_char(ch).raw()) {
        Some(legacy) if legacy != 0 => legacy,
        _ => keysym,
    }
}

/// A character no key can type (a control character).
#[derive(Debug, PartialEq, Eq)]
pub struct Untypeable;

/// The keysym that types `ch`; `None` for control characters.
#[must_use]
pub fn keysym_of(ch: char) -> Option<u32> {
    let code = u32::from(ch);
    match ch {
        '\t' => Some(TAB),
        '\n' | '\r' => Some(RETURN),
        _ if ch.is_control() => None,
        ' '..='\u{7e}' | '\u{a0}'..='\u{ff}' => Some(code),
        _ => Some(UNICODE_BASE + code),
    }
}

/// The keysyms of `strokes`, one per key press.
///
/// # Errors
///
/// [`Untypeable`] when a stroke holds a control character.
pub fn keysyms_of(strokes: &[Stroke]) -> Result<Zeroizing<Vec<u32>>, Untypeable> {
    let mut keysyms = Zeroizing::new(Vec::with_capacity(strokes.len()));
    for stroke in strokes {
        match stroke {
            Stroke::Tab => keysyms.push(TAB),
            Stroke::Text(units) => {
                for ch in char::decode_utf16(units.iter().copied()) {
                    let ch = ch.map_err(|_| Untypeable)?;
                    keysyms.push(keysym_of(ch).ok_or(Untypeable)?);
                }
            }
        }
    }
    Ok(keysyms)
}

/// One keymap and the evdev key codes that type its slice of the text, in order.
#[derive(Debug)]
pub struct Chunk {
    pub keymap: Zeroizing<String>,
    pub keys: Zeroizing<Vec<u32>>,
}

/// Splits `keysyms` into keymaps of at most [`MAX_KEYS_PER_KEYMAP`] different keysyms each.
#[must_use]
pub fn chunks(keysyms: &[u32]) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut distinct = Zeroizing::new(Vec::<u32>::with_capacity(MAX_KEYS_PER_KEYMAP));
    for (index, keysym) in keysyms.iter().enumerate() {
        if !distinct.contains(keysym) {
            if distinct.len() == MAX_KEYS_PER_KEYMAP {
                chunks.push(chunk(&keysyms[start..index]));
                start = index;
                distinct.clear();
            }
            distinct.push(*keysym);
        }
    }
    if start < keysyms.len() {
        chunks.push(chunk(&keysyms[start..]));
    }
    chunks
}

fn chunk(keysyms: &[u32]) -> Chunk {
    // Keys are assigned in keysym order, so the keymap does not spell out the typing order.
    let mut distinct = Zeroizing::new(keysyms.to_vec());
    distinct.sort_unstable();
    distinct.dedup();
    let keys = keysyms
        .iter()
        .filter_map(|keysym| distinct.binary_search(keysym).ok())
        .map(|slot| FIRST_EVDEV_KEY + u32::try_from(slot).unwrap_or_default())
        .collect();
    Chunk {
        keymap: keymap(&distinct),
        keys: Zeroizing::new(keys),
    }
}

/// An XKB keymap (text v1) with one key per keysym on a single level and no modifiers, written
/// without `include` so it does not depend on the compositor's XKB data. Keysyms are spelled
/// the way `xkb_keysym_from_name` reads them: `Tab`, `Return` and `Uxxxx` for characters.
#[must_use]
pub fn keymap(distinct_keysyms: &[u32]) -> Zeroizing<String> {
    let last = key_code(distinct_keysyms.len());
    // Sized up front: a growing String would leave unzeroized copies of the text behind.
    let mut text = Zeroizing::new(String::with_capacity(512 + distinct_keysyms.len() * 80));
    let _ = writeln!(
        text,
        "xkb_keymap {{\nxkb_keycodes \"vk\" {{\nminimum = {XKB_KEYCODE_OFFSET};\nmaximum = {last};"
    );
    for (slot, _) in distinct_keysyms.iter().enumerate() {
        let _ = writeln!(text, "<K{}> = {};", slot + 1, key_code(slot));
    }
    text.push_str(KEYMAP_MIDDLE);
    for (slot, keysym) in distinct_keysyms.iter().enumerate() {
        let _ = write!(
            text,
            "key <K{}> {{ type = \"ONE_LEVEL\", symbols[Group1] = [ ",
            slot + 1
        );
        write_keysym_name(&mut text, *keysym);
        text.push_str(" ] };\n");
    }
    text.push_str("};\n};\n");
    text
}

fn key_code(slot: usize) -> u32 {
    XKB_KEYCODE_OFFSET + FIRST_EVDEV_KEY + u32::try_from(slot).unwrap_or_default()
}

fn write_keysym_name(text: &mut String, keysym: u32) {
    match keysym {
        TAB => text.push_str("Tab"),
        RETURN => text.push_str("Return"),
        _ => {
            let _ = write!(text, "U{:04X}", keysym & UNICODE_MASK);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(units: &str) -> Stroke {
        Stroke::Text(Zeroizing::new(units.encode_utf16().collect()))
    }

    #[test]
    fn ascii_and_latin1_keep_their_code_point_as_keysym() {
        assert_eq!(keysym_of('a'), Some(0x61));
        assert_eq!(keysym_of('~'), Some(0x7e));
        assert_eq!(keysym_of(' '), Some(0x20));
        assert_eq!(keysym_of('é'), Some(0xe9));
        assert_eq!(keysym_of('\u{a0}'), Some(0xa0));
    }

    #[test]
    fn other_characters_are_unicode_keysyms() {
        assert_eq!(keysym_of('€'), Some(0x0100_20ac));
        assert_eq!(keysym_of('Ж'), Some(0x0100_0416));
        assert_eq!(keysym_of('😀'), Some(0x0101_f600));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_portal_prefers_the_legacy_keysym_of_a_character() {
        assert_eq!(portal_keysym(keysym_of('€').expect("typeable")), 0x20ac);
        assert_eq!(portal_keysym(keysym_of('Ж').expect("typeable")), 0x06f6);
        assert_eq!(portal_keysym(keysym_of('ж').expect("typeable")), 0x06d6);
        assert_eq!(portal_keysym(keysym_of('a').expect("typeable")), 0x61);
        assert_eq!(portal_keysym(keysym_of('é').expect("typeable")), 0xe9);
        assert_eq!(portal_keysym(TAB), TAB);
        assert_eq!(portal_keysym(0x0101_f600), 0x0101_f600);
    }

    #[test]
    fn tab_and_line_breaks_are_named_keys_and_other_controls_are_refused() {
        assert_eq!(keysym_of('\t'), Some(0xff09));
        assert_eq!(keysym_of('\n'), Some(0xff0d));
        assert_eq!(keysym_of('\u{0}'), None);
        assert_eq!(keysym_of('\u{7f}'), None);
        assert_eq!(keysym_of('\u{85}'), None);
    }

    #[test]
    fn strokes_become_keysyms_with_surrogate_pairs_joined() {
        let strokes = [text("a"), Stroke::Tab, text("😀"), text("é")];
        let keysyms = keysyms_of(&strokes).expect("typeable");
        assert_eq!(*keysyms, [0x61, 0xff09, 0x0101_f600, 0xe9]);
    }

    #[test]
    fn a_control_character_or_lone_surrogate_is_untypeable() {
        assert_eq!(
            keysyms_of(&[text("\u{1}")]).expect_err("untypeable"),
            Untypeable
        );
        let lone = Stroke::Text(Zeroizing::new(vec![0xd800]));
        assert_eq!(keysyms_of(&[lone]).expect_err("untypeable"), Untypeable);
    }

    #[test]
    fn the_keymap_has_one_key_per_distinct_keysym_in_keysym_order() {
        let map = keymap(&[0x61, 0xe9, 0x0100_20ac, TAB]);
        assert!(
            map.starts_with("xkb_keymap {\nxkb_keycodes \"vk\" {\nminimum = 8;\nmaximum = 13;\n")
        );
        for line in [
            "<K1> = 9;",
            "<K4> = 12;",
            "key <K1> { type = \"ONE_LEVEL\", symbols[Group1] = [ U0061 ] };",
            "key <K2> { type = \"ONE_LEVEL\", symbols[Group1] = [ U00E9 ] };",
            "key <K3> { type = \"ONE_LEVEL\", symbols[Group1] = [ U20AC ] };",
            "key <K4> { type = \"ONE_LEVEL\", symbols[Group1] = [ Tab ] };",
        ] {
            assert!(map.contains(line), "{line}\n{}", *map);
        }
        assert!(map.ends_with("};\n};\n"));
        assert!(!map.contains("include"));
    }

    #[test]
    fn braces_of_the_keymap_balance() {
        let map = keymap(&[0x61, RETURN]);
        assert_eq!(map.matches('{').count(), map.matches('}').count());
        assert!(map.contains("Return"));
    }

    #[test]
    fn repeated_characters_share_a_key_and_keys_follow_the_typing_order() {
        let planned = chunks(&[0x62, 0x61, 0x62, 0x62]);
        assert_eq!(planned.len(), 1);
        // 'a' sorts first, so it owns evdev key 1 and 'b' key 2.
        assert_eq!(*planned[0].keys, [2, 1, 2, 2]);
        assert!(planned[0].keymap.contains("<K2> = 10;"));
        assert!(!planned[0].keymap.contains("<K3>"));
    }

    #[test]
    fn more_distinct_keysyms_than_one_keymap_holds_start_a_second_keymap() {
        let many: Vec<u32> = (0x100..0x100 + 130).collect();
        let planned = chunks(&many);
        assert_eq!(planned.len(), 2);
        assert_eq!(planned[0].keys.len(), 128);
        assert_eq!(planned[1].keys.len(), 2);
        assert_eq!(*planned[1].keys, [1, 2]);
    }

    #[test]
    fn nothing_to_type_needs_no_keymap() {
        assert!(chunks(&[]).is_empty());
    }
}
