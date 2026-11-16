//! The key events one stroke turns into on Windows, without any Win32 types so the mapping is
//! tested on every host.

use zeroize::{DefaultIsZeroes, Zeroizing};

use crate::autotype::Stroke;

/// `VK_TAB`.
const VK_TAB: u16 = 0x09;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyEvent {
    /// Virtual key; zero for a Unicode event, which carries its character in `scan`.
    pub vk: u16,
    pub scan: u16,
    pub up: bool,
}

// The scan code of a Unicode event is a character of the password.
impl DefaultIsZeroes for KeyEvent {}

/// Down/up pairs for `stroke`: one pair per UTF-16 unit (a surrogate pair is two `KEYEVENTF_UNICODE`
/// events that the target recombines), or the real Tab key so forms move focus instead of
/// receiving a `\t` character.
#[must_use]
pub fn events(stroke: &Stroke) -> Zeroizing<Vec<KeyEvent>> {
    Zeroizing::new(match stroke {
        Stroke::Tab => pair(VK_TAB, 0).to_vec(),
        Stroke::Text(units) => units.iter().flat_map(|unit| pair(0, *unit)).collect(),
    })
}

const fn pair(vk: u16, scan: u16) -> [KeyEvent; 2] {
    [
        KeyEvent {
            vk,
            scan,
            up: false,
        },
        KeyEvent { vk, scan, up: true },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autotype::text_strokes;

    #[test]
    fn a_character_is_a_down_up_pair_of_unicode_events() {
        let strokes = text_strokes("a");
        let keys = events(&strokes[0]);
        assert_eq!(
            *keys,
            [
                KeyEvent {
                    vk: 0,
                    scan: 0x61,
                    up: false
                },
                KeyEvent {
                    vk: 0,
                    scan: 0x61,
                    up: true
                },
            ]
        );
    }

    #[test]
    fn a_surrogate_pair_is_two_pairs_in_order() {
        let strokes = text_strokes("\u{1F511}");
        let keys = events(&strokes[0]);
        let scans: Vec<(u16, bool)> = keys.iter().map(|key| (key.scan, key.up)).collect();
        assert_eq!(
            scans,
            [
                (0xD83D, false),
                (0xD83D, true),
                (0xDD11, false),
                (0xDD11, true)
            ]
        );
    }

    #[test]
    fn tab_is_the_virtual_key() {
        let keys = events(&Stroke::Tab);
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(|key| key.vk == 0x09 && key.scan == 0));
        assert_eq!([keys[0].up, keys[1].up], [false, true]);
    }

    #[test]
    fn an_empty_text_stroke_has_no_events() {
        assert!(events(&Stroke::Text(Zeroizing::new(Vec::new()))).is_empty());
    }
}
