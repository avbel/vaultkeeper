//! The Settings shortcut recorder: one key press with modifiers becomes the accelerator text the
//! `global-hotkey` parser reads ("Cmd+Alt+G"). The daemon registers it by physical key, so the
//! key comes from the winit key code when there is one; Slint's key text is the fallback (the
//! testing backend has no winit events).

use slint::{
    platform::Key,
    winit_030::winit::keyboard::{KeyCode, ModifiersState},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Mods {
    pub cmd: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    #[error("Add ⌘, ⌥ or ⌃ to the shortcut")]
    NeedsModifier,
    #[error("This key can't be a global shortcut")]
    UnsupportedKey,
}

/// `key` is a token from [`key_from_code`] or [`key_from_text`]; `None` is a key the parser has
/// no name for. Modifiers are written in a fixed order, so equal shortcuts are equal text.
pub fn accelerator(mods: Mods, key: Option<&str>) -> Result<String, Reject> {
    if !(mods.cmd || mods.ctrl || mods.alt) {
        return Err(Reject::NeedsModifier);
    }
    let key = key.ok_or(Reject::UnsupportedKey)?;
    let names = [
        (mods.ctrl, "Ctrl"),
        (mods.cmd, "Cmd"),
        (mods.alt, "Alt"),
        (mods.shift, "Shift"),
    ];
    let mut text = String::with_capacity(24);
    for (_, name) in names.iter().filter(|(on, _)| *on) {
        text.push_str(name);
        text.push('+');
    }
    text.push_str(key);
    Ok(text)
}

/// A winit press. winit does not swap ⌘ and ⌃ the way Slint's key events do: `SUPER` is ⌘.
pub fn physical_accelerator(code: KeyCode, held: ModifiersState) -> Result<String, Reject> {
    let mods = Mods {
        cmd: held.super_key(),
        ctrl: held.control_key(),
        alt: held.alt_key(),
        shift: held.shift_key(),
    };
    accelerator(mods, key_from_code(code))
}

const LETTERS: [&str; 26] = [
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S",
    "T", "U", "V", "W", "X", "Y", "Z",
];
const DIGITS: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
const F_KEYS: [&str; 12] = [
    "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
];
// The parser's literal spellings; `+` is its separator and never a key.
const PUNCTUATION: [&str; 11] = ["`", "\\", "[", "]", ",", "-", ".", "'", ";", "/", "="];

#[must_use]
pub fn key_from_code(code: KeyCode) -> Option<&'static str> {
    use KeyCode as C;
    let letters = [
        C::KeyA,
        C::KeyB,
        C::KeyC,
        C::KeyD,
        C::KeyE,
        C::KeyF,
        C::KeyG,
        C::KeyH,
        C::KeyI,
        C::KeyJ,
        C::KeyK,
        C::KeyL,
        C::KeyM,
        C::KeyN,
        C::KeyO,
        C::KeyP,
        C::KeyQ,
        C::KeyR,
        C::KeyS,
        C::KeyT,
        C::KeyU,
        C::KeyV,
        C::KeyW,
        C::KeyX,
        C::KeyY,
        C::KeyZ,
    ];
    let digits = [
        C::Digit0,
        C::Digit1,
        C::Digit2,
        C::Digit3,
        C::Digit4,
        C::Digit5,
        C::Digit6,
        C::Digit7,
        C::Digit8,
        C::Digit9,
    ];
    let f_keys = [
        C::F1,
        C::F2,
        C::F3,
        C::F4,
        C::F5,
        C::F6,
        C::F7,
        C::F8,
        C::F9,
        C::F10,
        C::F11,
        C::F12,
    ];
    let punctuation = [
        C::Backquote,
        C::Backslash,
        C::BracketLeft,
        C::BracketRight,
        C::Comma,
        C::Minus,
        C::Period,
        C::Quote,
        C::Semicolon,
        C::Slash,
        C::Equal,
    ];
    let named = match code {
        C::Space => Some("Space"),
        C::Enter => Some("Enter"),
        C::Tab => Some("Tab"),
        C::ArrowUp => Some("Up"),
        C::ArrowDown => Some("Down"),
        C::ArrowLeft => Some("Left"),
        C::ArrowRight => Some("Right"),
        _ => None,
    };
    named
        .or_else(|| pick(&letters, &LETTERS, &code))
        .or_else(|| pick(&digits, &DIGITS, &code))
        .or_else(|| pick(&f_keys, &F_KEYS, &code))
        .or_else(|| pick(&punctuation, &PUNCTUATION, &code))
}

fn pick<T: PartialEq>(keys: &[T], names: &[&'static str], wanted: &T) -> Option<&'static str> {
    keys.iter()
        .position(|key| key == wanted)
        .and_then(|index| names.get(index).copied())
}

/// Slint key text: a character, or a `slint::platform::Key` code point. Shift may have turned a
/// letter upper-case.
#[must_use]
pub fn key_from_text(text: &str) -> Option<&'static str> {
    let mut chars = text.chars();
    let (Some(c), None) = (chars.next(), chars.next()) else {
        return None;
    };
    let lower = c.to_ascii_lowercase();
    if lower.is_ascii_lowercase() {
        return LETTERS.get(usize::from(lower as u8 - b'a')).copied();
    }
    if c.is_ascii_digit() {
        return DIGITS.get(usize::from(c as u8 - b'0')).copied();
    }
    if let Some(&name) = PUNCTUATION.iter().find(|name| name.starts_with(c)) {
        return Some(name);
    }
    let named = [
        (Key::Space, "Space"),
        (Key::Return, "Enter"),
        (Key::Tab, "Tab"),
        (Key::UpArrow, "Up"),
        (Key::DownArrow, "Down"),
        (Key::LeftArrow, "Left"),
        (Key::RightArrow, "Right"),
    ];
    let f_keys = [
        Key::F1,
        Key::F2,
        Key::F3,
        Key::F4,
        Key::F5,
        Key::F6,
        Key::F7,
        Key::F8,
        Key::F9,
        Key::F10,
        Key::F11,
        Key::F12,
    ];
    named
        .iter()
        .find(|(key, _)| char::from(*key) == c)
        .map(|(_, name)| *name)
        .or_else(|| {
            f_keys
                .iter()
                .position(|key| char::from(*key) == c)
                .and_then(|index| F_KEYS.get(index).copied())
        })
}

/// A press of a modifier alone: the recorder keeps waiting for the key.
#[must_use]
pub fn is_modifier_text(text: &str) -> bool {
    let modifiers = [
        Key::Shift,
        Key::ShiftR,
        Key::Control,
        Key::ControlR,
        Key::Alt,
        Key::AltGr,
        Key::Meta,
        Key::MetaR,
        Key::CapsLock,
    ];
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => modifiers.iter().any(|key| char::from(*key) == c),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use global_hotkey::hotkey::{Code, HotKey, Modifiers};

    use super::*;

    const CMD_ALT: Mods = Mods {
        cmd: true,
        ctrl: false,
        alt: true,
        shift: false,
    };
    const CTRL_SHIFT: Mods = Mods {
        cmd: false,
        ctrl: true,
        alt: false,
        shift: true,
    };
    const CMD: Mods = Mods {
        cmd: true,
        ctrl: false,
        alt: false,
        shift: false,
    };

    fn parsed(text: &str) -> HotKey {
        HotKey::from_str(text).unwrap_or_else(|error| panic!("{text}: {error}"))
    }

    #[test]
    fn recorded_shortcuts_parse_to_the_pressed_keys() {
        let cases = [
            (
                CMD_ALT,
                KeyCode::KeyG,
                "Cmd+Alt+G",
                Modifiers::META | Modifiers::ALT,
                Code::KeyG,
            ),
            (
                CTRL_SHIFT,
                KeyCode::F5,
                "Ctrl+Shift+F5",
                Modifiers::CONTROL | Modifiers::SHIFT,
                Code::F5,
            ),
            (
                CMD,
                KeyCode::Space,
                "Cmd+Space",
                Modifiers::META,
                Code::Space,
            ),
            (CMD, KeyCode::Digit1, "Cmd+1", Modifiers::META, Code::Digit1),
            (
                CMD_ALT,
                KeyCode::Comma,
                "Cmd+Alt+,",
                Modifiers::META | Modifiers::ALT,
                Code::Comma,
            ),
            (
                CMD,
                KeyCode::Enter,
                "Cmd+Enter",
                Modifiers::META,
                Code::Enter,
            ),
            (
                CMD,
                KeyCode::ArrowUp,
                "Cmd+Up",
                Modifiers::META,
                Code::ArrowUp,
            ),
            (CMD, KeyCode::Tab, "Cmd+Tab", Modifiers::META, Code::Tab),
            (CMD, KeyCode::F12, "Cmd+F12", Modifiers::META, Code::F12),
        ];
        for (mods, code, text, want_mods, want_code) in cases {
            let recorded = accelerator(mods, key_from_code(code)).expect("recorded");
            assert_eq!(recorded, text);
            assert_eq!(parsed(&recorded), HotKey::new(Some(want_mods), want_code));
        }
    }

    #[test]
    fn every_physical_key_the_recorder_names_is_a_parser_key() {
        let codes = [
            KeyCode::KeyA,
            KeyCode::KeyZ,
            KeyCode::Digit0,
            KeyCode::Digit9,
            KeyCode::F1,
            KeyCode::Backquote,
            KeyCode::Backslash,
            KeyCode::BracketLeft,
            KeyCode::BracketRight,
            KeyCode::Minus,
            KeyCode::Period,
            KeyCode::Quote,
            KeyCode::Semicolon,
            KeyCode::Slash,
            KeyCode::Equal,
            KeyCode::ArrowDown,
            KeyCode::ArrowLeft,
            KeyCode::ArrowRight,
        ];
        for code in codes {
            let recorded = accelerator(CMD, key_from_code(code)).expect("named");
            parsed(&recorded);
        }
        assert_eq!(key_from_code(KeyCode::Escape), None);
        assert_eq!(key_from_code(KeyCode::ShiftLeft), None);
    }

    #[test]
    fn key_text_gives_the_same_names() {
        assert_eq!(key_from_text("g"), Some("G"));
        assert_eq!(key_from_text("G"), Some("G"), "Shift upper-cases the text");
        assert_eq!(key_from_text("7"), Some("7"));
        assert_eq!(key_from_text(","), Some(","));
        assert_eq!(key_from_text("`"), Some("`"));
        assert_eq!(key_from_text(" "), Some("Space"));
        assert_eq!(
            key_from_text(&char::from(Key::Return).to_string()),
            Some("Enter")
        );
        assert_eq!(key_from_text(&char::from(Key::F5).to_string()), Some("F5"));
        assert_eq!(
            key_from_text(&char::from(Key::F12).to_string()),
            Some("F12")
        );
        assert_eq!(
            key_from_text(&char::from(Key::UpArrow).to_string()),
            Some("Up")
        );
        assert_eq!(key_from_text("+"), None, "the parser's separator");
        assert_eq!(key_from_text("©"), None);
        assert_eq!(key_from_text("ab"), None);
        assert_eq!(key_from_text(""), None);
    }

    #[test]
    fn shift_alone_or_no_modifier_is_refused() {
        let shift = Mods {
            shift: true,
            ..Mods::default()
        };
        assert_eq!(accelerator(shift, Some("G")), Err(Reject::NeedsModifier));
        assert_eq!(
            accelerator(Mods::default(), Some("F5")),
            Err(Reject::NeedsModifier)
        );
        assert_eq!(accelerator(CMD, None), Err(Reject::UnsupportedKey));
    }

    #[test]
    fn all_four_modifiers_keep_one_order() {
        let all = Mods {
            cmd: true,
            ctrl: true,
            alt: true,
            shift: true,
        };
        let recorded = accelerator(all, Some("K")).expect("recorded");
        assert_eq!(recorded, "Ctrl+Cmd+Alt+Shift+K");
        assert_eq!(
            parsed(&recorded),
            HotKey::new(
                Some(Modifiers::CONTROL | Modifiers::META | Modifiers::ALT | Modifiers::SHIFT),
                Code::KeyK
            )
        );
    }

    #[test]
    fn physical_presses_map_super_to_command_and_control_to_control() {
        let recorded =
            physical_accelerator(KeyCode::KeyG, ModifiersState::SUPER | ModifiersState::ALT);
        assert_eq!(recorded.as_deref(), Ok("Cmd+Alt+G"));
        assert_eq!(
            parsed(&recorded.expect("recorded")),
            HotKey::new(Some(Modifiers::META | Modifiers::ALT), Code::KeyG)
        );
        let recorded =
            physical_accelerator(KeyCode::F5, ModifiersState::CONTROL | ModifiersState::SHIFT);
        assert_eq!(recorded.as_deref(), Ok("Ctrl+Shift+F5"));
        assert_eq!(
            physical_accelerator(KeyCode::KeyG, ModifiersState::SHIFT),
            Err(Reject::NeedsModifier)
        );
        assert_eq!(
            physical_accelerator(KeyCode::Escape, ModifiersState::SUPER),
            Err(Reject::UnsupportedKey)
        );
    }

    #[test]
    fn modifier_keys_alone_are_recognised() {
        assert!(is_modifier_text(&char::from(Key::Shift).to_string()));
        assert!(is_modifier_text(&char::from(Key::Control).to_string()));
        assert!(is_modifier_text(&char::from(Key::Meta).to_string()));
        assert!(!is_modifier_text("g"));
        assert!(!is_modifier_text(""));
    }
}
