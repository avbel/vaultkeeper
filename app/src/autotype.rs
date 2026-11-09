//! Auto-type: what the Quick Panel types into the app that was in front, `<username> Tab
//! <password>`, as a list of keystrokes the OS layer posts one by one. Platform-free, so the
//! splitting is tested everywhere; posting lives in [`crate::os::autotype`].

use vk_vault::model::{ItemKind, ItemSummary};
use zeroize::Zeroizing;

/// One character per key event, so at most a surrogate pair. An event may carry up to 20 units
/// (`CGEventKeyboardSetUnicodeString`), but web forms that react per key event can drop the rest.
const UNITS_PER_STROKE: usize = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Stroke {
    /// One character as UTF-16 (a surrogate pair stays together).
    Text(Zeroizing<Vec<u16>>),
    /// The real Tab key, so forms move focus instead of receiving a `\t` character.
    Tab,
}

/// Logins with a password; the username is optional.
#[must_use]
pub fn can_auto_type(item: &ItemSummary) -> bool {
    item.kind == ItemKind::Login && item.has_password
}

/// `username`, Tab, `password`; only the password when the username is empty.
#[must_use]
pub fn login_strokes(username: &str, password: &str) -> Vec<Stroke> {
    let mut strokes = Vec::new();
    if !username.is_empty() {
        strokes.extend(text_strokes(username));
        strokes.push(Stroke::Tab);
    }
    strokes.extend(text_strokes(password));
    strokes
}

/// One stroke per character, never splitting a surrogate pair.
#[must_use]
pub fn text_strokes(text: &str) -> Vec<Stroke> {
    text.chars()
        .map(|ch| {
            let mut units = Zeroizing::new(Vec::with_capacity(UNITS_PER_STROKE));
            let mut buffer = Zeroizing::new([0_u16; 2]);
            units.extend_from_slice(ch.encode_utf16(&mut *buffer));
            Stroke::Text(units)
        })
        .collect()
}

/// What the strokes type, with Tab as `\t`; for tests and the logging stub.
#[must_use]
pub fn typed_text(strokes: &[Stroke]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::new());
    for stroke in strokes {
        match stroke {
            Stroke::Text(units) => {
                text.extend(
                    char::decode_utf16(units.iter().copied())
                        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER)),
                );
            }
            Stroke::Tab => text.push('\t'),
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(stroke: &Stroke) -> Vec<u16> {
        match stroke {
            Stroke::Text(units) => units.to_vec(),
            Stroke::Tab => Vec::new(),
        }
    }

    #[test]
    fn username_tab_password() {
        let strokes = login_strokes("al", "p1");
        assert_eq!(strokes.len(), 5);
        assert_eq!(strokes[2], Stroke::Tab);
        assert_eq!(units(&strokes[0]), [u16::from(b'a')]);
        assert_eq!(units(&strokes[4]), [u16::from(b'1')]);
        assert_eq!(&*typed_text(&strokes), "al\tp1");
    }

    #[test]
    fn an_empty_username_types_only_the_password() {
        let strokes = login_strokes("", "secret");
        assert!(!strokes.contains(&Stroke::Tab));
        assert_eq!(&*typed_text(&strokes), "secret");
    }

    #[test]
    fn an_empty_password_types_nothing_after_the_tab() {
        assert_eq!(&*typed_text(&login_strokes("bob", "")), "bob\t");
        assert_eq!(login_strokes("", "").len(), 0);
    }

    #[test]
    fn characters_outside_the_bmp_stay_one_surrogate_pair() {
        // U+1F511 KEY is D83D DD11 in UTF-16 (Unicode 15, table 3-5).
        let strokes = text_strokes("é🔑");
        assert_eq!(strokes.len(), 2);
        assert_eq!(units(&strokes[0]), [0x00E9]);
        assert_eq!(units(&strokes[1]), [0xD83D, 0xDD11]);
        assert_eq!(&*typed_text(&strokes), "é🔑");
    }

    #[test]
    fn a_literal_tab_in_a_password_is_typed_as_text() {
        let strokes = text_strokes("a\tb");
        assert_eq!(units(&strokes[1]), [0x0009]);
        assert!(!strokes.contains(&Stroke::Tab));
    }

    fn item(kind: ItemKind, has_password: bool) -> ItemSummary {
        ItemSummary {
            id: vk_vault::model::ItemId(std::sync::Arc::from("id")),
            kind,
            name: "n".into(),
            subtitle: "".into(),
            favorite: false,
            folder_id: None,
            organization_id: None,
            primary_uri: None,
            has_password,
            has_totp: false,
            reprompt: false,
            deleted: false,
            editable: true,
        }
    }

    #[test]
    fn only_logins_with_a_password_can_be_typed() {
        assert!(can_auto_type(&item(ItemKind::Login, true)));
        assert!(!can_auto_type(&item(ItemKind::Login, false)));
        for kind in [
            ItemKind::Card,
            ItemKind::Identity,
            ItemKind::SecureNote,
            ItemKind::SshKey,
        ] {
            assert!(!can_auto_type(&item(kind, true)), "{kind:?}");
        }
    }
}
