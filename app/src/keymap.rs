//! In-window keyboard shortcuts. Slint reports ⌘ as `control` on macOS.

use slint::platform::Key;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Up,
    Down,
    CopyPassword,
    CopyUsername,
    CopyTotp,
    OpenUri,
    OpenInManager,
    Edit,
    ToggleFavorite,
    New,
    Generator,
    Settings,
    /// ⌘1…⌘5: login, card, identity, note, SSH key.
    FilterKind(u8),
    Escape,
    Lock,
    ToggleSidebar,
    FocusSearch,
    /// ⌘K: the Quick Panel from inside the app.
    QuickPanel,
    /// ⌘W: close the window (the app stays in the tray).
    CloseWindow,
    Quit,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Mods {
    pub cmd: bool,
    pub shift: bool,
    pub alt: bool,
}

fn is_key(text: &str, key: Key) -> bool {
    let mut chars = text.chars();
    chars.next() == Some(char::from(key)) && chars.next().is_none()
}

#[must_use]
pub fn command(text: &str, mods: Mods) -> Option<Command> {
    if mods.alt {
        return None;
    }
    if is_key(text, Key::UpArrow) {
        return Some(Command::Up);
    }
    if is_key(text, Key::DownArrow) {
        return Some(Command::Down);
    }
    if is_key(text, Key::Escape) {
        return Some(Command::Escape);
    }
    if is_key(text, Key::Return) {
        return Some(match (mods.cmd, mods.shift) {
            (true, true) => Command::OpenUri,
            (true, false) => Command::CopyTotp,
            (false, true) => Command::CopyUsername,
            (false, false) => Command::CopyPassword,
        });
    }
    if !mods.cmd {
        return None;
    }
    // Shift may turn letters upper-case in the key text.
    match (text.to_ascii_lowercase().as_str(), mods.shift) {
        ("l", _) => Some(Command::Lock),
        ("o", false) => Some(Command::OpenInManager),
        ("e", false) => Some(Command::Edit),
        ("f", false) => Some(Command::FocusSearch),
        ("f", true) => Some(Command::ToggleFavorite),
        ("k", false) => Some(Command::QuickPanel),
        ("w", false) => Some(Command::CloseWindow),
        ("q", false) => Some(Command::Quit),
        ("n", false) => Some(Command::New),
        ("g", false) => Some(Command::Generator),
        (",", false) => Some(Command::Settings),
        ("\\", false) => Some(Command::ToggleSidebar),
        (digit @ ("1" | "2" | "3" | "4" | "5"), false) => {
            digit.parse().ok().map(Command::FilterKind)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: Mods = Mods {
        cmd: true,
        shift: false,
        alt: false,
    };
    const SHIFT: Mods = Mods {
        cmd: false,
        shift: true,
        alt: false,
    };
    const CMD_SHIFT: Mods = Mods {
        cmd: true,
        shift: true,
        alt: false,
    };

    fn key(k: Key) -> String {
        char::from(k).to_string()
    }

    #[test]
    fn return_variants_follow_the_spec() {
        assert_eq!(
            command(&key(Key::Return), Mods::default()),
            Some(Command::CopyPassword)
        );
        assert_eq!(
            command(&key(Key::Return), SHIFT),
            Some(Command::CopyUsername)
        );
        assert_eq!(command(&key(Key::Return), CMD), Some(Command::CopyTotp));
        assert_eq!(
            command(&key(Key::Return), CMD_SHIFT),
            Some(Command::OpenUri)
        );
    }

    #[test]
    fn navigation_and_escape() {
        assert_eq!(
            command(&key(Key::UpArrow), Mods::default()),
            Some(Command::Up)
        );
        assert_eq!(
            command(&key(Key::DownArrow), Mods::default()),
            Some(Command::Down)
        );
        assert_eq!(
            command(&key(Key::Escape), Mods::default()),
            Some(Command::Escape)
        );
    }

    #[test]
    fn command_shortcuts() {
        assert_eq!(command("o", CMD), Some(Command::OpenInManager));
        assert_eq!(command("e", CMD), Some(Command::Edit));
        assert_eq!(command("f", CMD), Some(Command::FocusSearch));
        assert_eq!(command("F", CMD_SHIFT), Some(Command::ToggleFavorite));
        assert_eq!(command("k", CMD), Some(Command::QuickPanel));
        assert_eq!(command("w", CMD), Some(Command::CloseWindow));
        assert_eq!(command("q", CMD), Some(Command::Quit));
        assert_eq!(command("n", CMD), Some(Command::New));
        assert_eq!(command("g", CMD), Some(Command::Generator));
        assert_eq!(command(",", CMD), Some(Command::Settings));
        assert_eq!(command("\\", CMD), Some(Command::ToggleSidebar));
        assert_eq!(command("l", CMD), Some(Command::Lock));
        assert_eq!(command("L", CMD_SHIFT), Some(Command::Lock));
        assert_eq!(command("1", CMD), Some(Command::FilterKind(1)));
        assert_eq!(command("5", CMD), Some(Command::FilterKind(5)));
    }

    #[test]
    fn plain_typing_is_left_to_the_search_field() {
        assert_eq!(command("o", Mods::default()), None);
        assert_eq!(command("1", Mods::default()), None);
        assert_eq!(command("6", CMD), None);
        assert_eq!(command("x", CMD), None);
        let alt = Mods {
            alt: true,
            ..Mods::default()
        };
        assert_eq!(command(&key(Key::Return), alt), None);
    }
}
