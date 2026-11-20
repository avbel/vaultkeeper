//! User preferences and their mapping to the Settings window's option lists. Both processes read
//! them from `settings.json` (see [`crate::os::settings_file`]); unknown or missing fields fall
//! back to the defaults, so an older or newer file still loads.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    #[default]
    System,
    Light,
    Dark,
}

/// Tray icon style. `Auto` follows the menu bar (macOS) or the taskbar theme (Windows); `White`
/// and `Black` are the monochrome glyphs; `Blue` is the brand colour, independent of the bar.
/// The wire names stay the old `system`/`light`/`dark` so a file written by this build still
/// loads in a released one; the new names are accepted as aliases.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrayIconChoice {
    #[default]
    #[serde(rename = "system", alias = "auto")]
    Auto,
    #[serde(rename = "light", alias = "white")]
    White,
    #[serde(rename = "dark", alias = "black")]
    Black,
    Blue,
}

impl TrayIconChoice {
    #[must_use]
    pub const fn index(self) -> i32 {
        match self {
            Self::Auto => 0,
            Self::White => 1,
            Self::Black => 2,
            Self::Blue => 3,
        }
    }

    #[must_use]
    pub const fn from_index(index: i32) -> Option<Self> {
        match index {
            0 => Some(Self::Auto),
            1 => Some(Self::White),
            2 => Some(Self::Black),
            3 => Some(Self::Blue),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockTimeout {
    Minutes(u16),
    /// No idle timer. Older versions wrote `on_sleep`, which also meant "lock on sleep and screen
    /// lock"; that part is now [`Settings::lock_on_sleep`], on by default, so it carries over.
    #[serde(alias = "on_sleep")]
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardClear {
    Seconds(u16),
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshApproval {
    #[default]
    Always,
    RememberUntilLock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserMatch {
    #[default]
    Domain,
    Host,
}

/// Large-text setting: multiplies every font size and row height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextScale {
    #[default]
    Default,
    Large,
    Larger,
}

impl TextScale {
    #[must_use]
    pub const fn factor(self) -> f32 {
        match self {
            Self::Default => 1.0,
            Self::Large => 1.15,
            Self::Larger => 1.3,
        }
    }

    #[must_use]
    pub const fn index(self) -> i32 {
        match self {
            Self::Default => 0,
            Self::Large => 1,
            Self::Larger => 2,
        }
    }

    #[must_use]
    pub const fn from_index(index: i32) -> Option<Self> {
        match index {
            0 => Some(Self::Default),
            1 => Some(Self::Large),
            2 => Some(Self::Larger),
            _ => None,
        }
    }
}

/// Manager window placement in logical pixels, restored when it opens again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowGeometry {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub sidebar_collapsed: bool,
}

pub const MANAGER_MIN_SIZE: (u32, u32) = (760, 480);

impl WindowGeometry {
    /// Keeps the window at least its minimum size and its origin on the screen's positive
    /// quadrant; clamping to the actual screen bounds needs the platform's screen list.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            x: self.x.max(0),
            y: self.y.max(0),
            width: self.width.max(MANAGER_MIN_SIZE.0),
            height: self.height.max(MANAGER_MIN_SIZE.1),
            ..self
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeChoice,
    /// Tray icon style (see [`TrayIconChoice`]).
    pub tray_icon: TrayIconChoice,
    pub text_scale: TextScale,
    /// Website icons on login rows, fetched through the account's server.
    pub show_site_icons: bool,
    /// Windows only: keep Vaultkeeper windows out of screenshots, screen sharing and Recall.
    pub hide_from_capture: bool,
    pub manager_geometry: Option<WindowGeometry>,
    pub lock_timeout: LockTimeout,
    /// Lock when the Mac sleeps or the screen locks, whatever the timeout.
    pub lock_on_sleep: bool,
    pub clipboard_clear: ClipboardClear,
    pub start_at_login: bool,
    pub ask_unlock_on_start: bool,
    pub require_master_password_on_start: bool,
    /// Off for a new install; a file written before this default changed and lacking the field
    /// keeps the agent on, as it was then.
    #[serde(default = "legacy_ssh_agent")]
    pub ssh_agent: bool,
    pub cli_access: bool,
    /// Check GitHub daily and install a verified update once the vault is locked; off makes no
    /// update requests until "Check for Updates…" is clicked.
    pub auto_update: bool,
    pub ssh_approval: SshApproval,
    pub ssh_touch_id: bool,
    pub browser_integration: bool,
    /// Per-browser install switches; they only matter while `browser_integration` is on.
    pub browser_chrome: bool,
    pub browser_edge: bool,
    pub browser_firefox: bool,
    pub browser_touch_id: bool,
    pub browser_save_prompts: bool,
    pub browser_copy_totp: bool,
    /// Fill without the picker when exactly one login matches the site (Touch ID still applies).
    pub browser_fill_single: bool,
    /// Fill a remembered login as soon as its page opens, with no click. Off by default: the
    /// password is then readable by the page's scripts without the user having asked for it.
    pub browser_autofill: bool,
    /// Save and sign in with vault passkeys; off leaves every site to the browser's own.
    pub browser_passkeys: bool,
    pub browser_default_match: BrowserMatch,
    pub hotkey: String,
    /// Opens the Generator window from anywhere; empty means no shortcut.
    pub generator_hotkey: String,
    /// Start the Touch ID unlock as soon as something needs the vault, before any lock window.
    pub touch_id_right_away: bool,
    #[serde(deserialize_with = "lenient_generator")]
    pub generator: GeneratorPrefs,
    /// Sealed by [`crate::last_login`]; never plain text. A value of the wrong type reads as
    /// `None` instead of failing the whole file.
    #[serde(deserialize_with = "lenient_string")]
    pub last_login: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::System,
            tray_icon: TrayIconChoice::default(),
            text_scale: TextScale::Default,
            show_site_icons: true,
            hide_from_capture: true,
            manager_geometry: None,
            lock_timeout: LockTimeout::Minutes(15),
            lock_on_sleep: true,
            clipboard_clear: ClipboardClear::Seconds(30),
            start_at_login: false,
            ask_unlock_on_start: false,
            require_master_password_on_start: false,
            ssh_agent: false,
            cli_access: false,
            auto_update: true,
            ssh_approval: SshApproval::Always,
            ssh_touch_id: false,
            browser_integration: false,
            browser_chrome: true,
            browser_edge: true,
            browser_firefox: true,
            browser_touch_id: false,
            browser_save_prompts: true,
            browser_copy_totp: true,
            browser_fill_single: true,
            browser_autofill: false,
            browser_passkeys: true,
            browser_default_match: BrowserMatch::Domain,
            hotkey: DEFAULT_HOTKEY.to_owned(),
            generator_hotkey: String::new(),
            touch_id_right_away: false,
            last_login: None,
            generator: GeneratorPrefs::default(),
        }
    }
}

/// The generator's last options, so the next generator opens with them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneratorPrefs {
    pub passphrase_mode: bool,
    pub length: u8,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub special: bool,
    pub min_numbers: u8,
    pub min_special: u8,
    pub avoid_ambiguous: bool,
    pub words: u8,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for GeneratorPrefs {
    fn default() -> Self {
        let password = vk_gen::generator::PasswordOptions::default();
        let passphrase = vk_gen::generator::PassphraseOptions::default();
        Self {
            passphrase_mode: false,
            length: password.length,
            uppercase: password.uppercase,
            lowercase: password.lowercase,
            numbers: password.numbers,
            special: password.special,
            min_numbers: password.min_numbers,
            min_special: password.min_special,
            avoid_ambiguous: password.avoid_ambiguous,
            words: passphrase.words,
            separator: passphrase.separator,
            capitalize: passphrase.capitalize,
            include_number: passphrase.include_number,
        }
    }
}

impl GeneratorPrefs {
    /// The saved password options, clamped to the generator's valid ranges.
    #[must_use]
    pub fn password_options(&self) -> vk_gen::generator::PasswordOptions {
        vk_gen::generator::PasswordOptions {
            length: self.length.clamp(5, 128),
            uppercase: self.uppercase,
            lowercase: self.lowercase,
            numbers: self.numbers,
            special: self.special,
            min_numbers: self.min_numbers.min(9),
            min_special: self.min_special.min(9),
            avoid_ambiguous: self.avoid_ambiguous,
        }
    }

    /// The saved passphrase options, clamped to the generator's valid ranges.
    #[must_use]
    pub fn passphrase_options(&self) -> vk_gen::generator::PassphraseOptions {
        vk_gen::generator::PassphraseOptions {
            words: self.words.clamp(3, 20),
            separator: self.separator.clone(),
            capitalize: self.capitalize,
            include_number: self.include_number,
        }
    }
}

/// A damaged `generator` entry falls back to the defaults instead of failing the whole file.
const fn legacy_ssh_agent() -> bool {
    true
}

fn lenient_generator<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<GeneratorPrefs, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).unwrap_or_default())
}

fn lenient_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(value.as_str().map(str::to_owned))
}

impl Settings {
    /// Pulls values a hand-edited file may carry back into the supported range.
    #[must_use]
    pub fn sanitized(self) -> Self {
        let lock_timeout = match self.lock_timeout {
            LockTimeout::Minutes(0) => LockTimeout::Minutes(1),
            other => other,
        };
        let clipboard_clear = match self.clipboard_clear {
            ClipboardClear::Seconds(0) => ClipboardClear::Seconds(1),
            other => other,
        };
        let hotkey = if self.hotkey.trim().is_empty() {
            Self::default().hotkey
        } else {
            self.hotkey
        };
        Self {
            lock_timeout,
            clipboard_clear,
            hotkey,
            manager_geometry: self.manager_geometry.map(WindowGeometry::clamped),
            ..self
        }
    }
}

/// Windows reserves most Win+ chords and Ctrl+Alt is AltGr on many layouts, so Ctrl+Shift it is.
#[cfg(windows)]
pub const DEFAULT_HOTKEY: &str = "Ctrl+Shift+Space";
#[cfg(not(windows))]
pub const DEFAULT_HOTKEY: &str = "Cmd+Shift+Space";

/// "Cmd+Shift+Space" as macOS shows it, "⌘⇧Space": modifiers as symbols in Apple's order
/// (⌃⌥⇧⌘), then the key. `KeyK` / `Digit1` (global-hotkey's code names) become `K` / `1`.
#[must_use]
pub fn hotkey_symbols(accelerator: &str) -> String {
    const ORDER: [(&str, &[&str]); 4] = [
        ("⌃", &["ctrl", "control"]),
        ("⌥", &["alt", "option"]),
        ("⇧", &["shift"]),
        (
            "⌘",
            &[
                "cmd",
                "command",
                "super",
                "meta",
                "cmdorctrl",
                "commandorcontrol",
            ],
        ),
    ];
    let parts: Vec<&str> = accelerator
        .split('+')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    let Some((key, modifiers)) = parts.split_last() else {
        return String::new();
    };
    let mut text: String = ORDER
        .iter()
        .filter(|(_, names)| {
            modifiers
                .iter()
                .any(|modifier| names.contains(&modifier.to_ascii_lowercase().as_str()))
        })
        .map(|(symbol, _)| *symbol)
        .collect();
    let key = key
        .strip_prefix("Key")
        .or_else(|| key.strip_prefix("Digit"))
        .filter(|rest| rest.len() == 1)
        .unwrap_or(key);
    let named = [
        (&["up", "arrowup"][..], "↑"),
        (&["down", "arrowdown"], "↓"),
        (&["left", "arrowleft"], "←"),
        (&["right", "arrowright"], "→"),
        (&["enter"], "↩"),
        (&["tab"], "⇥"),
    ]
    .iter()
    .find(|(names, _)| names.contains(&key.to_ascii_lowercase().as_str()))
    .map(|(_, symbol)| *symbol);
    match named {
        Some(symbol) => text.push_str(symbol),
        None if key.len() == 1 => text.push_str(&key.to_ascii_uppercase()),
        None => text.push_str(key),
    }
    text
}

/// The shortcut as this platform shows it: macOS symbols, or "Ctrl+Shift+Space" on Windows.
#[must_use]
pub fn hotkey_display(accelerator: &str) -> String {
    if cfg!(windows) {
        hotkey_names(accelerator)
    } else {
        hotkey_symbols(accelerator)
    }
}

/// Exactly Ctrl and Alt held, no Shift and no Win/Cmd: AltGr on layouts that have it.
#[must_use]
pub fn ctrl_alt_only(accelerator: &str) -> bool {
    let parts: Vec<String> = accelerator
        .split('+')
        .map(|part| part.trim().to_lowercase())
        .filter(|part| !part.is_empty())
        .collect();
    let Some((_, modifiers)) = parts.split_last() else {
        return false;
    };
    let has = |names: &[&str]| modifiers.iter().any(|part| names.contains(&part.as_str()));
    has(&["ctrl", "control", "cmdorctrl", "commandorcontrol"])
        && has(&["alt", "option"])
        && !has(&["shift", "cmd", "command", "super", "meta", "win"])
}

/// "Ctrl+Shift+Space": modifiers by name in Windows order (Ctrl, Alt, Shift, Win) joined with `+`.
#[must_use]
pub fn hotkey_names(accelerator: &str) -> String {
    const ORDER: [(&str, &[&str]); 4] = [
        (
            "Ctrl",
            &["ctrl", "control", "cmdorctrl", "commandorcontrol"],
        ),
        ("Alt", &["alt", "option"]),
        ("Shift", &["shift"]),
        ("Win", &["cmd", "command", "super", "meta"]),
    ];
    let parts: Vec<&str> = accelerator
        .split('+')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    let Some((key, modifiers)) = parts.split_last() else {
        return String::new();
    };
    let mut names: Vec<String> = ORDER
        .iter()
        .filter(|(_, aliases)| {
            modifiers
                .iter()
                .any(|modifier| aliases.contains(&modifier.to_ascii_lowercase().as_str()))
        })
        .map(|(name, _)| (*name).to_owned())
        .collect();
    let key = key
        .strip_prefix("Key")
        .or_else(|| key.strip_prefix("Digit"))
        .filter(|rest| rest.len() == 1)
        .or_else(|| key.strip_prefix("Arrow"))
        .unwrap_or(key);
    names.push(if key.len() == 1 {
        key.to_ascii_uppercase()
    } else {
        key.to_owned()
    });
    names.join("+")
}

pub const LOCK_OPTIONS: [LockTimeout; 6] = [
    LockTimeout::Minutes(1),
    LockTimeout::Minutes(5),
    LockTimeout::Minutes(15),
    LockTimeout::Minutes(30),
    LockTimeout::Minutes(60),
    LockTimeout::Never,
];

pub const CLIPBOARD_OPTIONS: [ClipboardClear; 4] = [
    ClipboardClear::Seconds(10),
    ClipboardClear::Seconds(30),
    ClipboardClear::Seconds(60),
    ClipboardClear::Never,
];

impl LockTimeout {
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Minutes(1) => "1 minute".to_owned(),
            Self::Minutes(minutes) => format!("{minutes} minutes"),
            Self::Never => "Never".to_owned(),
        }
    }
}

impl ClipboardClear {
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Seconds(seconds) => format!("After {seconds} s"),
            Self::Never => "Never".to_owned(),
        }
    }

    #[must_use]
    pub fn duration(self) -> Option<Duration> {
        match self {
            Self::Seconds(seconds) => Some(Duration::from_secs(u64::from(seconds))),
            Self::Never => None,
        }
    }
}

#[must_use]
pub fn option_index<T: PartialEq>(options: &[T], value: &T) -> i32 {
    options
        .iter()
        .position(|option| option == value)
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or(-1)
}

#[must_use]
pub fn option_at<T: Copy>(options: &[T], index: i32) -> Option<T> {
    usize::try_from(index)
        .ok()
        .and_then(|index| options.get(index))
        .copied()
}

impl ThemeChoice {
    #[must_use]
    pub const fn index(self) -> i32 {
        match self {
            Self::System => 0,
            Self::Light => 1,
            Self::Dark => 2,
        }
    }

    #[must_use]
    pub const fn from_index(index: i32) -> Option<Self> {
        match index {
            0 => Some(Self::System),
            1 => Some(Self::Light),
            2 => Some(Self::Dark),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_bare_ctrl_alt_pair_counts_as_altgr() {
        use super::ctrl_alt_only;
        assert!(ctrl_alt_only("Ctrl+Alt+G"));
        assert!(ctrl_alt_only("alt+control+F5"));
        assert!(!ctrl_alt_only("Ctrl+Alt+Shift+G"));
        assert!(!ctrl_alt_only("Ctrl+Alt+Cmd+G"));
        assert!(!ctrl_alt_only("Ctrl+G"));
        assert!(!ctrl_alt_only("Alt+G"));
        assert!(!ctrl_alt_only("G"));
        assert!(!ctrl_alt_only(""));
    }

    use super::*;

    #[test]
    fn defaults_match_the_spec() {
        let settings = Settings::default();
        assert_eq!(settings.theme, ThemeChoice::System);
        assert_eq!(
            settings.clipboard_clear.duration(),
            Some(Duration::from_secs(30))
        );
        assert!(!settings.require_master_password_on_start);
        assert!(!settings.ssh_agent);
        assert!(settings.auto_update);
    }

    #[test]
    fn the_ssh_agent_is_off_for_new_installs_and_on_for_files_that_predate_the_default() {
        assert!(!Settings::default().ssh_agent);
        let old: Settings = serde_json::from_str(r#"{"theme":"dark"}"#).expect("old settings");
        assert!(old.ssh_agent);
        let off: Settings = serde_json::from_str(r#"{"ssh_agent":false}"#).expect("explicit off");
        assert!(!off.ssh_agent);
        let json = serde_json::to_string(&Settings::default()).expect("serialize");
        assert!(json.contains(r#""ssh_agent":false"#), "{json}");
    }

    #[test]
    fn browser_settings_default_and_survive_round_trip() {
        let old: Settings = serde_json::from_str(r#"{"theme":"dark"}"#).expect("old settings");
        assert!(!old.browser_integration);
        assert!(old.browser_chrome);
        assert!(old.browser_edge);
        assert!(old.browser_firefox);
        assert!(!old.browser_touch_id);
        assert!(old.browser_save_prompts);
        assert!(old.browser_copy_totp);
        assert!(old.browser_fill_single);
        assert!(!old.browser_autofill);
        assert!(old.browser_passkeys);
        assert_eq!(old.browser_default_match, BrowserMatch::Domain);
        let settings = Settings {
            browser_integration: true,
            browser_chrome: false,
            browser_edge: false,
            browser_firefox: false,
            browser_autofill: true,
            browser_default_match: BrowserMatch::Host,
            ..old
        };
        let json = serde_json::to_string(&settings).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Settings>(&json).expect("deserialize"),
            settings
        );
    }

    #[test]
    fn capture_exclusion_is_on_unless_a_file_says_otherwise() {
        assert!(Settings::default().hide_from_capture);
        let old: Settings = serde_json::from_str(r#"{"theme":"dark"}"#).expect("old settings");
        assert!(old.hide_from_capture);
        let off: Settings =
            serde_json::from_str(r#"{"hide_from_capture":false}"#).expect("explicit off");
        assert!(!off.hide_from_capture);
        let json = serde_json::to_string(&off).expect("serialize");
        assert!(json.contains(r#""hide_from_capture":false"#), "{json}");
    }

    #[test]
    fn option_lists_round_trip() {
        for (index, option) in LOCK_OPTIONS.iter().enumerate() {
            let index = i32::try_from(index).expect("small");
            assert_eq!(option_index(&LOCK_OPTIONS, option), index);
            assert_eq!(option_at(&LOCK_OPTIONS, index), Some(*option));
        }
        assert_eq!(option_at(&LOCK_OPTIONS, -1), None);
        assert_eq!(option_at(&LOCK_OPTIONS, 6), None);
        assert_eq!(
            option_index(&CLIPBOARD_OPTIONS, &ClipboardClear::Seconds(45)),
            -1
        );
    }

    #[test]
    fn labels() {
        assert_eq!(LockTimeout::Minutes(1).label(), "1 minute");
        assert_eq!(LockTimeout::Minutes(15).label(), "15 minutes");
        assert_eq!(LockTimeout::Never.label(), "Never");
        assert_eq!(ClipboardClear::Seconds(10).label(), "After 10 s");
        assert_eq!(ClipboardClear::Never.label(), "Never");
        assert_eq!(ClipboardClear::Never.duration(), None);
    }

    #[test]
    fn text_scale_follows_the_refinement_steps() {
        assert!((TextScale::Default.factor() - 1.0).abs() < f32::EPSILON);
        assert!((TextScale::Large.factor() - 1.15).abs() < f32::EPSILON);
        assert!((TextScale::Larger.factor() - 1.3).abs() < f32::EPSILON);
        for scale in [TextScale::Default, TextScale::Large, TextScale::Larger] {
            assert_eq!(TextScale::from_index(scale.index()), Some(scale));
        }
        assert_eq!(TextScale::from_index(3), None);
    }

    #[test]
    fn geometry_is_clamped_to_the_minimum_size() {
        let geometry = WindowGeometry {
            x: -40,
            y: 10,
            width: 300,
            height: 900,
            sidebar_collapsed: true,
        };
        assert_eq!(
            geometry.clamped(),
            WindowGeometry {
                x: 0,
                y: 10,
                width: 760,
                height: 900,
                sidebar_collapsed: true,
            }
        );
    }

    #[test]
    fn a_broken_last_login_value_is_dropped_without_resetting_other_settings() {
        for broken in ["42", "{\"server\":1}", "[]", "null"] {
            let json = format!(r#"{{"theme":"dark","last_login":{broken}}}"#);
            let settings: Settings = serde_json::from_str(&json).expect(&json);
            assert_eq!(settings.theme, ThemeChoice::Dark, "{json}");
            assert_eq!(settings.last_login, None, "{json}");
        }
    }

    #[test]
    fn hotkeys_are_shown_with_mac_symbols_in_apple_order() {
        assert_eq!(hotkey_symbols("Cmd+Shift+Space"), "⇧⌘Space");
        assert_eq!(hotkey_symbols("Shift+Cmd+KeyK"), "⇧⌘K");
        assert_eq!(hotkey_symbols("ctrl+alt+Digit1"), "⌃⌥1");
        assert_eq!(hotkey_symbols("Cmd+Alt+k"), "⌥⌘K");
        assert_eq!(hotkey_symbols("F5"), "F5");
        assert_eq!(hotkey_symbols("Cmd+Alt+Up"), "⌥⌘↑");
        assert_eq!(hotkey_symbols("Ctrl+ArrowLeft"), "⌃←");
        assert_eq!(hotkey_symbols("Cmd+Enter"), "⌘↩");
        assert_eq!(hotkey_symbols("Cmd+Shift+Tab"), "⇧⌘⇥");
        assert_eq!(hotkey_symbols("Cmd+Alt+,"), "⌥⌘,");
    }

    #[test]
    fn hotkey_names_follow_the_windows_convention() {
        assert_eq!(hotkey_names("Ctrl+Shift+Space"), "Ctrl+Shift+Space");
        assert_eq!(hotkey_names("Shift+Cmd+KeyK"), "Shift+Win+K");
        assert_eq!(hotkey_names("shift+alt+ctrl+Digit1"), "Ctrl+Alt+Shift+1");
        assert_eq!(hotkey_names("Ctrl+ArrowLeft"), "Ctrl+Left");
        assert_eq!(hotkey_names("Ctrl+Alt+,"), "Ctrl+Alt+,");
        assert_eq!(hotkey_names(""), "");
        assert_eq!(hotkey_symbols(""), "");
    }

    #[test]
    fn a_damaged_generator_entry_falls_back_to_the_defaults_only() {
        let json = r#"{"theme":"dark","generator":{"length":"long"}}"#;
        let settings: Settings = serde_json::from_str(json).expect(json);
        assert_eq!(settings.theme, ThemeChoice::Dark);
        assert_eq!(settings.generator, GeneratorPrefs::default());
        let missing: Settings = serde_json::from_str(r#"{"theme":"dark"}"#).expect("missing");
        assert_eq!(missing.generator, GeneratorPrefs::default());
    }

    #[test]
    fn json_round_trips_every_field() {
        let settings = Settings {
            theme: ThemeChoice::Dark,
            tray_icon: TrayIconChoice::White,
            text_scale: TextScale::Larger,
            show_site_icons: false,
            hide_from_capture: false,
            manager_geometry: Some(WindowGeometry {
                x: 10,
                y: 20,
                width: 1120,
                height: 700,
                sidebar_collapsed: true,
            }),
            lock_timeout: LockTimeout::Never,
            lock_on_sleep: false,
            clipboard_clear: ClipboardClear::Never,
            start_at_login: true,
            ask_unlock_on_start: true,
            require_master_password_on_start: true,
            ssh_agent: false,
            cli_access: true,
            auto_update: false,
            ssh_approval: SshApproval::RememberUntilLock,
            ssh_touch_id: true,
            browser_integration: true,
            browser_chrome: false,
            browser_edge: true,
            browser_firefox: false,
            browser_touch_id: true,
            browser_save_prompts: false,
            browser_copy_totp: false,
            browser_fill_single: false,
            browser_autofill: true,
            browser_passkeys: false,
            browser_default_match: BrowserMatch::Host,
            hotkey: "Cmd+Alt+K".to_owned(),
            generator_hotkey: "Cmd+Alt+G".to_owned(),
            touch_id_right_away: true,
            last_login: Some("2.sealed".to_owned()),
            generator: GeneratorPrefs {
                passphrase_mode: true,
                length: 40,
                special: true,
                words: 8,
                separator: "_".to_owned(),
                ..GeneratorPrefs::default()
            },
        };
        let json = serde_json::to_string(&settings).expect("encode");
        let back: Settings = serde_json::from_str(&json).expect("decode");
        assert_eq!(back, settings);
    }

    #[test]
    fn the_file_format_is_stable_snake_case() {
        let json = r#"{"theme":"light","lock_timeout":{"minutes":5},"clipboard_clear":{"seconds":10},
            "ssh_approval":"remember_until_lock","text_scale":"large"}"#;
        let settings: Settings = serde_json::from_str(json).expect("decode");
        assert_eq!(settings.theme, ThemeChoice::Light);
        assert_eq!(settings.lock_timeout, LockTimeout::Minutes(5));
        assert_eq!(settings.clipboard_clear, ClipboardClear::Seconds(10));
        assert_eq!(settings.ssh_approval, SshApproval::RememberUntilLock);
        assert_eq!(settings.text_scale, TextScale::Large);
        assert_eq!(
            settings.hotkey, DEFAULT_HOTKEY,
            "missing fields take the default"
        );
        assert!(
            settings.lock_on_sleep,
            "files from before the setting lock on sleep"
        );
        let on_sleep: Settings =
            serde_json::from_str(r#"{"lock_timeout":"on_sleep","unknown":1}"#).expect("decode");
        assert_eq!(on_sleep.lock_timeout, LockTimeout::Never);
        assert!(
            on_sleep.lock_on_sleep,
            "the old \"on sleep\" choice keeps locking on sleep"
        );
        let json = serde_json::to_string(&on_sleep).expect("encode");
        assert!(json.contains(r#""lock_timeout":"never""#), "{json}");
        assert!(json.contains(r#""lock_on_sleep":true"#), "{json}");
    }

    #[test]
    fn files_from_before_the_touch_id_option_get_its_default() {
        let settings: Settings =
            serde_json::from_str(r#"{"theme":"dark","hotkey":"Cmd+Alt+K"}"#).expect("decode");
        assert!(!settings.touch_id_right_away, "Touch ID waits for a click");
        assert!(
            settings.show_site_icons,
            "site icons are on until switched off"
        );
        assert_eq!(settings.theme, ThemeChoice::Dark);
    }

    #[test]
    fn locking_on_sleep_is_on_by_default_next_to_the_timeout() {
        let defaults = Settings::default();
        assert!(defaults.lock_on_sleep);
        assert_eq!(defaults.lock_timeout, LockTimeout::Minutes(15));
    }

    #[test]
    fn sanitizing_fixes_values_the_ui_never_writes() {
        let odd = Settings {
            lock_timeout: LockTimeout::Minutes(0),
            clipboard_clear: ClipboardClear::Seconds(0),
            hotkey: "  ".to_owned(),
            manager_geometry: Some(WindowGeometry {
                x: -5,
                y: 0,
                width: 10,
                height: 10,
                sidebar_collapsed: false,
            }),
            ..Settings::default()
        }
        .sanitized();
        assert_eq!(odd.lock_timeout, LockTimeout::Minutes(1));
        assert_eq!(odd.clipboard_clear, ClipboardClear::Seconds(1));
        assert_eq!(odd.hotkey, DEFAULT_HOTKEY);
        assert_eq!(
            odd.manager_geometry.map(|g| (g.x, g.width, g.height)),
            Some((0, 760, 480))
        );
        assert_eq!(Settings::default().sanitized(), Settings::default());
    }

    #[test]
    fn theme_index_round_trips() {
        for choice in [ThemeChoice::System, ThemeChoice::Light, ThemeChoice::Dark] {
            assert_eq!(ThemeChoice::from_index(choice.index()), Some(choice));
        }
        assert_eq!(ThemeChoice::from_index(3), None);
    }

    #[test]
    fn tray_icon_index_round_trips() {
        for choice in [
            TrayIconChoice::Auto,
            TrayIconChoice::White,
            TrayIconChoice::Black,
            TrayIconChoice::Blue,
        ] {
            assert_eq!(TrayIconChoice::from_index(choice.index()), Some(choice));
        }
        assert_eq!(TrayIconChoice::from_index(4), None);
        assert_eq!(TrayIconChoice::from_index(-1), None);
    }

    #[test]
    fn old_tray_icon_names_still_load() {
        for (json, expected) in [
            (r#"{"tray_icon":"system"}"#, TrayIconChoice::Auto),
            (r#"{"tray_icon":"light"}"#, TrayIconChoice::White),
            (r#"{"tray_icon":"dark"}"#, TrayIconChoice::Black),
            (r#"{"tray_icon":"auto"}"#, TrayIconChoice::Auto),
            (r#"{"tray_icon":"white"}"#, TrayIconChoice::White),
            (r#"{"tray_icon":"black"}"#, TrayIconChoice::Black),
        ] {
            let settings: Settings = serde_json::from_str(json).expect(json);
            assert_eq!(settings.tray_icon, expected, "{json}");
        }
    }

    #[test]
    fn the_tray_icon_is_auto_unless_a_file_says_otherwise() {
        assert_eq!(Settings::default().tray_icon, TrayIconChoice::Auto);
        let blue: Settings = serde_json::from_str(r#"{"tray_icon":"blue"}"#).expect("blue");
        assert_eq!(blue.tray_icon, TrayIconChoice::Blue);
    }

    #[test]
    fn tray_icon_blue_round_trips() {
        let settings = Settings {
            tray_icon: TrayIconChoice::Blue,
            ..Settings::default()
        };
        let json = serde_json::to_string(&settings).expect("encode");
        assert_eq!(
            serde_json::from_str::<Settings>(&json)
                .expect("decode")
                .tray_icon,
            TrayIconChoice::Blue
        );
        assert!(json.contains(r#""tray_icon":"blue""#), "{json}");
    }

    #[test]
    fn tray_icon_keeps_old_wire_names() {
        let settings = Settings {
            tray_icon: TrayIconChoice::White,
            ..Settings::default()
        };
        let json = serde_json::to_string(&settings).expect("encode");
        assert!(json.contains(r#""tray_icon":"light""#), "{json}");
    }
}
