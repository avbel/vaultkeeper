//! A saved accelerator ("Ctrl+Shift+Space") in the spellings Linux desktops want: the
//! GlobalShortcuts portal's trigger syntax and the key-binding lines of the compositors that have
//! no portal backend. Plain functions over text, so they test on any host.

/// The accelerator's modifiers and its key as an XKB keysym name, which the portal, Sway and
/// Hyprland all read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chord {
    ctrl: bool,
    alt: bool,
    shift: bool,
    logo: bool,
    key: String,
}

impl Chord {
    /// `None` for text without a key or with a key this converter has no keysym for.
    #[must_use]
    pub fn parse(accelerator: &str) -> Option<Self> {
        let mut chord = Self {
            ctrl: false,
            alt: false,
            shift: false,
            logo: false,
            key: String::new(),
        };
        let mut key = None;
        for part in accelerator.split('+').map(str::trim) {
            match part.to_ascii_lowercase().as_str() {
                "" => return None,
                "ctrl" | "control" | "cmdorctrl" | "commandorcontrol" => chord.ctrl = true,
                "alt" | "option" => chord.alt = true,
                "shift" => chord.shift = true,
                "super" | "cmd" | "command" | "meta" | "win" => chord.logo = true,
                _ if key.is_some() => return None,
                _ => key = Some(keysym(part)?),
            }
        }
        chord.key = key?;
        Some(chord)
    }

    fn modifiers(&self) -> Vec<Modifier> {
        [
            (self.ctrl, Modifier::Ctrl),
            (self.alt, Modifier::Alt),
            (self.shift, Modifier::Shift),
            (self.logo, Modifier::Logo),
        ]
        .into_iter()
        .filter_map(|(held, modifier)| held.then_some(modifier))
        .collect()
    }

    fn joined(&self, separator: &str, name: impl Fn(Modifier) -> &'static str) -> String {
        let mut parts: Vec<String> = self
            .modifiers()
            .into_iter()
            .map(|modifier| name(modifier).to_owned())
            .collect();
        parts.push(self.key.clone());
        parts.join(separator)
    }
}

#[derive(Debug, Clone, Copy)]
enum Modifier {
    Ctrl,
    Alt,
    Shift,
    Logo,
}

/// `Ctrl+Shift+Space` becomes `CTRL+SHIFT+space`, the `preferred_trigger` of the shortcuts
/// specification.
#[must_use]
pub fn portal_trigger(accelerator: &str) -> Option<String> {
    Chord::parse(accelerator).map(|chord| {
        chord.joined("+", |modifier| match modifier {
            Modifier::Ctrl => "CTRL",
            Modifier::Alt => "ALT",
            Modifier::Shift => "SHIFT",
            Modifier::Logo => "LOGO",
        })
    })
}

fn keysym(token: &str) -> Option<String> {
    let lower = token.to_ascii_lowercase();
    let single = |text: &str| {
        let mut chars = text.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => Some(c),
            _ => None,
        }
    };
    let letter_or_digit = lower
        .strip_prefix("key")
        .or_else(|| lower.strip_prefix("digit"))
        .unwrap_or(&lower);
    if let Some(c) = single(letter_or_digit).filter(char::is_ascii_alphanumeric) {
        return Some(c.to_ascii_lowercase().to_string());
    }
    if let Some(number) = lower
        .strip_prefix('f')
        .and_then(|rest| rest.parse::<u8>().ok())
        && (1..=24).contains(&number)
    {
        return Some(format!("F{number}"));
    }
    let named = match lower.as_str() {
        "space" | " " => "space",
        "enter" | "return" => "Return",
        "tab" => "Tab",
        "escape" | "esc" => "Escape",
        "backspace" => "BackSpace",
        "delete" => "Delete",
        "insert" => "Insert",
        "home" => "Home",
        "end" => "End",
        "pageup" => "Page_Up",
        "pagedown" => "Page_Down",
        "up" | "arrowup" => "Up",
        "down" | "arrowdown" => "Down",
        "left" | "arrowleft" => "Left",
        "right" | "arrowright" => "Right",
        "`" | "backquote" => "grave",
        "\\" | "backslash" => "backslash",
        "[" | "bracketleft" => "bracketleft",
        "]" | "bracketright" => "bracketright",
        "," | "comma" => "comma",
        "-" | "minus" => "minus",
        "." | "period" => "period",
        "'" | "quote" => "apostrophe",
        ";" | "semicolon" => "semicolon",
        "/" | "slash" => "slash",
        "=" | "equal" => "equal",
        _ => return None,
    };
    Some(named.to_owned())
}

/// The ids the GlobalShortcuts portal registers; a Hyprland `global` bind addresses them as
/// `<app id>:<id>`.
pub const QUICK_PANEL_ID: &str = "quick-panel";
pub const GENERATOR_ID: &str = "generator";

/// What `XDG_CURRENT_DESKTOP` and the distribution say about where a binding line goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compositor {
    Sway,
    Hyprland,
    /// Hyprland configured through Omarchy's Lua bindings (`~/.config/hypr/bindings.lua`).
    Omarchy,
    Other,
}

impl Compositor {
    /// `current_desktop` is `XDG_CURRENT_DESKTOP`, a colon-separated list; Omarchy is Hyprland, so
    /// the Lua bindings file of an Omarchy install wins.
    #[must_use]
    pub fn detect(current_desktop: &str, omarchy_lua: bool) -> Self {
        let has = |name: &str| {
            current_desktop
                .split(':')
                .any(|entry| entry.eq_ignore_ascii_case(name))
        };
        if omarchy_lua && has("hyprland") {
            Self::Omarchy
        } else if has("sway") {
            Self::Sway
        } else if has("hyprland") {
            Self::Hyprland
        } else {
            Self::Other
        }
    }
}

/// The flags a compositor binding passes to `launcher`; the second instance forwards them to the
/// daemon.
const SEARCH_FLAG: &str = "--search";
const GENERATOR_FLAG: &str = "--generator";

/// The binding lines for the saved shortcuts, one per line; an empty accelerator has none.
/// `launcher` is what starts Vaultkeeper from the compositor (`vaultkeeper`, or an absolute path
/// when it is not on `PATH`). `None` when the desktop has no line syntax this app knows.
#[must_use]
pub fn compositor_lines(
    compositor: Compositor,
    launcher: &str,
    quick_panel: &str,
    generator: &str,
) -> Option<String> {
    let search = format!("{launcher} {SEARCH_FLAG}");
    let generate = format!("{launcher} {GENERATOR_FLAG}");
    let entries = [
        (quick_panel, search.as_str(), "Vaultkeeper"),
        (generator, generate.as_str(), "Vaultkeeper generator"),
    ];
    let lines: Vec<String> = entries
        .iter()
        .filter_map(|(accelerator, command, title)| {
            let chord = Chord::parse(accelerator)?;
            line(compositor, &chord, command, title)
        })
        .collect();
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// The bind lines for desktops whose portal backend takes no shortcut proposals but does run an
/// app's shortcut through a `global` bind of the compositor (Hyprland: xdg-desktop-portal-hyprland
/// ignores `ConfigureShortcuts`). The empty accelerator has no line.
#[must_use]
pub fn global_lines(
    compositor: Compositor,
    app_id: &str,
    quick_panel: &str,
    generator: &str,
) -> Option<String> {
    let entries = [
        (quick_panel, QUICK_PANEL_ID, "Vaultkeeper"),
        (generator, GENERATOR_ID, "Vaultkeeper generator"),
    ];
    let lines: Vec<String> = entries
        .iter()
        .filter_map(|(accelerator, id, title)| {
            let chord = Chord::parse(accelerator)?;
            global_line(compositor, &chord, &format!("{app_id}:{id}"), title)
        })
        .collect();
    (!lines.is_empty()).then(|| lines.join("\n"))
}

fn global_line(compositor: Compositor, chord: &Chord, target: &str, title: &str) -> Option<String> {
    let name = |modifier| match modifier {
        Modifier::Ctrl => "CTRL",
        Modifier::Alt => "ALT",
        Modifier::Shift => "SHIFT",
        Modifier::Logo => "SUPER",
    };
    match compositor {
        Compositor::Omarchy => {
            let keys = chord.joined(" + ", name).to_ascii_uppercase();
            Some(format!(
                "o.bind(\"{keys}\", \"{title}\", hl.dsp.global(\"{target}\"))"
            ))
        }
        Compositor::Hyprland => {
            let modifiers = chord
                .modifiers()
                .into_iter()
                .map(name)
                .collect::<Vec<_>>()
                .join(" ");
            let key = chord.key.to_ascii_uppercase();
            Some(format!("bind = {modifiers}, {key}, global, {target}"))
        }
        Compositor::Sway | Compositor::Other => None,
    }
}

fn line(compositor: Compositor, chord: &Chord, command: &str, title: &str) -> Option<String> {
    match compositor {
        Compositor::Sway => {
            let keys = chord.joined("+", |modifier| match modifier {
                Modifier::Ctrl => "Ctrl",
                Modifier::Alt => "Alt",
                Modifier::Shift => "Shift",
                Modifier::Logo => "Mod4",
            });
            Some(format!("bindsym {keys} exec {command}"))
        }
        Compositor::Hyprland => {
            let modifiers = chord
                .modifiers()
                .into_iter()
                .map(|modifier| match modifier {
                    Modifier::Ctrl => "CTRL",
                    Modifier::Alt => "ALT",
                    Modifier::Shift => "SHIFT",
                    Modifier::Logo => "SUPER",
                })
                .collect::<Vec<_>>()
                .join(" ");
            Some(format!(
                "bind = {modifiers}, {}, exec, {command}",
                chord.key
            ))
        }
        Compositor::Omarchy => {
            let keys = chord
                .joined(" + ", |modifier| match modifier {
                    Modifier::Ctrl => "CTRL",
                    Modifier::Alt => "ALT",
                    Modifier::Shift => "SHIFT",
                    Modifier::Logo => "SUPER",
                })
                .to_ascii_uppercase();
            Some(format!("o.bind(\"{keys}\", \"{title}\", \"{command}\")"))
        }
        Compositor::Other => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_portal_trigger_names_modifiers_in_capitals_and_the_key_as_a_keysym() {
        let cases = [
            ("Ctrl+Shift+Space", "CTRL+SHIFT+space"),
            ("Cmd+Alt+KeyK", "ALT+LOGO+k"),
            ("Super+Digit1", "LOGO+1"),
            ("alt+control+F5", "CTRL+ALT+F5"),
            ("Ctrl+Enter", "CTRL+Return"),
            ("Ctrl+Quote", "CTRL+apostrophe"),
            ("Ctrl+,", "CTRL+comma"),
            ("CmdOrCtrl+Up", "CTRL+Up"),
        ];
        for (accelerator, trigger) in cases {
            assert_eq!(
                portal_trigger(accelerator).as_deref(),
                Some(trigger),
                "{accelerator}"
            );
        }
    }

    #[test]
    fn text_without_a_usable_key_has_no_trigger() {
        for accelerator in [
            "",
            "Ctrl+",
            "Ctrl+Shift",
            "Ctrl+Hyper",
            "Ctrl+A+B",
            "Ctrl++",
        ] {
            assert_eq!(portal_trigger(accelerator), None, "{accelerator:?}");
        }
    }

    #[test]
    fn the_compositor_comes_from_the_desktop_list_and_the_distribution() {
        assert_eq!(Compositor::detect("sway", false), Compositor::Sway);
        assert_eq!(Compositor::detect("Hyprland", false), Compositor::Hyprland);
        assert_eq!(Compositor::detect("Hyprland", true), Compositor::Omarchy);
        assert_eq!(Compositor::detect("ubuntu:GNOME", false), Compositor::Other);
        assert_eq!(Compositor::detect("", true), Compositor::Other);
    }

    #[test]
    fn sway_lines_use_bindsym_and_mod4_for_super() {
        assert_eq!(
            compositor_lines(
                Compositor::Sway,
                "vaultkeeper",
                "Ctrl+Shift+Space",
                "Super+Alt+G"
            )
            .as_deref(),
            Some(
                "bindsym Ctrl+Shift+space exec vaultkeeper --search\n\
                 bindsym Alt+Mod4+g exec vaultkeeper --generator"
            )
        );
    }

    #[test]
    fn sway_lines_run_the_launcher_it_is_given() {
        assert_eq!(
            compositor_lines(
                Compositor::Sway,
                "/opt/vk/vaultkeeper",
                "Ctrl+Shift+Enter",
                ""
            )
            .as_deref(),
            Some("bindsym Ctrl+Shift+Return exec /opt/vk/vaultkeeper --search")
        );
    }

    #[test]
    fn hyprland_lines_use_exec_binds() {
        assert_eq!(
            compositor_lines(Compositor::Hyprland, "vaultkeeper", "Ctrl+Shift+Space", "")
                .as_deref(),
            Some("bind = CTRL SHIFT, space, exec, vaultkeeper --search")
        );
    }

    #[test]
    fn omarchy_lines_are_the_lua_binding_call() {
        assert_eq!(
            compositor_lines(
                Compositor::Omarchy,
                "vaultkeeper",
                "Ctrl+Shift+Space",
                "Ctrl+Alt+G"
            )
            .as_deref(),
            Some(
                "o.bind(\"CTRL + SHIFT + SPACE\", \"Vaultkeeper\", \"vaultkeeper --search\")\n\
                 o.bind(\"CTRL + ALT + G\", \"Vaultkeeper generator\", \"vaultkeeper --generator\")"
            )
        );
    }

    const APP: &str = "io.github.avbel.Vaultkeeper";

    #[test]
    fn omarchy_global_lines_are_the_verified_lua_bind() {
        assert_eq!(
            global_lines(Compositor::Omarchy, APP, "Ctrl+Shift+Space", "").as_deref(),
            Some(
                "o.bind(\"CTRL + SHIFT + SPACE\", \"Vaultkeeper\", \
                 hl.dsp.global(\"io.github.avbel.Vaultkeeper:quick-panel\"))"
            )
        );
    }

    #[test]
    fn classic_hyprland_global_lines_use_the_bind_global_form() {
        assert_eq!(
            global_lines(Compositor::Hyprland, APP, "Ctrl+Shift+Space", "Super+Alt+G").as_deref(),
            Some(
                "bind = CTRL SHIFT, SPACE, global, io.github.avbel.Vaultkeeper:quick-panel\n\
                 bind = ALT SUPER, G, global, io.github.avbel.Vaultkeeper:generator"
            )
        );
    }

    #[test]
    fn other_desktops_have_no_global_lines() {
        assert_eq!(global_lines(Compositor::Sway, APP, "Ctrl+Space", ""), None);
        assert_eq!(global_lines(Compositor::Other, APP, "Ctrl+Space", ""), None);
        assert_eq!(global_lines(Compositor::Hyprland, APP, "", ""), None);
    }

    #[test]
    fn an_unknown_desktop_or_no_shortcut_has_no_lines() {
        assert_eq!(
            compositor_lines(Compositor::Other, "vaultkeeper", "Ctrl+Shift+Space", ""),
            None
        );
        assert_eq!(
            compositor_lines(Compositor::Sway, "vaultkeeper", "", ""),
            None
        );
    }
}
