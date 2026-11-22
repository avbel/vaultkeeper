//! The way to get a tray icon on the desktop this session runs, for the "no tray" notice and the
//! Settings remedy. The tray host differs per desktop, so naming one the user does not run (a
//! Waybar module on Omarchy, which has none) sends them looking for the wrong thing.

use super::security_gate::Distro;

/// A phrase without a capital or full stop; callers put it after a clause or capitalise it.
/// `current_desktop` is `XDG_CURRENT_DESKTOP`, a colon-separated list.
#[must_use]
pub fn tray_way(distro: Distro, current_desktop: &str) -> &'static str {
    let has = |name: &str| {
        current_desktop
            .split(':')
            .any(|entry| entry.eq_ignore_ascii_case(name))
    };
    if distro == Distro::Omarchy {
        "restart the Omarchy shell, which hosts the tray"
    } else if has("gnome") || has("ubuntu") {
        match distro {
            Distro::Ubuntu => "enable the Ubuntu AppIndicator extension in Extensions",
            Distro::Fedora => {
                "install gnome-shell-extension-appindicator and enable it in Extensions"
            }
            _ => "install and enable the AppIndicator extension",
        }
    } else if has("kde") {
        "add the System Tray widget to the Plasma panel; the tray is built in"
    } else if has("sway") {
        "add a tray module to your bar (Waybar `tray` or swaybar `tray_output`)"
    } else if has("hyprland") {
        "add a tray module to your bar (Waybar `tray`, or your shell's own tray)"
    } else {
        "run a StatusNotifierItem host (a panel tray module, or the AppIndicator extension on GNOME)"
    }
}

/// The wlroots bars (swaybar, Waybar's default style) are dark whatever the colour scheme says,
/// so a scheme-driven black glyph is unreadable on them. Omarchy restyles its bar and is not
/// covered: the caller treats that distro on its own.
#[must_use]
pub fn bar_is_dark(current_desktop: &str) -> bool {
    current_desktop
        .split(':')
        .any(|entry| entry.eq_ignore_ascii_case("sway") || entry.eq_ignore_ascii_case("hyprland"))
}

/// The session's own desktop name; empty outside a desktop session.
#[must_use]
pub fn session_desktop() -> String {
    std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_desktop_names_its_own_tray_host() {
        assert!(tray_way(Distro::Ubuntu, "ubuntu:GNOME").contains("Ubuntu AppIndicator"));
        assert!(tray_way(Distro::Fedora, "GNOME").contains("gnome-shell-extension-appindicator"));
        assert!(tray_way(Distro::OtherArch, "GNOME").contains("AppIndicator extension"));
        assert!(tray_way(Distro::Fedora, "KDE").contains("built in"));
        assert!(tray_way(Distro::Fedora, "sway").contains("tray_output"));
        assert!(tray_way(Distro::OtherArch, "Hyprland").contains("Waybar"));
    }

    #[test]
    fn omarchy_never_sends_the_user_to_waybar_or_gnome() {
        let way = tray_way(Distro::Omarchy, "Hyprland");
        assert!(way.contains("Omarchy shell"));
        assert!(!way.contains("Waybar"));
    }

    #[test]
    fn only_the_wlroots_desktops_have_an_always_dark_bar() {
        assert!(bar_is_dark("sway"));
        assert!(bar_is_dark("Hyprland"));
        assert!(!bar_is_dark("KDE"));
        assert!(!bar_is_dark("ubuntu:GNOME"));
        assert!(!bar_is_dark(""));
    }

    #[test]
    fn an_unknown_desktop_stays_neutral() {
        let way = tray_way(Distro::Other, "");
        assert!(way.contains("StatusNotifierItem"));
        assert!(!way.contains("Sway"));
    }
}
