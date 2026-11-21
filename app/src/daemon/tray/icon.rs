//! Which glyph the Linux tray shows and how it reaches the host: by icon name when the hicolor
//! icon is installed, as an ARGB pixmap otherwise.

use std::path::{Path, PathBuf};

use vk_platform::desktop_file::APP_ID;

use crate::settings::TrayIconChoice;

/// Hosts pick the closest size; panels draw 16 to 24 px, scaled displays need more.
#[cfg(target_os = "linux")]
pub const PIXMAP_SIZES: [u32; 3] = [22, 32, 48];

const SYSTEM_DATA_DIRS: [&str; 2] = ["/usr/local/share", "/usr/share"];

/// Where the installed icon would be, user directory first.
#[must_use]
pub fn icon_paths(data_home: Option<&Path>) -> Vec<PathBuf> {
    let relative = format!("icons/hicolor/scalable/apps/{APP_ID}.svg");
    data_home
        .into_iter()
        .chain(SYSTEM_DATA_DIRS.iter().map(Path::new))
        .map(|dir| dir.join(&relative))
        .collect()
}

/// The brand icon is a coloured hicolor icon, so only the blue choice may use the icon name; a
/// monochrome choice has to travel as a pixmap or the host would draw the coloured one.
#[must_use]
pub fn icon_name(choice: TrayIconChoice, installed: bool) -> String {
    if choice == TrayIconChoice::Blue && installed {
        APP_ID.to_owned()
    } else {
        String::new()
    }
}

/// RGBA to the StatusNotifierItem's ARGB32 in network byte order.
#[must_use]
pub fn argb32(rgba: &[u8]) -> Vec<u8> {
    rgba.as_chunks::<4>()
        .0
        .iter()
        .flat_map(|&[red, green, blue, alpha]| [alpha, red, green, blue])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::taskbar::Glyph;

    #[test]
    fn tray_auto_glyph_follows_the_system_scheme() {
        assert_eq!(
            Glyph::choose(TrayIconChoice::Auto, Some(true)),
            Glyph::White
        );
        assert_eq!(
            Glyph::choose(TrayIconChoice::Auto, Some(false)),
            Glyph::Black
        );
        assert_eq!(Glyph::choose(TrayIconChoice::Auto, None), Glyph::Neutral);
    }

    #[test]
    fn tray_explicit_choices_ignore_the_system_scheme() {
        assert_eq!(Glyph::choose(TrayIconChoice::Blue, Some(true)), Glyph::Blue);
        assert_eq!(
            Glyph::choose(TrayIconChoice::White, Some(false)),
            Glyph::White
        );
        assert_eq!(
            Glyph::choose(TrayIconChoice::Black, Some(true)),
            Glyph::Black
        );
    }

    #[test]
    fn tray_icon_name_is_the_app_id_only_for_an_installed_blue_icon() {
        assert_eq!(icon_name(TrayIconChoice::Blue, true), APP_ID);
        assert_eq!(icon_name(TrayIconChoice::Blue, false), "");
        assert_eq!(icon_name(TrayIconChoice::Auto, true), "");
    }

    #[test]
    fn tray_icon_is_looked_up_in_the_user_then_the_system_directories() {
        let paths = icon_paths(Some(Path::new("/home/me/.local/share")));
        assert_eq!(
            paths[0],
            Path::new(
                "/home/me/.local/share/icons/hicolor/scalable/apps/io.github.avbel.Vaultkeeper.svg"
            )
        );
        assert_eq!(paths.len(), 3);
        assert_eq!(icon_paths(None).len(), 2);
    }

    #[test]
    fn tray_pixmap_is_argb_in_network_order() {
        assert_eq!(argb32(&[1, 2, 3, 4, 5, 6, 7, 8]), [4, 1, 2, 3, 8, 5, 6, 7]);
    }
}
