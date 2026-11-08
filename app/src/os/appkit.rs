//! AppKit glue for the UI process: the activation policy (a Dock icon only while the Manager is
//! open), bringing the app forward, and the Quick Panel's place on the cursor's screen.

use crate::hooks::{DockIcon, WindowPlacement};

/// The Quick Panel's top edge sits this far down the screen (ui-refinements.md).
const QUICK_PANEL_TOP: f32 = 0.22;

/// A screen rectangle in AppKit's global coordinates: points, origin at the bottom left of the
/// primary screen, y growing upwards.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScreenRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl ScreenRect {
    fn contains(&self, x: f64, y: f64) -> bool {
        x >= self.x && x < self.x + self.width && y >= self.y && y < self.y + self.height
    }
}

/// Top-left origin of a `width` × `height` panel centred on `screen`, its top at 22% of the
/// screen height, in the top-left-origin logical coordinates winit uses (flipped against the
/// primary screen's height).
#[must_use]
pub fn quick_panel_origin_in(
    screen: ScreenRect,
    primary_height: f64,
    width: f32,
    height: f32,
) -> slint::LogicalPosition {
    let screen_top = primary_height - (screen.y + screen.height);
    let x = screen.x + (screen.width - f64::from(width)) / 2.0;
    let mut top = screen_top + screen.height * f64::from(QUICK_PANEL_TOP);
    let bottom_limit = screen_top + screen.height - f64::from(height);
    if top > bottom_limit {
        top = bottom_limit.max(screen_top);
    }
    #[allow(clippy::cast_possible_truncation)]
    slint::LogicalPosition::new(x as f32, top as f32)
}

/// The screen under `(x, y)`, else the first one (the primary).
#[must_use]
pub fn screen_at(screens: &[ScreenRect], x: f64, y: f64) -> Option<ScreenRect> {
    screens
        .iter()
        .copied()
        .find(|screen| screen.contains(x, y))
        .or_else(|| screens.first().copied())
}

/// Whether the system appearance is dark; `None` off the main thread or when AppKit cannot tell.
#[must_use]
pub fn system_dark() -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        macos::system_dark()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

pub struct AppKitDock;

impl DockIcon for AppKitDock {
    fn set_visible(&self, visible: bool) {
        #[cfg(target_os = "macos")]
        macos::set_regular(visible);
        #[cfg(not(target_os = "macos"))]
        let _ = visible;
    }

    fn activate(&self) {
        #[cfg(target_os = "macos")]
        macos::activate();
    }
}

pub struct CursorScreen;

impl WindowPlacement for CursorScreen {
    fn quick_panel_origin(&self, width: f32, height: f32) -> Option<slint::LogicalPosition> {
        #[cfg(target_os = "macos")]
        {
            let (screens, (x, y)) = macos::screens_and_mouse()?;
            let primary_height = screens.first()?.height;
            let screen = screen_at(&screens, x, y)?;
            Some(quick_panel_origin_in(screen, primary_height, width, height))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (width, height);
            None
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{
        NSAppearanceNameAqua, NSAppearanceNameDarkAqua, NSApplication,
        NSApplicationActivationPolicy, NSEvent, NSScreen,
    };
    use objc2_foundation::NSArray;

    use super::ScreenRect;

    /// Every caller is a Slint callback, which runs on the main thread; elsewhere this is a no-op.
    fn main_thread() -> Option<MainThreadMarker> {
        let marker = MainThreadMarker::new();
        if marker.is_none() {
            tracing::warn!("AppKit call off the main thread ignored");
        }
        marker
    }

    pub(super) fn set_regular(regular: bool) {
        let Some(mtm) = main_thread() else {
            return;
        };
        let app = NSApplication::sharedApplication(mtm);
        let policy = if regular {
            NSApplicationActivationPolicy::Regular
        } else {
            NSApplicationActivationPolicy::Accessory
        };
        if !app.setActivationPolicy(policy) {
            tracing::debug!(regular, "activation policy unchanged");
        }
        if regular {
            activate_app(&app);
        }
    }

    pub(super) fn activate() {
        if let Some(mtm) = main_thread() {
            activate_app(&NSApplication::sharedApplication(mtm));
        }
    }

    // Cooperative `activate()` (macOS 14+) is ignored when another app is frontmost, which is
    // always the case when the daemon's hotkey or tray asks this process for a window.
    #[allow(deprecated)]
    fn activate_app(app: &NSApplication) {
        app.activateIgnoringOtherApps(true);
    }

    pub(super) fn system_dark() -> Option<bool> {
        let mtm = MainThreadMarker::new()?;
        let appearance = NSApplication::sharedApplication(mtm).effectiveAppearance();
        // SAFETY: the appearance names are immutable framework constants.
        let (aqua, dark) = unsafe { (NSAppearanceNameAqua, NSAppearanceNameDarkAqua) };
        let best =
            appearance.bestMatchFromAppearancesWithNames(&NSArray::from_slice(&[aqua, dark]))?;
        Some(&*best == dark)
    }

    pub(super) fn screens_and_mouse() -> Option<(Vec<ScreenRect>, (f64, f64))> {
        let mtm = main_thread()?;
        let screens: Vec<ScreenRect> = NSScreen::screens(mtm)
            .iter()
            .map(|screen| {
                let frame = screen.frame();
                ScreenRect {
                    x: frame.origin.x,
                    y: frame.origin.y,
                    width: frame.size.width,
                    height: frame.size.height,
                }
            })
            .collect();
        let mouse = NSEvent::mouseLocation();
        Some((screens, (mouse.x, mouse.y)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY: ScreenRect = ScreenRect {
        x: 0.0,
        y: 0.0,
        width: 1512.0,
        height: 982.0,
    };
    /// A 1920×1080 display placed to the right of the primary, bottoms aligned.
    const RIGHT: ScreenRect = ScreenRect {
        x: 1512.0,
        y: 0.0,
        width: 1920.0,
        height: 1080.0,
    };

    #[test]
    fn panel_is_centred_with_its_top_at_22_percent_of_the_primary() {
        let origin = quick_panel_origin_in(PRIMARY, 982.0, 560.0, 340.0);
        assert!((origin.x - 476.0).abs() < 0.01, "{origin:?}");
        assert!((origin.y - 216.04).abs() < 0.01, "{origin:?}");
    }

    #[test]
    fn a_taller_secondary_screen_is_flipped_against_the_primary_height() {
        // Its top is 98 pt above the primary's top, i.e. y = -98 in top-left coordinates.
        let origin = quick_panel_origin_in(RIGHT, 982.0, 560.0, 340.0);
        assert!((origin.x - 2192.0).abs() < 0.01, "{origin:?}");
        assert!((origin.y - (-98.0 + 237.6)).abs() < 0.01, "{origin:?}");
    }

    #[test]
    fn a_short_screen_keeps_the_panel_on_it() {
        let short = ScreenRect {
            height: 400.0,
            ..PRIMARY
        };
        let origin = quick_panel_origin_in(short, 400.0, 560.0, 340.0);
        assert!((origin.y - 60.0).abs() < 0.01, "bottom-aligned: {origin:?}");
    }

    #[test]
    fn the_cursor_picks_its_screen_and_falls_back_to_the_primary() {
        let screens = [PRIMARY, RIGHT];
        assert_eq!(screen_at(&screens, 2000.0, 500.0), Some(RIGHT));
        assert_eq!(screen_at(&screens, 10.0, 10.0), Some(PRIMARY));
        assert_eq!(screen_at(&screens, -50.0, 10.0), Some(PRIMARY));
        assert_eq!(screen_at(&[], 0.0, 0.0), None);
    }
}
