//! Windows shell glue for the UI process: the Quick Panel's place on the cursor's screen and a
//! no-op Dock (the taskbar button follows the Manager window on its own).

#[cfg(windows)]
use crate::hooks::{DockIcon, WindowPlacement};

/// The Quick Panel's top edge sits this far down the screen (ui-refinements.md).
const QUICK_PANEL_TOP: f32 = 0.22;

/// Top-left origin of a `width` × `height` panel centred on a work area given in top-left-origin
/// logical coordinates, its top at 22% of the work area height. Windows work areas are already
/// top-left (unlike AppKit's bottom-left origin), so the arithmetic here is its own function.
#[must_use]
pub fn quick_panel_origin_in_work_area(
    left: f64,
    top: f64,
    work_width: f64,
    work_height: f64,
    width: f32,
    height: f32,
) -> slint::LogicalPosition {
    let x = left + (work_width - f64::from(width)) / 2.0;
    let mut y = top + work_height * f64::from(QUICK_PANEL_TOP);
    let bottom_limit = top + work_height - f64::from(height);
    if y > bottom_limit {
        y = bottom_limit.max(top);
    }
    #[allow(clippy::cast_possible_truncation)]
    slint::LogicalPosition::new(x as f32, y as f32)
}

/// Top-left origin of a `width` × `height` window centred on a work area given in top-left-origin
/// logical coordinates, kept inside it when the window is larger.
#[must_use]
pub fn centred_in_work_area(
    left: f64,
    top: f64,
    work_width: f64,
    work_height: f64,
    width: f32,
    height: f32,
) -> slint::LogicalPosition {
    let x = left + ((work_width - f64::from(width)) / 2.0).max(0.0);
    let y = top + ((work_height - f64::from(height)) / 2.0).max(0.0);
    #[allow(clippy::cast_possible_truncation)]
    slint::LogicalPosition::new(x as f32, y as f32)
}

/// The taskbar button follows the Manager window on Windows, so the Dock hook has nothing to do.
#[cfg(windows)]
pub struct WindowsDock;

#[cfg(windows)]
impl DockIcon for WindowsDock {
    fn set_visible(&self, _visible: bool) {}
}

#[cfg(windows)]
pub struct WindowsPlacement;

#[cfg(windows)]
impl WindowPlacement for WindowsPlacement {
    fn quick_panel_origin(&self, width: f32, height: f32) -> Option<slint::LogicalPosition> {
        let (left, top, work_width, work_height) = cursor_work_area()?;
        Some(quick_panel_origin_in_work_area(
            left,
            top,
            work_width,
            work_height,
            width,
            height,
        ))
    }

    fn centred_origin(&self, width: f32, height: f32) -> Option<slint::LogicalPosition> {
        let (left, top, work_width, work_height) = cursor_work_area()?;
        Some(centred_in_work_area(
            left,
            top,
            work_width,
            work_height,
            width,
            height,
        ))
    }
}

/// The work area (left, top, width, height) in logical units of the monitor under the cursor.
#[cfg(windows)]
fn cursor_work_area() -> Option<(f64, f64, f64, f64)> {
    use windows_sys::Win32::{
        Foundation::{POINT, RECT},
        Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromPoint},
        UI::{HiDpi::GetDpiForMonitor, WindowsAndMessaging::GetCursorPos},
    };

    let mut cursor = POINT { x: 0, y: 0 };
    // SAFETY: `cursor` is a local out pointer the call fills.
    if unsafe { GetCursorPos(&raw mut cursor) } == 0 {
        return None;
    }
    // SAFETY: `cursor` was just filled; `MONITOR_DEFAULTTONEAREST` always yields a monitor.
    let monitor = unsafe { MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST) };
    if monitor.is_null() {
        return None;
    }
    let mut info = MONITORINFO {
        cbSize: u32::try_from(std::mem::size_of::<MONITORINFO>()).expect("MONITORINFO is 40 bytes"),
        rcMonitor: RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        rcWork: RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        dwFlags: 0,
    };
    // SAFETY: `monitor` is valid and `info` is a live struct with the size it needs.
    if unsafe { GetMonitorInfoW(monitor, &raw mut info) } == 0 {
        return None;
    }
    let mut dpi = 0_u32;
    let mut dpi_y = 0_u32;
    // SAFETY: `monitor` is valid; both DPI pointers are live locals.
    if unsafe {
        GetDpiForMonitor(
            monitor,
            windows_sys::Win32::UI::HiDpi::MDT_EFFECTIVE_DPI,
            &raw mut dpi,
            &raw mut dpi_y,
        )
    } < 0
    {
        return None;
    }
    let scale = f64::from(dpi) / 96.0;
    let left = f64::from(info.rcWork.left) / scale;
    let top = f64::from(info.rcWork.top) / scale;
    let work_width = f64::from(info.rcWork.right - info.rcWork.left) / scale;
    let work_height = f64::from(info.rcWork.bottom - info.rcWork.top) / scale;
    Some((left, top, work_width, work_height))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_is_centred_with_its_top_at_22_percent_of_the_work_area() {
        let origin = quick_panel_origin_in_work_area(0.0, 0.0, 1512.0, 982.0, 560.0, 340.0);
        assert!((origin.x - 476.0).abs() < 0.01, "{origin:?}");
        assert!((origin.y - 216.04).abs() < 0.01, "{origin:?}");
    }

    #[test]
    fn a_work_area_away_from_the_primary_origin_offsets_the_panel() {
        let origin = quick_panel_origin_in_work_area(1512.0, 100.0, 1920.0, 1080.0, 560.0, 340.0);
        assert!((origin.x - 2192.0).abs() < 0.01, "{origin:?}");
        assert!((origin.y - (100.0 + 237.6)).abs() < 0.01, "{origin:?}");
    }

    #[test]
    fn a_window_is_centred_on_an_offset_work_area() {
        let origin = centred_in_work_area(1512.0, 100.0, 1920.0, 1080.0, 420.0, 480.0);
        assert!((origin.x - 2262.0).abs() < 0.01, "{origin:?}");
        assert!((origin.y - 400.0).abs() < 0.01, "{origin:?}");
    }

    #[test]
    fn a_window_taller_than_the_work_area_keeps_its_top_on_it() {
        let origin = centred_in_work_area(0.0, 40.0, 1512.0, 400.0, 420.0, 600.0);
        assert!((origin.y - 40.0).abs() < 0.01, "{origin:?}");
    }

    #[test]
    fn a_short_work_area_keeps_the_panel_on_it() {
        let origin = quick_panel_origin_in_work_area(0.0, 0.0, 1512.0, 400.0, 560.0, 340.0);
        assert!((origin.y - 60.0).abs() < 0.01, "bottom-aligned: {origin:?}");
    }
}
