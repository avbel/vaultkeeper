//! The tray icon on Windows: which glyph reads on the taskbar, a watcher for the theme that
//! decides it, and the glyph rasterised at the pixel size the notification area really uses
//! (docs/solutions/windows-support.md §7.1).

use slint::{Image, Rgba8Pixel, SharedPixelBuffer};

use crate::settings::TrayIconChoice;

/// The tray SVGs declare this size; it is swapped for the target pixel size before rasterising,
/// because Slint renders an SVG only at its intrinsic size and Windows would otherwise scale the
/// 36 px bitmap down to 16 to 32 px, which blurs the keyhole.
const INTRINSIC_SIZE: &str = r#"width="36" height="36""#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glyph {
    Blue,
    White,
    Black,
    Neutral,
}

impl Glyph {
    /// `taskbar_dark` only matters for `Auto`; unknown falls back to the grey glyph that reads on
    /// both bars.
    #[must_use]
    pub const fn choose(choice: TrayIconChoice, taskbar_dark: Option<bool>) -> Self {
        match (choice, taskbar_dark) {
            (TrayIconChoice::Blue, _) => Self::Blue,
            (TrayIconChoice::White, _) | (TrayIconChoice::Auto, Some(true)) => Self::White,
            (TrayIconChoice::Black, _) | (TrayIconChoice::Auto, Some(false)) => Self::Black,
            (TrayIconChoice::Auto, None) => Self::Neutral,
        }
    }

    const fn svg(self) -> &'static str {
        match self {
            Self::Blue => include_str!("../../ui/icons/tray-blue.svg"),
            Self::White => include_str!("../../ui/icons/tray-light.svg"),
            Self::Black => include_str!("../../ui/icons/tray-dark.svg"),
            Self::Neutral => include_str!("../../ui/icons/tray-neutral.svg"),
        }
    }
}

/// The glyph as a square bitmap of `px` pixels, ready for `SystemTrayIcon::icon`.
#[must_use]
pub fn rasterise(glyph: Glyph, px: u32) -> Option<Image> {
    rasterise_rgba(glyph, px).map(Image::from_rgba8)
}

/// The glyph's pixels, for hosts that take raw bitmaps (the Linux StatusNotifierItem pixmap).
#[must_use]
pub fn rasterise_rgba(glyph: Glyph, px: u32) -> Option<SharedPixelBuffer<Rgba8Pixel>> {
    let svg = glyph
        .svg()
        .replacen(INTRINSIC_SIZE, &format!(r#"width="{px}" height="{px}""#), 1);
    Image::load_from_svg_data(svg.as_bytes()).ok()?.to_rgba8()
}

/// Whether a `COLORREF` (0x00BBGGRR) is closer to black than to white.
#[cfg(any(windows, test))]
const fn is_dark_colorref(color: u32) -> bool {
    let (red, green, blue) = (color & 0xFF, (color >> 8) & 0xFF, (color >> 16) & 0xFF);
    // Rec. 601 weights, scaled by 1000.
    red * 299 + green * 587 + blue * 114 < 128_000
}

#[cfg(windows)]
pub use windows::{
    ThemeWatch, double_click_time, icon_pixel_size, taskbar_dark, watch_taskbar_theme,
};

/// The longest gap between two clicks that still counts as a double-click; Windows' default.
#[cfg(not(windows))]
#[must_use]
pub const fn double_click_time() -> std::time::Duration {
    std::time::Duration::from_millis(500)
}

/// Stands in for the registry watcher, which only exists on Windows.
#[cfg(not(windows))]
pub struct ThemeWatch;

/// Whether the taskbar is drawn dark; `None` when it cannot be told.
#[cfg(not(windows))]
#[must_use]
pub const fn taskbar_dark() -> Option<bool> {
    None
}

/// The notification area's small-icon size for the primary monitor's DPI.
#[cfg(not(windows))]
#[must_use]
pub const fn icon_pixel_size() -> Option<u32> {
    None
}

/// Calls `on_change` from a helper thread whenever the taskbar theme may have changed.
#[cfg(not(windows))]
#[must_use]
pub fn watch_taskbar_theme(on_change: impl Fn() + Send + 'static) -> Option<ThemeWatch> {
    let _ = on_change;
    None
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::c_void,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
        thread::{self, JoinHandle},
    };

    use windows_sys::{
        Win32::{
            Foundation::{ERROR_SUCCESS, HANDLE, WAIT_OBJECT_0},
            Graphics::Gdi::{
                COLOR_WINDOW, GetSysColor, MONITOR_DEFAULTTOPRIMARY, MonitorFromPoint,
            },
            System::{
                Registry::{
                    HKEY, HKEY_CURRENT_USER, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET,
                    RRF_RT_REG_DWORD, RegCloseKey, RegGetValueW, RegNotifyChangeKeyValue,
                    RegOpenKeyExW,
                },
                Threading::{CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects},
            },
            UI::{
                HiDpi::{GetDpiForMonitor, GetSystemMetricsForDpi, MDT_EFFECTIVE_DPI},
                Input::KeyboardAndMouse::GetDoubleClickTime,
                WindowsAndMessaging::{SM_CXSMICON, SPI_GETHIGHCONTRAST, SystemParametersInfoW},
            },
        },
        core::{PCWSTR, w},
    };

    use super::is_dark_colorref;

    /// `HIGHCONTRASTW` lives in the `Win32_UI_Accessibility` feature, which nothing else needs.
    #[repr(C)]
    struct HighContrast {
        size: u32,
        flags: u32,
        default_scheme: *mut u16,
    }

    const HCF_HIGHCONTRASTON: u32 = 1;

    const PERSONALIZE: PCWSTR = w!(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
    // Switching a contrast theme rewrites this key; the registry has no other signal short of a
    // window receiving `WM_SETTINGCHANGE`, and the tray process stays windowless.
    const HIGH_CONTRAST: PCWSTR = w!(r"Control Panel\Accessibility\HighContrast");

    /// `SystemUsesLightTheme` is the taskbar's theme; `AppsUseLightTheme` is the apps' and can
    /// differ. A contrast theme overrides both and is read from the system colours.
    #[must_use]
    pub fn taskbar_dark() -> Option<bool> {
        if let Some(dark) = high_contrast_dark() {
            return Some(dark);
        }
        let mut data = 0_u32;
        let mut size = 4_u32;
        // SAFETY: the key and value names are static NUL-terminated strings, and `data` and
        // `size` are live locals sized for a REG_DWORD.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PERSONALIZE,
                w!("SystemUsesLightTheme"),
                RRF_RT_REG_DWORD,
                ptr::null_mut(),
                (&raw mut data).cast::<c_void>(),
                &raw mut size,
            )
        };
        (status == ERROR_SUCCESS).then_some(data == 0)
    }

    fn high_contrast_dark() -> Option<bool> {
        let mut contrast = HighContrast {
            size: u32::try_from(size_of::<HighContrast>()).ok()?,
            flags: 0,
            default_scheme: ptr::null_mut(),
        };
        // SAFETY: `contrast` is a live `#[repr(C)]` mirror of `HIGHCONTRASTW` whose size field is
        // set, as the call requires.
        let ok = unsafe {
            SystemParametersInfoW(
                SPI_GETHIGHCONTRAST,
                contrast.size,
                (&raw mut contrast).cast::<c_void>(),
                0,
            )
        };
        if ok == 0 || contrast.flags & HCF_HIGHCONTRASTON == 0 {
            return None;
        }
        // SAFETY: takes an index constant and has no memory effects.
        Some(is_dark_colorref(unsafe { GetSysColor(COLOR_WINDOW) }))
    }

    /// The user's setting from the Mouse control panel.
    #[must_use]
    pub fn double_click_time() -> std::time::Duration {
        // SAFETY: no arguments; reads a per-user system setting.
        std::time::Duration::from_millis(u64::from(unsafe { GetDoubleClickTime() }))
    }

    /// Slint does not tell which DPI the notification area uses, so this is the primary monitor's,
    /// where the taskbar lives by default; the icon is re-rasterised on every refresh, which
    /// follows a DPI change at the next settings or vault event.
    #[must_use]
    pub fn icon_pixel_size() -> Option<u32> {
        let origin = windows_sys::Win32::Foundation::POINT { x: 0, y: 0 };
        // SAFETY: by value arguments; `MONITOR_DEFAULTTOPRIMARY` always yields a monitor.
        let monitor = unsafe { MonitorFromPoint(origin, MONITOR_DEFAULTTOPRIMARY) };
        let (mut dpi_x, mut dpi_y) = (0_u32, 0_u32);
        // SAFETY: both out pointers address live locals.
        if unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &raw mut dpi_x, &raw mut dpi_y) }
            < 0
        {
            return None;
        }
        // SAFETY: takes an index and a DPI by value.
        let px = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, dpi_x) };
        u32::try_from(px).ok().filter(|px| *px > 0)
    }

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from `RegOpenKeyExW` and nothing else owns it.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }

    fn open_key(subkey: PCWSTR) -> Option<Key> {
        let mut key: HKEY = ptr::null_mut();
        // SAFETY: `subkey` is a static NUL-terminated string and `key` a live out pointer.
        let status =
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, KEY_NOTIFY, &raw mut key) };
        (status == ERROR_SUCCESS).then_some(Key(key))
    }

    fn create_event() -> Option<OwnedHandle> {
        // SAFETY: no security attributes or name; the auto-reset, unsignalled event is owned by
        // the returned handle.
        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        // SAFETY: `CreateEventW` returned a handle this function owns when it is non-null.
        (!event.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(event) })
    }

    fn arm(key: &Key, event: &OwnedHandle) -> bool {
        // SAFETY: the key and the event are alive for the call; the registration is one-shot and
        // outlives it only until the event is signalled or the key is closed.
        let status = unsafe {
            RegNotifyChangeKeyValue(
                key.0,
                0,
                REG_NOTIFY_CHANGE_LAST_SET,
                event.as_raw_handle(),
                1,
            )
        };
        status == ERROR_SUCCESS
    }

    /// Stops and joins its thread on drop.
    pub struct ThemeWatch {
        stop: OwnedHandle,
        thread: Option<JoinHandle<()>>,
    }

    impl Drop for ThemeWatch {
        fn drop(&mut self) {
            // SAFETY: the handle is a live event owned by `self`.
            unsafe { SetEvent(self.stop.as_raw_handle()) };
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// Calls `on_change` from a helper thread whenever the taskbar theme or a contrast theme may
    /// have changed, until the handle is dropped. The thread exists because
    /// `RegNotifyChangeKeyValue` is the only window-less signal for these keys.
    #[must_use]
    pub fn watch_taskbar_theme(on_change: impl Fn() + Send + 'static) -> Option<ThemeWatch> {
        let stop = create_event()?;
        let thread_stop = stop.try_clone().ok()?;
        let thread = thread::Builder::new()
            .name("taskbar-theme".to_owned())
            .spawn(move || run(&thread_stop, &on_change))
            .ok()?;
        Some(ThemeWatch {
            stop,
            thread: Some(thread),
        })
    }

    fn run(stop: &OwnedHandle, on_change: &impl Fn()) {
        let watched: Vec<(Key, OwnedHandle)> = [PERSONALIZE, HIGH_CONTRAST]
            .into_iter()
            .filter_map(|subkey| Some((open_key(subkey)?, create_event()?)))
            .filter(|(key, event)| arm(key, event))
            .collect();
        if watched.is_empty() {
            tracing::warn!("cannot watch the taskbar theme");
            return;
        }
        let handles: Vec<HANDLE> = std::iter::once(stop)
            .chain(watched.iter().map(|(_, event)| event))
            .map(AsRawHandle::as_raw_handle)
            .collect();
        let Ok(count) = u32::try_from(handles.len()) else {
            return;
        };
        loop {
            // SAFETY: `handles` holds `count` live event handles owned by this function and the
            // caller's `stop`, which outlive the call.
            let signalled = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, INFINITE) };
            let Some(index) = signalled.checked_sub(WAIT_OBJECT_0).filter(|i| *i < count) else {
                tracing::warn!("taskbar theme watcher stopped on a wait failure");
                return;
            };
            let Some(slot) = index.checked_sub(1) else {
                return;
            };
            let Some((key, event)) = watched.get(slot as usize) else {
                return;
            };
            // Re-arm first: a change that lands while `on_change` runs would otherwise be lost.
            if !arm(key, event) {
                tracing::warn!("cannot re-arm the taskbar theme watcher; it stops here");
                on_change();
                return;
            }
            on_change();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_follows_the_taskbar_and_the_rest_ignore_it() {
        let auto = |dark| Glyph::choose(TrayIconChoice::Auto, dark);
        assert_eq!(auto(Some(true)), Glyph::White);
        assert_eq!(auto(Some(false)), Glyph::Black);
        assert_eq!(auto(None), Glyph::Neutral);
        for dark in [Some(true), Some(false), None] {
            assert_eq!(Glyph::choose(TrayIconChoice::Blue, dark), Glyph::Blue);
            assert_eq!(Glyph::choose(TrayIconChoice::White, dark), Glyph::White);
            assert_eq!(Glyph::choose(TrayIconChoice::Black, dark), Glyph::Black);
        }
    }

    #[test]
    fn every_glyph_is_rasterised_at_the_requested_size() {
        for glyph in [Glyph::Blue, Glyph::White, Glyph::Black, Glyph::Neutral] {
            for px in [16, 20, 24, 32] {
                let image = rasterise(glyph, px).expect("rasterised");
                assert_eq!((image.size().width, image.size().height), (px, px));
                let pixels = image.to_rgba8().expect("pixels");
                assert!(
                    pixels.as_slice().iter().any(|pixel| pixel.a > 0),
                    "{glyph:?} at {px} is blank"
                );
            }
        }
    }

    #[test]
    fn colorref_darkness_uses_luminance() {
        assert!(is_dark_colorref(0x0000_0000));
        assert!(!is_dark_colorref(0x00FF_FFFF));
        assert!(is_dark_colorref(0x00FF_0000), "pure blue is dark");
        assert!(!is_dark_colorref(0x0000_FF00), "pure green is light");
    }
}
