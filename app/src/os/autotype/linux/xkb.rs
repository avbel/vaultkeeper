//! The session's XKB keymap, and what the desktop does with a keysym sent through the RemoteDesktop
//! portal. libxkbcommon is the one winit already loaded for the window.
//!
//! Mutter (`meta-virtual-input-device-native.c`, `notify_keyval`) looks the keysym up in the
//! layout that is active only: the first key code, in ascending order, with the keysym on any
//! level. It then holds Shift for level 2 and ISO_Level3_Shift for level 3, nothing for higher
//! levels, and presses the key. A keysym the layout lacks is dropped with a warning in the
//! compositor's log; one on a level above 3 comes out as the key's first level. It never switches
//! the layout. xdg-desktop-portal-kde resolves keysyms the same way. [`Keymap::types`] replays
//! exactly that on a state of its own, so the answer is what the focused app would receive.

use std::ptr::{self, NonNull};

use xkbcommon_dl::{
    XkbCommon, xkb_context, xkb_context_flags, xkb_key_direction, xkb_keymap,
    xkb_keymap_compile_flags, xkb_keymap_format, xkb_keysym_t, xkb_state, xkbcommon_option,
};

const SHIFT_L: u32 = 0xffe1;
const ISO_LEVEL3_SHIFT: u32 = 0xfe03;
/// XKB key codes are evdev codes plus 8.
const EVDEV_OFFSET: u32 = 8;

pub(super) struct Keymap {
    lib: &'static XkbCommon,
    context: NonNull<xkb_context>,
    map: NonNull<xkb_keymap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Key {
    pub code: u32,
    /// Zero-based, as libxkbcommon counts them.
    pub level: u32,
}

struct State<'a> {
    lib: &'a XkbCommon,
    state: NonNull<xkb_state>,
}

impl Drop for State<'_> {
    fn drop(&mut self) {
        // SAFETY: `state` came from `xkb_state_new` and this is its only reference.
        unsafe { (self.lib.xkb_state_unref)(self.state.as_ptr()) };
    }
}

impl Drop for Keymap {
    fn drop(&mut self) {
        // SAFETY: both came from their `_new` functions and these are their only references; a
        // `State` borrows `self`, so none outlives the keymap.
        unsafe {
            (self.lib.xkb_keymap_unref)(self.map.as_ptr());
            (self.lib.xkb_context_unref)(self.context.as_ptr());
        }
    }
}

impl Keymap {
    /// Compiles keymap text (`wl_keyboard.keymap`, format `xkb_v1`).
    pub(super) fn parse(text: &[u8]) -> Result<Self, &'static str> {
        let lib = xkbcommon_option().ok_or("libxkbcommon is not installed")?;
        // A compiled keymap includes nothing, so the XKB data directories are not looked for.
        // The binding takes the flags as an enum, which cannot also carry
        // `XKB_CONTEXT_NO_ENVIRONMENT_NAMES`; that one only matters when compiling from layout
        // names, which never happens here.
        let flags = xkb_context_flags::XKB_CONTEXT_NO_DEFAULT_INCLUDES;
        // SAFETY: plain constructor; a null result is handled.
        let context = unsafe { (lib.xkb_context_new)(flags) };
        let context = NonNull::new(context).ok_or("libxkbcommon gave no context")?;
        // SAFETY: `context` is live and the pointer and length describe `text`, which
        // libxkbcommon only reads during the call.
        let keymap = unsafe {
            (lib.xkb_keymap_new_from_buffer)(
                context.as_ptr(),
                text.as_ptr().cast(),
                text.len(),
                xkb_keymap_format::XKB_KEYMAP_FORMAT_TEXT_V1,
                xkb_keymap_compile_flags::XKB_KEYMAP_COMPILE_NO_FLAGS,
            )
        };
        let Some(keymap) = NonNull::new(keymap) else {
            // SAFETY: `context` is live and not used again.
            unsafe { (lib.xkb_context_unref)(context.as_ptr()) };
            return Err("the session's keymap does not compile");
        };
        Ok(Self {
            lib,
            context,
            map: keymap,
        })
    }

    pub(super) fn layouts(&self) -> u32 {
        // SAFETY: `map` is live.
        unsafe { (self.lib.xkb_keymap_num_layouts)(self.map.as_ptr()) }
    }

    /// The key the desktop presses for `keysym` while `layout` is active.
    pub(super) fn key_of(&self, layout: u32, keysym: u32) -> Option<Key> {
        let keymap = self.map.as_ptr();
        // SAFETY: `map` is live.
        let (first, last) = unsafe {
            (
                (self.lib.xkb_keymap_min_keycode)(keymap),
                (self.lib.xkb_keymap_max_keycode)(keymap),
            )
        };
        // Mutter's loop stops before the last key code; so does this one.
        for code in first..last {
            // SAFETY: `map` is live; any key code and layout are valid arguments.
            let levels = unsafe { (self.lib.xkb_keymap_num_levels_for_key)(keymap, code, layout) };
            for level in 0..levels {
                if self.level_has(code, layout, level, keysym) {
                    return Some(Key { code, level });
                }
            }
        }
        None
    }

    fn level_has(&self, code: u32, layout: u32, level: u32, keysym: u32) -> bool {
        let mut syms: *const xkb_keysym_t = ptr::null();
        // SAFETY: `map` is live and `syms` is a valid place for the result.
        let count = unsafe {
            (self.lib.xkb_keymap_key_get_syms_by_level)(
                self.map.as_ptr(),
                code,
                layout,
                level,
                &raw mut syms,
            )
        };
        let Ok(count) = usize::try_from(count) else {
            return false;
        };
        if count == 0 || syms.is_null() {
            return false;
        }
        // SAFETY: libxkbcommon returned `count` keysyms at `syms`, owned by the keymap, which
        // outlives this borrow.
        unsafe { std::slice::from_raw_parts(syms, count) }.contains(&keysym)
    }

    /// Whether sending `keysym` through the portal, with `layout` active and the modifiers of
    /// `locked` locked (Caps Lock, Num Lock), makes the focused app receive `expected`; with no
    /// character expected (Tab, Return), whether it receives the keysym itself.
    pub(super) fn types(
        &self,
        layout: u32,
        locked: u32,
        keysym: u32,
        expected: Option<char>,
    ) -> bool {
        let Some(key) = self.key_of(layout, keysym) else {
            return false;
        };
        if !mutter_takes(key.code) {
            return false;
        }
        let Some(state) = self.state(layout, locked) else {
            return false;
        };
        let modifier = match key.level {
            1 => Some(SHIFT_L),
            2 => Some(ISO_LEVEL3_SHIFT),
            _ => None,
        };
        if let Some(held) = modifier.and_then(|modifier| self.key_of(layout, modifier)) {
            // SAFETY: `state` is live.
            unsafe {
                (self.lib.xkb_state_update_key)(
                    state.state.as_ptr(),
                    held.code,
                    xkb_key_direction::XKB_KEY_DOWN,
                );
            }
        }
        if let Some(ch) = expected {
            // SAFETY: `state` is live.
            let typed =
                unsafe { (self.lib.xkb_state_key_get_utf32)(state.state.as_ptr(), key.code) };
            typed == u32::from(ch)
        } else {
            // SAFETY: `state` is live.
            let typed =
                unsafe { (self.lib.xkb_state_key_get_one_sym)(state.state.as_ptr(), key.code) };
            typed == keysym
        }
    }

    fn state(&self, layout: u32, locked: u32) -> Option<State<'_>> {
        // SAFETY: `map` is live; a null result is handled.
        let state = unsafe { (self.lib.xkb_state_new)(self.map.as_ptr()) };
        let state = State {
            lib: self.lib,
            state: NonNull::new(state)?,
        };
        // SAFETY: `state` is live.
        unsafe {
            (self.lib.xkb_state_update_mask)(state.state.as_ptr(), 0, 0, locked, 0, 0, layout);
        }
        Some(state)
    }
}

/// Mutter drops a virtual key whose evdev code is outside the kernel's keyboard ranges
/// (`get_button_type`); the bounds are `KEY_ESC..=KEY_MICMUTE`, `KEY_OK..=KEY_LIGHTS_TOGGLE` and
/// `KEY_ALS_TOGGLE..=KEY_KBDINPUTASSIST_CANCEL` from `linux/input-event-codes.h`.
fn mutter_takes(code: u32) -> bool {
    code.checked_sub(EVDEV_OFFSET)
        .is_some_and(|evdev| matches!(evdev, 1..=248 | 0x160..=0x21e | 0x230..=0x265))
}

#[cfg(test)]
pub(super) mod tests {
    //! The fixtures are keymaps compiled on Fedora 45 by libxkbcommon 1.13.1 from
    //! xkeyboard-config 2.48 (rules evdev, model pc105; layouts `us`, `ru,us` and `de`), which is
    //! what GNOME hands its clients. Every expected key code and level is read off the fixture
    //! text: `<AC01> = 38;` in `xkb_keycodes`, `key <AC01> { [ 0x61, 0x41 ] };` in `xkb_symbols`.

    use super::*;

    pub const US: &[u8] = include_bytes!("fixtures/us.xkb");
    pub const RU_US: &[u8] = include_bytes!("fixtures/ru-us.xkb");
    pub const DE: &[u8] = include_bytes!("fixtures/de.xkb");

    /// `Lock` is the second of the eight core modifiers, `Mod2` (Num Lock) the fifth.
    pub const CAPS_LOCK: u32 = 1 << 1;
    pub const NUM_LOCK: u32 = 1 << 4;

    pub fn keymap(text: &[u8]) -> Keymap {
        Keymap::parse(text).expect("fixture compiles")
    }

    fn key(code: u32, level: u32) -> Key {
        Key { code, level }
    }

    #[test]
    fn fixtures_have_their_layouts() {
        assert_eq!(keymap(US).layouts(), 1);
        assert_eq!(keymap(RU_US).layouts(), 2);
        assert_eq!(keymap(DE).layouts(), 1);
    }

    #[test]
    fn text_that_is_no_keymap_is_refused() {
        assert!(Keymap::parse(b"xkb_keymap {").is_err());
        assert!(Keymap::parse(b"").is_err());
    }

    #[test]
    fn us_keys() {
        let us = keymap(US);
        assert_eq!(us.key_of(0, 0x61), Some(key(38, 0)));
        assert_eq!(us.key_of(0, 0x41), Some(key(38, 1)));
        assert_eq!(us.key_of(0, 0x40), Some(key(11, 1)));
        assert_eq!(us.key_of(0, 0xff09), Some(key(23, 0)));
        // `>` is on <AB09> (60) and on <LSGT> (94); the lower key code wins.
        assert_eq!(us.key_of(0, 0x3e), Some(key(60, 1)));
        // The only EuroSign of `us` is the multimedia key <I443> = 443.
        assert_eq!(us.key_of(0, 0x20ac), Some(key(443, 0)));
        assert_eq!(us.key_of(0, 0xf6), None);
        assert_eq!(us.key_of(0, 0x6f6), None);
        assert_eq!(us.key_of(0, SHIFT_L), Some(key(50, 0)));
        assert_eq!(us.key_of(0, ISO_LEVEL3_SHIFT), Some(key(92, 0)));
    }

    #[test]
    fn russian_and_english_groups_of_one_keymap() {
        let both = keymap(RU_US);
        assert_eq!(both.key_of(0, 0x6d6), Some(key(47, 0)));
        assert_eq!(both.key_of(0, 0x6f6), Some(key(47, 1)));
        assert_eq!(both.key_of(0, 0x2e), Some(key(61, 0)));
        assert_eq!(both.key_of(0, 0x2c), Some(key(61, 1)));
        assert_eq!(both.key_of(0, 0x22), Some(key(11, 1)));
        assert_eq!(both.key_of(0, 0x61), None);
        assert_eq!(both.key_of(0, 0x40), None);
        assert_eq!(both.key_of(1, 0x61), Some(key(38, 0)));
        assert_eq!(both.key_of(1, 0x40), Some(key(11, 1)));
        assert_eq!(both.key_of(1, 0x2e), Some(key(60, 0)));
        assert_eq!(both.key_of(1, 0x6d6), None);
    }

    #[test]
    fn german_keys_and_their_third_level() {
        let de = keymap(DE);
        assert_eq!(de.key_of(0, 0x7a), Some(key(29, 0)));
        assert_eq!(de.key_of(0, 0x79), Some(key(52, 0)));
        assert_eq!(de.key_of(0, 0xf6), Some(key(47, 0)));
        assert_eq!(de.key_of(0, 0xdf), Some(key(20, 0)));
        assert_eq!(de.key_of(0, 0x40), Some(key(24, 2)));
        assert_eq!(de.key_of(0, 0x20ac), Some(key(26, 2)));
        assert_eq!(de.key_of(0, 0x0100_2026), Some(key(60, 2)));
        assert_eq!(de.key_of(0, 0x0100_203a), Some(key(52, 3)));
        assert_eq!(de.key_of(0, 0x0100_1e9e), Some(key(20, 4)));
    }

    #[test]
    fn a_keysym_of_the_active_layout_types_its_character() {
        let us = keymap(US);
        for (keysym, ch) in [(0x61, 'a'), (0x41, 'A'), (0x40, '@'), (0x20ac, '€')] {
            assert!(us.types(0, 0, keysym, Some(ch)), "{ch}");
        }
        assert!(us.types(0, 0, 0xff09, None));
        assert!(us.types(0, 0, 0xff0d, None));
        let de = keymap(DE);
        for (keysym, ch) in [
            (0x40, '@'),
            (0x20ac, '€'),
            (0xf6, 'ö'),
            (0xd6, 'Ö'),
            (0x0100_2026, '…'),
        ] {
            assert!(de.types(0, 0, keysym, Some(ch)), "{ch}");
        }
        let both = keymap(RU_US);
        assert!(both.types(0, 0, 0x6f6, Some('Ж')));
        assert!(both.types(1, 0, 0x41, Some('A')));
    }

    #[test]
    fn a_keysym_the_active_layout_lacks_types_nothing() {
        let us = keymap(US);
        assert!(!us.types(0, 0, 0xf6, Some('ö')));
        assert!(!us.types(0, 0, 0x6f6, Some('Ж')));
        let both = keymap(RU_US);
        assert!(!both.types(0, 0, 0x61, Some('a')));
        assert!(!both.types(0, 0, 0x40, Some('@')));
        assert!(!both.types(1, 0, 0x6f6, Some('Ж')));
    }

    #[test]
    fn a_keysym_above_the_third_level_comes_out_wrong() {
        let de = keymap(DE);
        // Level 4 of <AB01> and level 5 of <AE11>: the desktop holds no modifier for them.
        assert!(!de.types(0, 0, 0x0100_203a, Some('›')));
        assert!(!de.types(0, 0, 0x0100_1e9e, Some('ẞ')));
    }

    #[test]
    fn caps_lock_changes_letters_and_num_lock_does_not() {
        let us = keymap(US);
        assert!(!us.types(0, CAPS_LOCK, 0x61, Some('a')));
        assert!(!us.types(0, CAPS_LOCK, 0x41, Some('A')));
        assert!(us.types(0, CAPS_LOCK, 0x40, Some('@')));
        assert!(us.types(0, NUM_LOCK, 0x61, Some('a')));
        assert!(us.types(0, NUM_LOCK, 0x41, Some('A')));
    }

    #[test]
    fn only_keyboard_key_codes_reach_the_app() {
        assert!(mutter_takes(38));
        assert!(mutter_takes(443));
        assert!(!mutter_takes(8));
        assert!(!mutter_takes(7));
        // BTN_LEFT (0x110) plus the offset.
        assert!(!mutter_takes(0x110 + 8));
    }
}
