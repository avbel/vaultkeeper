//! The desktop's light/dark preference as the Settings portal reports it.
//!
//! Only Linux ever stores a value; elsewhere the winit backend already reports the scheme, so
//! [`current`] stays [`SystemScheme::Unknown`] and the Slint palette is left alone.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SystemScheme {
    #[default]
    Unknown,
    Light,
    Dark,
}

impl SystemScheme {
    /// `None` is the portal's "no preference", which the app treats as unknown.
    #[must_use]
    pub const fn from_dark(dark: Option<bool>) -> Self {
        match dark {
            Some(true) => Self::Dark,
            Some(false) => Self::Light,
            None => Self::Unknown,
        }
    }

    /// The value of `Theme.portal-scheme`.
    #[must_use]
    pub const fn slint_code(self) -> i32 {
        match self {
            Self::Unknown => 0,
            Self::Light => 1,
            Self::Dark => 2,
        }
    }

    const fn to_bits(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Light => 1,
            Self::Dark => 2,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits {
            1 => Self::Light,
            2 => Self::Dark,
            _ => Self::Unknown,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

#[must_use]
pub fn current() -> SystemScheme {
    SystemScheme::from_bits(CURRENT.load(Ordering::Acquire))
}

pub fn store(scheme: SystemScheme) {
    CURRENT.store(scheme.to_bits(), Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_preference_maps_to_the_slint_codes() {
        assert_eq!(SystemScheme::from_dark(None).slint_code(), 0);
        assert_eq!(SystemScheme::from_dark(Some(false)).slint_code(), 1);
        assert_eq!(SystemScheme::from_dark(Some(true)).slint_code(), 2);
    }

    #[test]
    fn a_stored_scheme_is_read_back() {
        store(SystemScheme::Dark);
        assert_eq!(current(), SystemScheme::Dark);
        store(SystemScheme::Unknown);
        assert_eq!(current(), SystemScheme::Unknown);
    }
}
