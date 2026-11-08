//! Password and passphrase generators (OS CSPRNG). Defaults match the official clients.

use zeroize::Zeroizing;

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordOptions {
    /// 5..=128, default 14.
    pub length: u8,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    /// Special set `!@#$%^&*`.
    pub special: bool,
    /// Minimum digits / specials, 0..=9 each (only when the set is enabled).
    pub min_numbers: u8,
    pub min_special: u8,
    /// Remove `Il1O0` when true.
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 14,
            uppercase: true,
            lowercase: true,
            numbers: true,
            special: false,
            min_numbers: 1,
            min_special: 0,
            avoid_ambiguous: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// 3..=20, default 6.
    pub words: u8,
    pub separator: String,
    pub capitalize: bool,
    /// Appends one random digit to one random word.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".to_owned(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// EFF long wordlist (7776 words), one per line.
const EFF_LONG: &str = include_str!("../data/eff_long.txt");

pub fn generate_password(options: &PasswordOptions) -> Result<Zeroizing<String>> {
    let _ = options;
    todo!("step 3")
}

pub fn generate_passphrase(options: &PassphraseOptions) -> Result<Zeroizing<String>> {
    let _ = (options, EFF_LONG);
    todo!("step 3")
}
