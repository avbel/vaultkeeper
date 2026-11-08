//! RFC 6238 TOTP. Accepts a bare base32 secret (SHA1/6 digits/30 s), an `otpauth://totp/...` URI
//! (`secret`, `algorithm`, `digits`, `period`) or `steam://<base32>` (5 chars from the Steam alphabet).

use zeroize::Zeroizing;

use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// Parsed TOTP parameters; the secret is zeroized on drop.
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
    steam: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    pub code: Zeroizing<String>,
    pub period: u32,
    /// Seconds until this code expires (1..=period).
    pub remaining: u32,
}

impl Totp {
    pub fn parse(input: &str) -> Result<Self> {
        let _ = input;
        todo!("step 3")
    }

    #[must_use]
    pub fn generate(&self, unix_time: u64) -> TotpCode {
        let _ = (
            unix_time,
            &self.secret,
            self.algorithm,
            self.digits,
            self.period,
            self.steam,
        );
        todo!("step 3")
    }

    #[must_use]
    pub const fn period(&self) -> u32 {
        self.period
    }
}
