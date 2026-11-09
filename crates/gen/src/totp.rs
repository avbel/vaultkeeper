//! RFC 6238 TOTP. Accepts a bare base32 secret (SHA1/6 digits/30 s), an `otpauth://totp/...` URI
//! (`secret`, `algorithm`, `digits`, `period`) or `steam://<base32>` (5 chars from the Steam alphabet).
//!
//! Spaces and dashes, which issuers use to group a secret for reading, are ignored like the
//! official clients do. Unlike them, other characters outside the base32 alphabet are rejected
//! instead of being silently dropped, so a typo never yields a wrong code. `digits` is 1..=10 as
//! in the official clients (codes shorter than 6 exist, e.g. some 4-digit bank tokens).

use std::borrow::Cow;
use std::fmt;
use std::sync::LazyLock;

use data_encoding::{Encoding, Specification};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use url::form_urlencoded;
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

const DEFAULT_DIGITS: u8 = 6;
const DEFAULT_PERIOD: u32 = 30;
const MIN_DIGITS: u8 = 1;
const MAX_DIGITS: u8 = 10;
const STEAM_DIGITS: u8 = 5;
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
const BASE32_SYMBOLS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Trailing-bit checking is off because secrets typed by hand are often not canonical base32 and
// the official clients accept them.
static BASE32: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str(BASE32_SYMBOLS);
    spec.check_trailing_bits = false;
    spec.encoding()
        .expect("static base32 specification is valid")
});

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

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("steam", &self.steam)
            .finish()
    }
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
        let input = input.trim();
        if let Some(rest) = strip_prefix_ignore_case(input, "otpauth://") {
            parse_otpauth(rest)
        } else if let Some(secret) = strip_prefix_ignore_case(input, "steam://") {
            Ok(Self {
                secret: decode_secret(secret)?,
                algorithm: Algorithm::Sha1,
                digits: STEAM_DIGITS,
                period: DEFAULT_PERIOD,
                steam: true,
            })
        } else {
            Ok(Self::with_defaults(decode_secret(input)?))
        }
    }

    #[must_use]
    pub fn generate(&self, unix_time: u64) -> TotpCode {
        let period = u64::from(self.period);
        let truncated = match self.algorithm {
            Algorithm::Sha1 => hmac_truncated::<Hmac<Sha1>>(&self.secret, unix_time / period),
            Algorithm::Sha256 => hmac_truncated::<Hmac<Sha256>>(&self.secret, unix_time / period),
            Algorithm::Sha512 => hmac_truncated::<Hmac<Sha512>>(&self.secret, unix_time / period),
        };
        let code = if self.steam {
            steam_code(truncated)
        } else {
            numeric_code(truncated, self.digits)
        };
        let remaining = u32::try_from(period - unix_time % period)
            .expect("remaining seconds never exceed the u32 period");
        TotpCode {
            code,
            period: self.period,
            remaining,
        }
    }

    #[must_use]
    pub const fn period(&self) -> u32 {
        self.period
    }

    const fn with_defaults(secret: Zeroizing<Vec<u8>>) -> Self {
        Self {
            secret,
            algorithm: Algorithm::Sha1,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
            steam: false,
        }
    }
}

fn strip_prefix_ignore_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let head = input.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &input[prefix.len()..])
}

fn parse_otpauth(rest: &str) -> Result<Totp> {
    let rest = rest.split_once('#').map_or(rest, |(head, _)| head);
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let kind = path.split('/').next().unwrap_or_default();
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(Error::InvalidTotp("only otpauth://totp URIs are supported"));
    }

    let mut params = OtpauthParams::default();
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        params.apply(&key, value)?;
    }
    params.finish()
}

#[derive(Default)]
struct OtpauthParams {
    secret: Option<Zeroizing<Vec<u8>>>,
    algorithm: Option<Algorithm>,
    digits: Option<u8>,
    period: Option<u32>,
}

impl OtpauthParams {
    // The first occurrence of a repeated parameter wins.
    fn apply(&mut self, key: &str, value: Cow<'_, str>) -> Result<()> {
        if key.eq_ignore_ascii_case("secret") {
            let decoded = decode_secret(&value);
            scrub(value);
            if self.secret.is_none() {
                self.secret = Some(decoded?);
            }
        } else if key.eq_ignore_ascii_case("algorithm") {
            if self.algorithm.is_none() {
                self.algorithm = Some(parse_algorithm(&value)?);
            }
        } else if key.eq_ignore_ascii_case("digits") {
            if self.digits.is_none() {
                self.digits = Some(parse_digits(&value)?);
            }
        } else if key.eq_ignore_ascii_case("period") && self.period.is_none() {
            self.period = Some(parse_period(&value)?);
        }
        Ok(())
    }

    fn finish(self) -> Result<Totp> {
        let secret = self
            .secret
            .ok_or(Error::InvalidTotp("missing secret parameter"))?;
        Ok(Totp {
            secret,
            algorithm: self.algorithm.unwrap_or(Algorithm::Sha1),
            digits: self.digits.unwrap_or(DEFAULT_DIGITS),
            period: self.period.unwrap_or(DEFAULT_PERIOD),
            steam: false,
        })
    }
}

fn scrub(value: Cow<'_, str>) {
    if let Cow::Owned(mut owned) = value {
        owned.zeroize();
    }
}

fn parse_algorithm(value: &str) -> Result<Algorithm> {
    if value.eq_ignore_ascii_case("SHA1") {
        Ok(Algorithm::Sha1)
    } else if value.eq_ignore_ascii_case("SHA256") {
        Ok(Algorithm::Sha256)
    } else if value.eq_ignore_ascii_case("SHA512") {
        Ok(Algorithm::Sha512)
    } else {
        Err(Error::InvalidTotp("unsupported algorithm"))
    }
}

fn parse_digits(value: &str) -> Result<u8> {
    value
        .parse::<u8>()
        .ok()
        .filter(|digits| (MIN_DIGITS..=MAX_DIGITS).contains(digits))
        .ok_or(Error::InvalidTotp("digits must be 1..=10"))
}

fn parse_period(value: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .ok()
        .filter(|period| *period > 0)
        .ok_or(Error::InvalidTotp(
            "period must be a positive number of seconds",
        ))
}

fn decode_secret(raw: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut cleaned = Zeroizing::new(Vec::with_capacity(raw.len()));
    cleaned.extend(
        raw.bytes()
            .filter(|byte| !byte.is_ascii_whitespace() && *byte != b'-')
            .map(|byte| byte.to_ascii_uppercase()),
    );
    while cleaned.last() == Some(&b'=') {
        cleaned.pop();
    }
    if cleaned.is_empty() {
        return Err(Error::InvalidTotp("empty secret"));
    }
    BASE32
        .decode(&cleaned)
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidTotp("secret is not valid base32"))
}

fn hmac_truncated<M: Mac + KeyInit>(key: &[u8], counter: u64) -> u32 {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    dynamic_truncation(&mac.finalize().into_bytes())
}

// RFC 4226 section 5.3. The shortest digest is 20 bytes and the offset is at most 15, so the
// 4-byte window always fits.
fn dynamic_truncation(digest: &[u8]) -> u32 {
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ])
}

fn numeric_code(truncated: u32, digits: u8) -> Zeroizing<String> {
    let mut divisor = 10_u64.pow(u32::from(digits) - 1);
    let mut value = u64::from(truncated) % (divisor * 10);
    let mut code = Zeroizing::new(String::with_capacity(usize::from(digits)));
    while divisor > 0 {
        let digit = u8::try_from(value / divisor).expect("quotient is a single decimal digit");
        code.push(char::from(b'0' + digit));
        value %= divisor;
        divisor /= 10;
    }
    code
}

fn steam_code(truncated: u32) -> Zeroizing<String> {
    let base = u32::try_from(STEAM_ALPHABET.len()).expect("alphabet length fits in u32");
    let mut value = truncated;
    let mut code = Zeroizing::new(String::with_capacity(usize::from(STEAM_DIGITS)));
    for _ in 0..STEAM_DIGITS {
        let index = usize::try_from(value % base).expect("alphabet index fits in usize");
        code.push(char::from(STEAM_ALPHABET[index]));
        value /= base;
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    const B32_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const B32_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
    const B32_SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
                              GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=";

    // RFC 6238 Appendix B: (unix time, SHA1, SHA256, SHA512), 8 digits, 30 s step.
    const RFC_VECTORS: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];

    // 2023-01-01T00:00:00Z, the instant used by the Bitwarden SDK vectors.
    const BITWARDEN_TIME: u64 = 1_672_531_200;

    fn raw(seed: &[u8], algorithm: Algorithm) -> Totp {
        Totp {
            secret: Zeroizing::new(seed.to_vec()),
            algorithm,
            digits: 8,
            period: 30,
            steam: false,
        }
    }

    fn code_at(input: &str, unix_time: u64) -> String {
        let totp = Totp::parse(input).expect("input should parse");
        totp.generate(unix_time).code.to_string()
    }

    fn parse_error(input: &str) -> Error {
        Totp::parse(input)
            .err()
            .unwrap_or_else(|| panic!("{input:?} should be rejected"))
    }

    #[test]
    fn rfc6238_vectors_from_ascii_seeds() {
        for (time, sha1, sha256, sha512) in RFC_VECTORS {
            let cases = [
                (SEED_SHA1, Algorithm::Sha1, sha1),
                (SEED_SHA256, Algorithm::Sha256, sha256),
                (SEED_SHA512, Algorithm::Sha512, sha512),
            ];
            for (seed, algorithm, expected) in cases {
                let actual = raw(seed, algorithm).generate(time);
                assert_eq!(actual.code.as_str(), expected, "{algorithm:?} at {time}");
            }
        }
    }

    #[test]
    fn rfc6238_vectors_through_otpauth_parsing() {
        for (time, sha1, sha256, sha512) in RFC_VECTORS {
            let cases = [
                (B32_SHA1, "SHA1", sha1),
                (B32_SHA256, "SHA256", sha256),
                (B32_SHA512, "SHA512", sha512),
            ];
            for (secret, algorithm, expected) in cases {
                let uri = format!(
                    "otpauth://totp/RFC?secret={secret}&algorithm={algorithm}&digits=8&period=30"
                );
                assert_eq!(code_at(&uri, time), expected, "{algorithm} at {time}");
            }
        }
    }

    #[test]
    fn bare_secrets_match_bitwarden_vectors() {
        let cases = [
            ("WQIQ25BRKZYCJVYP", "194506"),
            ("wqiq25brkzycjvyp", "194506"),
            ("wqiq 25br\tkzyc jvyp\n", "194506"),
            ("PIUDISEQYA", "829846"),
            ("PIUDISEQYA======", "829846"),
            ("ddfdf", "932653"),
            ("HJSGFJHDFDJDJKSDFD", "000034"),
            ("xvdsfasdfasdasdghsgsdfg", "403786"),
            ("DKWOW4PCP3MYFWLN53BLYAMYQEQJU4MJ", "559388"),
        ];
        for (secret, expected) in cases {
            let totp = Totp::parse(secret).expect("secret should parse");
            let code = totp.generate(BITWARDEN_TIME);
            assert_eq!(code.code.as_str(), expected, "secret {secret:?}");
            assert_eq!(code.period, 30);
        }
    }

    #[test]
    fn otpauth_defaults_match_bare_secret() {
        let uri = "otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP";
        assert_eq!(code_at(uri, BITWARDEN_TIME), "194506");
    }

    #[test]
    fn otpauth_period_and_algorithm_match_bitwarden_vectors() {
        let period = "otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP&period=60";
        let totp = Totp::parse(period).expect("period uri should parse");
        let code = totp.generate(BITWARDEN_TIME);
        assert_eq!(code.code.as_str(), "730364");
        assert_eq!(code.period, 60);
        assert_eq!(totp.period(), 60);

        let sha256 = "otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP&algorithm=SHA256";
        assert_eq!(code_at(sha256, BITWARDEN_TIME), "842615");
    }

    #[test]
    fn otpauth_accepts_uri_variations() {
        let expected = code_at("WQIQ25BRKZYCJVYP", BITWARDEN_TIME);
        let uris = [
            "OTPAuth://TOTP/test-account?SECRET=WQIQ25BRKZYCJVYP",
            "  otpauth://totp/Issuer:user%40example.com?issuer=Issuer&secret=WQIQ25BRKZYCJVYP  ",
            "otpauth://totp/?secret=WQIQ25BRKZYCJVYP",
            "otpauth://totp?secret=WQIQ25BRKZYCJVYP",
            "otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&algorithm=sha1&digits=6&period=30",
            "otpauth://totp/x?secret=WQIQ%2025BR+KZYC%20JVYP",
            "otpauth://totp/x?secret=wqiq25brkzycjvyp#fragment",
            "otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&secret=AAAAAAAA",
            "otpauth://totp/x?unknown=1&secret=WQIQ25BRKZYCJVYP&image=https%3A%2F%2Fa.b%2Fc.png",
        ];
        for uri in uris {
            assert_eq!(code_at(uri, BITWARDEN_TIME), expected, "uri {uri:?}");
        }
    }

    #[test]
    fn otpauth_digits_range_is_honored() {
        for digits in MIN_DIGITS..=MAX_DIGITS {
            let uri = format!("otpauth://totp/x?secret={B32_SHA1}&digits={digits}");
            let code = code_at(&uri, 59);
            assert_eq!(code.len(), usize::from(digits), "digits={digits}");
            assert!(code.bytes().all(|b| b.is_ascii_digit()), "{code}");
        }
    }

    #[test]
    fn short_codes_are_the_last_digits_of_the_rfc_value() {
        // RFC 6238 appendix B, SHA1 at T = 59 s: 94287082.
        let code = |digits: u8| {
            code_at(
                &format!("otpauth://totp/x?secret={B32_SHA1}&digits={digits}"),
                59,
            )
        };
        assert_eq!(code(5), "87082");
        assert_eq!(code(4), "7082");
        assert_eq!(code(1), "2");
    }

    #[test]
    fn grouping_dashes_and_spaces_are_ignored() {
        // Bitwarden SDK vector: WQIQ25BRKZYCJVYP at 2023-01-01T00:00:00Z is 194506.
        for secret in [
            "WQIQ-25BR-KZYC-JVYP",
            "wqiq 25br kzyc jvyp",
            "WQIQ - 25BR\tKZYC-JVYP",
            "otpauth://totp/x?secret=WQIQ-25BR-KZYC-JVYP",
            "steam://WQIQ-25BR-KZYC-JVYP",
        ] {
            let expected = if secret.starts_with("steam") {
                code_at("steam://WQIQ25BRKZYCJVYP", BITWARDEN_TIME)
            } else {
                "194506".to_owned()
            };
            assert_eq!(code_at(secret, BITWARDEN_TIME), expected, "{secret:?}");
        }
    }

    #[test]
    fn ten_digit_code_is_the_zero_padded_truncated_value() {
        // RFC 4226 dynamic truncation at T=1 yields 1094287082 for the SHA1 seed (the 8-digit
        // code 94287082 is its last eight digits).
        let uri = format!("otpauth://totp/x?secret={B32_SHA1}&digits=10");
        assert_eq!(code_at(&uri, 59), "1094287082");
    }

    #[test]
    fn leading_zeros_are_kept() {
        assert_eq!(code_at("HJSGFJHDFDJDJKSDFD", BITWARDEN_TIME), "000034");
        let uri = format!("otpauth://totp/x?secret={B32_SHA1}&digits=8");
        assert_eq!(code_at(&uri, 1_111_111_109), "07081804");
    }

    #[test]
    fn steam_matches_bitwarden_vector() {
        let secret = "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ";
        let totp = Totp::parse(&format!("steam://{secret}")).expect("steam uri should parse");
        let code = totp.generate(BITWARDEN_TIME);
        assert_eq!(code.code.as_str(), "7W6CJ");
        assert_eq!(code.period, 30);
        assert_eq!(
            code_at(&format!("StEam://{secret}"), BITWARDEN_TIME),
            "7W6CJ"
        );
    }

    #[test]
    fn steam_codes_use_only_the_steam_alphabet() {
        let totp = Totp::parse("steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ").expect("steam");
        for step in 0..200_u64 {
            let code = totp.generate(step * 30);
            assert_eq!(code.code.len(), 5);
            assert!(
                code.code.bytes().all(|b| STEAM_ALPHABET.contains(&b)),
                "{}",
                code.code.as_str()
            );
        }
    }

    #[test]
    fn code_is_stable_within_a_period_and_changes_across_it() {
        let totp = Totp::parse("WQIQ25BRKZYCJVYP").expect("secret");
        let first = totp.generate(BITWARDEN_TIME);
        assert_eq!(first.code, totp.generate(BITWARDEN_TIME + 29).code);
        assert_ne!(first.code, totp.generate(BITWARDEN_TIME + 30).code);
    }

    #[test]
    fn remaining_seconds_at_period_boundaries() {
        let totp = Totp::parse("WQIQ25BRKZYCJVYP").expect("secret");
        let cases = [
            (0, 30),
            (1, 29),
            (29, 1),
            (30, 30),
            (59, 1),
            (60, 30),
            (BITWARDEN_TIME, 30),
        ];
        for (time, remaining) in cases {
            assert_eq!(totp.generate(time).remaining, remaining, "time {time}");
        }

        let long = Totp::parse("otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&period=60").expect("uri");
        let cases = [(0, 60), (59, 1), (60, 60), (61, 59), (119, 1)];
        for (time, remaining) in cases {
            assert_eq!(long.generate(time).remaining, remaining, "time {time}");
        }
    }

    #[test]
    fn extreme_times_and_periods_do_not_panic() {
        let totp = Totp::parse("WQIQ25BRKZYCJVYP").expect("secret");
        let code = totp.generate(u64::MAX);
        assert_eq!(code.code.len(), 6);
        assert!((1..=30).contains(&code.remaining));

        let uri = format!("otpauth://totp/x?secret={B32_SHA1}&period={}", u32::MAX);
        let huge = Totp::parse(&uri).expect("max period");
        assert_eq!(huge.generate(u64::MAX).period, u32::MAX);
        assert!((1..=u32::MAX).contains(&huge.generate(5).remaining));
    }

    #[test]
    fn rejects_empty_and_invalid_secrets() {
        let inputs = [
            "",
            "   ",
            "======",
            "A",
            "AAA",
            "AAAAAA",
            "!!!!",
            "PIUD1IS!EQYA=",
            "KAKFJWOSFJ12NWL",
            "AB=CD",
            "WQIQ25BRKZYCJVYP\u{e9}",
            "steam://",
            "steam://   ",
            "steam://!!!",
            "steam://ABCD123!",
            "otpauth://totp/x?secret=",
            "otpauth://totp/x?secret=%20%20",
            "otpauth://totp/x?secret=1111",
        ];
        for input in inputs {
            assert!(
                matches!(parse_error(input), Error::InvalidTotp(_)),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn rejects_hotp_and_unknown_uri_kinds() {
        let inputs = [
            "otpauth://hotp/x?secret=WQIQ25BRKZYCJVYP&counter=1",
            "otpauth://HOTP/x?secret=WQIQ25BRKZYCJVYP",
            "otpauth://foo/x?secret=WQIQ25BRKZYCJVYP",
            "otpauth://totpx/x?secret=WQIQ25BRKZYCJVYP",
            "otpauth://",
            "otpauth://totp",
            "otpauth://totp/x",
            "otpauth://totp/x?issuer=Acme",
        ];
        for input in inputs {
            assert!(
                matches!(parse_error(input), Error::InvalidTotp(_)),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn rejects_out_of_range_parameters() {
        let params = [
            "digits=11",
            "digits=0",
            "digits=-6",
            "digits=abc",
            "digits=",
            "digits=300",
            "period=0",
            "period=-30",
            "period=abc",
            "period=",
            "period=4294967296",
            "algorithm=MD5",
            "algorithm=",
            "algorithm=SHA3",
        ];
        for param in params {
            let uri = format!("otpauth://totp/x?secret=WQIQ25BRKZYCJVYP&{param}");
            assert!(
                matches!(parse_error(&uri), Error::InvalidTotp(_)),
                "param {param}"
            );
        }
    }

    #[test]
    fn error_messages_name_the_problem() {
        assert_eq!(
            parse_error("").to_string(),
            "invalid TOTP secret or URI: empty secret"
        );
        assert_eq!(
            parse_error("otpauth://hotp/x?secret=WQIQ25BRKZYCJVYP").to_string(),
            "invalid TOTP secret or URI: only otpauth://totp URIs are supported"
        );
        assert_eq!(
            parse_error("otpauth://totp/x").to_string(),
            "invalid TOTP secret or URI: missing secret parameter"
        );
    }

    #[test]
    fn debug_output_redacts_the_secret() {
        let totp = Totp::parse("WQIQ25BRKZYCJVYP").expect("secret");
        let debug = format!("{totp:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains("WQIQ"), "{debug}");
        assert!(!debug.contains("180, 17"), "{debug}");
    }
}
