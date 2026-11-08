//! Password and passphrase generators (OS CSPRNG). Defaults match the official clients.
//!
//! A failure of the OS random source panics: no safe fallback exists for secret generation.

mod passphrase;

pub use passphrase::{PassphraseOptions, generate_passphrase};

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::seq::SliceRandom;
use rand::{Rng, RngExt};
use zeroize::Zeroizing;

use crate::{Error, Result};

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@#$%^&*";
const AMBIGUOUS: &[u8] = b"Il1O0";

const MIN_LENGTH: u8 = 5;
const MAX_LENGTH: u8 = 128;
const MAX_MINIMUM: u8 = 9;

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

struct CharSet {
    chars: Vec<u8>,
    required: usize,
}

pub fn generate_password(options: &PasswordOptions) -> Result<Zeroizing<String>> {
    let sets = plan_password(options)?;
    Ok(build_password(
        &mut UnwrapErr(SysRng),
        &sets,
        usize::from(options.length),
    ))
}

fn plan_password(options: &PasswordOptions) -> Result<Vec<CharSet>> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length) {
        return Err(Error::InvalidOptions("password length must be 5..=128"));
    }
    if options.min_numbers > MAX_MINIMUM || options.min_special > MAX_MINIMUM {
        return Err(Error::InvalidOptions("minimum counts must be 0..=9"));
    }

    let candidates = [
        (options.uppercase, UPPERCASE, 1),
        (options.lowercase, LOWERCASE, 1),
        (
            options.numbers,
            DIGITS,
            usize::from(options.min_numbers.max(1)),
        ),
        (
            options.special,
            SPECIAL,
            usize::from(options.min_special.max(1)),
        ),
    ];
    let sets: Vec<CharSet> = candidates
        .into_iter()
        .filter(|(enabled, ..)| *enabled)
        .map(|(_, chars, required)| CharSet {
            chars: chars
                .iter()
                .copied()
                .filter(|c| !(options.avoid_ambiguous && AMBIGUOUS.contains(c)))
                .collect(),
            required,
        })
        .collect();

    if sets.is_empty() {
        return Err(Error::InvalidOptions(
            "at least one character set must be enabled",
        ));
    }
    if sets.iter().map(|set| set.required).sum::<usize>() > usize::from(options.length) {
        return Err(Error::InvalidOptions(
            "required characters exceed the password length",
        ));
    }
    Ok(sets)
}

fn build_password<R: Rng + ?Sized>(
    rng: &mut R,
    sets: &[CharSet],
    length: usize,
) -> Zeroizing<String> {
    let pool: Vec<u8> = sets
        .iter()
        .flat_map(|set| set.chars.iter().copied())
        .collect();
    let mut chars = Zeroizing::new(Vec::with_capacity(length));
    for set in sets {
        for _ in 0..set.required {
            chars.push(pick(rng, &set.chars));
        }
    }
    while chars.len() < length {
        chars.push(pick(rng, &pool));
    }
    chars.shuffle(rng);

    let mut password = Zeroizing::new(String::with_capacity(length));
    password.extend(chars.iter().map(|&byte| char::from(byte)));
    password
}

fn pick<R: Rng + ?Sized>(rng: &mut R, chars: &[u8]) -> u8 {
    chars[rng.random_range(0..chars.len())]
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const ITERATIONS: usize = 300;

    fn options(length: u8) -> PasswordOptions {
        PasswordOptions {
            length,
            ..PasswordOptions::default()
        }
    }

    fn all_sets(length: u8) -> PasswordOptions {
        PasswordOptions {
            length,
            uppercase: true,
            lowercase: true,
            numbers: true,
            special: true,
            min_numbers: 1,
            min_special: 1,
            avoid_ambiguous: false,
        }
    }

    fn password(options: &PasswordOptions) -> Zeroizing<String> {
        generate_password(options).expect("options should be valid")
    }

    fn count(password: &str, set: &[u8]) -> usize {
        password.bytes().filter(|byte| set.contains(byte)).count()
    }

    fn assert_invalid(result: Result<Zeroizing<String>>, message: &str) {
        match result {
            Err(Error::InvalidOptions(actual)) => assert_eq!(actual, message),
            other => panic!("expected InvalidOptions({message:?}), got {other:?}"),
        }
    }

    #[test]
    fn default_password_has_default_length_and_required_sets() {
        for _ in 0..ITERATIONS {
            let value = password(&PasswordOptions::default());
            assert_eq!(value.len(), 14);
            assert!(count(&value, UPPERCASE) >= 1, "{}", value.as_str());
            assert!(count(&value, LOWERCASE) >= 1, "{}", value.as_str());
            assert!(count(&value, DIGITS) >= 1, "{}", value.as_str());
            assert_eq!(count(&value, SPECIAL), 0, "{}", value.as_str());
        }
    }

    #[test]
    fn password_length_matches_option_across_the_valid_range() {
        for length in [5, 6, 14, 64, 127, 128] {
            let value = password(&all_sets(length));
            assert_eq!(value.len(), usize::from(length));
        }
    }

    #[test]
    fn rejects_lengths_outside_5_to_128() {
        for length in [0, 1, 4, 129, 200, 255] {
            assert_invalid(
                generate_password(&options(length)),
                "password length must be 5..=128",
            );
        }
    }

    #[test]
    fn every_enabled_set_is_present_even_at_the_shortest_length() {
        for _ in 0..ITERATIONS {
            let value = password(&all_sets(5));
            assert!(count(&value, UPPERCASE) >= 1, "{}", value.as_str());
            assert!(count(&value, LOWERCASE) >= 1, "{}", value.as_str());
            assert!(count(&value, DIGITS) >= 1, "{}", value.as_str());
            assert!(count(&value, SPECIAL) >= 1, "{}", value.as_str());
        }
    }

    #[test]
    fn single_enabled_set_produces_only_that_set() {
        let cases: [(PasswordOptions, &[u8]); 4] = [
            (
                PasswordOptions {
                    lowercase: false,
                    numbers: false,
                    ..options(30)
                },
                UPPERCASE,
            ),
            (
                PasswordOptions {
                    uppercase: false,
                    numbers: false,
                    ..options(30)
                },
                LOWERCASE,
            ),
            (
                PasswordOptions {
                    uppercase: false,
                    lowercase: false,
                    ..options(30)
                },
                DIGITS,
            ),
            (
                PasswordOptions {
                    uppercase: false,
                    lowercase: false,
                    numbers: false,
                    special: true,
                    min_numbers: 0,
                    ..options(30)
                },
                SPECIAL,
            ),
        ];
        for (opts, set) in cases {
            for _ in 0..50 {
                let value = password(&opts);
                assert_eq!(count(&value, set), value.len(), "{}", value.as_str());
            }
        }
    }

    #[test]
    fn minimum_counts_are_honored() {
        let opts = PasswordOptions {
            min_numbers: 5,
            min_special: 4,
            ..all_sets(20)
        };
        for _ in 0..ITERATIONS {
            let value = password(&opts);
            assert_eq!(value.len(), 20);
            assert!(count(&value, DIGITS) >= 5, "{}", value.as_str());
            assert!(count(&value, SPECIAL) >= 4, "{}", value.as_str());
            assert!(count(&value, UPPERCASE) >= 1, "{}", value.as_str());
            assert!(count(&value, LOWERCASE) >= 1, "{}", value.as_str());
        }
    }

    #[test]
    fn minimums_that_fill_the_whole_password_are_accepted() {
        let opts = PasswordOptions {
            uppercase: false,
            lowercase: false,
            special: false,
            min_numbers: 5,
            ..options(5)
        };
        for _ in 0..50 {
            let value = password(&opts);
            assert_eq!(count(&value, DIGITS), 5);
        }

        let opts = PasswordOptions {
            uppercase: false,
            lowercase: false,
            min_numbers: 3,
            min_special: 2,
            special: true,
            ..options(5)
        };
        for _ in 0..50 {
            let value = password(&opts);
            assert_eq!(count(&value, DIGITS), 3, "{}", value.as_str());
            assert_eq!(count(&value, SPECIAL), 2, "{}", value.as_str());
        }
    }

    #[test]
    fn maximum_minimums_fit_in_a_long_password() {
        let opts = PasswordOptions {
            min_numbers: 9,
            min_special: 9,
            ..all_sets(40)
        };
        let value = password(&opts);
        assert!(count(&value, DIGITS) >= 9);
        assert!(count(&value, SPECIAL) >= 9);
    }

    #[test]
    fn ambiguous_characters_are_absent_when_requested() {
        let opts = PasswordOptions {
            avoid_ambiguous: true,
            ..all_sets(128)
        };
        for _ in 0..ITERATIONS {
            let value = password(&opts);
            assert_eq!(count(&value, b"Il1O0"), 0, "{}", value.as_str());
        }
    }

    #[test]
    fn ambiguous_characters_appear_when_not_excluded() {
        let mut seen = HashSet::new();
        for _ in 0..ITERATIONS {
            seen.extend(password(&all_sets(128)).bytes());
        }
        for byte in b"Il1O0" {
            assert!(seen.contains(byte), "{} never generated", char::from(*byte));
        }
    }

    #[test]
    fn avoid_ambiguous_still_satisfies_required_sets() {
        let opts = PasswordOptions {
            avoid_ambiguous: true,
            min_numbers: 3,
            ..all_sets(10)
        };
        for _ in 0..ITERATIONS {
            let value = password(&opts);
            assert!(count(&value, DIGITS) >= 3, "{}", value.as_str());
            assert!(count(&value, UPPERCASE) >= 1, "{}", value.as_str());
            assert!(count(&value, LOWERCASE) >= 1, "{}", value.as_str());
            assert!(count(&value, SPECIAL) >= 1, "{}", value.as_str());
            assert_eq!(count(&value, b"Il1O0"), 0, "{}", value.as_str());
        }
    }

    #[test]
    fn password_uses_only_enabled_set_characters() {
        let allowed: Vec<u8> = [UPPERCASE, LOWERCASE, DIGITS, SPECIAL].concat();
        for _ in 0..ITERATIONS {
            let value = password(&all_sets(128));
            assert_eq!(count(&value, &allowed), 128, "{}", value.as_str());
        }
    }

    #[test]
    fn rejects_when_no_set_is_enabled() {
        let opts = PasswordOptions {
            uppercase: false,
            lowercase: false,
            numbers: false,
            special: false,
            ..options(14)
        };
        assert_invalid(
            generate_password(&opts),
            "at least one character set must be enabled",
        );
    }

    #[test]
    fn rejects_minimums_above_nine() {
        let numbers = PasswordOptions {
            min_numbers: 10,
            ..options(40)
        };
        let special = PasswordOptions {
            min_special: 10,
            special: true,
            ..options(40)
        };
        for opts in [numbers, special] {
            assert_invalid(generate_password(&opts), "minimum counts must be 0..=9");
        }
    }

    #[test]
    fn rejects_required_characters_exceeding_length() {
        let opts = PasswordOptions {
            min_numbers: 3,
            min_special: 2,
            ..all_sets(5)
        };
        assert_invalid(
            generate_password(&opts),
            "required characters exceed the password length",
        );

        let opts = PasswordOptions {
            min_numbers: 9,
            ..options(10)
        };
        assert_invalid(
            generate_password(&opts),
            "required characters exceed the password length",
        );
    }

    #[test]
    fn minimums_of_disabled_sets_are_ignored() {
        let opts = PasswordOptions {
            numbers: false,
            special: false,
            min_numbers: 9,
            min_special: 9,
            ..options(5)
        };
        for _ in 0..50 {
            let value = password(&opts);
            assert_eq!(count(&value, DIGITS), 0, "{}", value.as_str());
            assert_eq!(count(&value, SPECIAL), 0, "{}", value.as_str());
        }
    }

    #[test]
    fn zero_minimum_still_guarantees_one_character_of_each_enabled_set() {
        let opts = PasswordOptions {
            min_numbers: 0,
            min_special: 0,
            ..all_sets(5)
        };
        for _ in 0..ITERATIONS {
            let value = password(&opts);
            assert!(count(&value, DIGITS) >= 1, "{}", value.as_str());
            assert!(count(&value, SPECIAL) >= 1, "{}", value.as_str());
        }
    }

    #[test]
    fn thousand_passwords_are_distinct() {
        let unique: HashSet<String> = (0..1000)
            .map(|_| password(&PasswordOptions::default()).to_string())
            .collect();
        assert_eq!(unique.len(), 1000);
    }

    #[test]
    fn digit_choice_is_uniform() {
        let opts = PasswordOptions {
            uppercase: false,
            lowercase: false,
            min_numbers: 0,
            ..options(128)
        };
        let mut tally = [0_usize; 10];
        for _ in 0..200 {
            for byte in password(&opts).bytes() {
                tally[usize::from(byte - b'0')] += 1;
            }
        }
        // 25600 draws, mean 2560 per digit, sigma about 48; 300 is over six sigma.
        for (digit, seen) in tally.iter().enumerate() {
            assert!(seen.abs_diff(2560) < 300, "digit {digit} seen {seen} times");
        }
    }

    #[test]
    fn required_characters_are_shuffled_across_positions() {
        let mut first_chars = HashSet::new();
        for _ in 0..ITERATIONS {
            let value = password(&all_sets(8));
            let first = value.as_bytes()[0];
            for (name, set) in [
                ("upper", UPPERCASE),
                ("lower", LOWERCASE),
                ("digit", DIGITS),
            ] {
                if set.contains(&first) {
                    first_chars.insert(name);
                }
            }
        }
        assert_eq!(
            first_chars.len(),
            3,
            "first position only held {first_chars:?}"
        );
    }

    #[test]
    fn defaults_match_the_official_clients() {
        let options = PasswordOptions::default();
        assert_eq!(options.length, 14);
        assert!(options.uppercase && options.lowercase && options.numbers);
        assert!(!options.special && !options.avoid_ambiguous);
        assert_eq!((options.min_numbers, options.min_special), (1, 0));
    }
}
