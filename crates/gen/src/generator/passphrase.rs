//! EFF long wordlist passphrases.

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::{Rng, RngExt};
use zeroize::Zeroizing;

use crate::{Error, Result};

const MIN_WORDS: u8 = 3;
const MAX_WORDS: u8 = 20;

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
const EFF_LONG: &str = include_str!("../../data/eff_long.txt");
const EFF_WORD_COUNT: usize = 7776;

// Checked at compile time so word lookup by index can never miss and the passphrase buffer can be
// sized exactly (a reallocation would leave an unzeroized copy of the secret behind).
const EFF_MAX_WORD_LEN: usize = {
    let bytes = EFF_LONG.as_bytes();
    let (mut count, mut longest, mut current) = (0, 0, 0);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            count += 1;
            if current > longest {
                longest = current;
            }
            current = 0;
        } else {
            current += 1;
        }
        i += 1;
    }
    assert!(
        count == EFF_WORD_COUNT && current == 0,
        "eff_long.txt must hold 7776 newline-terminated words"
    );
    longest
};

pub fn generate_passphrase(options: &PassphraseOptions) -> Result<Zeroizing<String>> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&options.words) {
        return Err(Error::InvalidOptions("passphrase must have 3..=20 words"));
    }
    Ok(build_passphrase(&mut UnwrapErr(SysRng), options))
}

fn build_passphrase<R: Rng + ?Sized>(
    rng: &mut R,
    options: &PassphraseOptions,
) -> Zeroizing<String> {
    let words = usize::from(options.words);
    let separators = (words - 1) * options.separator.len();
    let mut passphrase = Zeroizing::new(String::with_capacity(
        words * (EFF_MAX_WORD_LEN + 1) + separators,
    ));
    let number_word = options.include_number.then(|| rng.random_range(0..words));

    for index in 0..words {
        if index > 0 {
            passphrase.push_str(&options.separator);
        }
        push_word(&mut passphrase, random_word(rng), options.capitalize);
        if number_word == Some(index) {
            passphrase.push(char::from(b'0' + rng.random_range(0..10_u8)));
        }
    }
    passphrase
}

fn random_word<R: Rng + ?Sized>(rng: &mut R) -> &'static str {
    EFF_LONG
        .lines()
        .nth(rng.random_range(0..EFF_WORD_COUNT))
        .expect("wordlist length is verified at compile time")
}

fn push_word(out: &mut String, word: &str, capitalize: bool) {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) if capitalize => {
            out.push(first.to_ascii_uppercase());
            out.push_str(chars.as_str());
        }
        _ => out.push_str(word),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const ITERATIONS: usize = 300;

    fn passphrase(options: &PassphraseOptions) -> Zeroizing<String> {
        generate_passphrase(options).expect("options should be valid")
    }

    fn wordlist() -> HashSet<&'static str> {
        EFF_LONG.lines().collect()
    }

    fn assert_invalid(result: Result<Zeroizing<String>>, message: &str) {
        match result {
            Err(Error::InvalidOptions(actual)) => assert_eq!(actual, message),
            other => panic!("expected InvalidOptions({message:?}), got {other:?}"),
        }
    }

    #[test]
    fn wordlist_has_7776_unique_lowercase_words() {
        let words: Vec<&str> = EFF_LONG.lines().collect();
        assert_eq!(words.len(), 7776);
        assert_eq!(words.iter().collect::<HashSet<_>>().len(), 7776);
        assert_eq!(words[0], "abacus");
        assert_eq!(words[7775], "zoom");
        for word in &words {
            assert!(
                (3..=EFF_MAX_WORD_LEN).contains(&word.len()),
                "{word:?} has length {}",
                word.len()
            );
            assert!(
                word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{word:?}"
            );
        }
        assert_eq!(
            EFF_MAX_WORD_LEN,
            words.iter().map(|w| w.len()).max().unwrap_or(0)
        );
    }

    fn dotted(words: u8) -> PassphraseOptions {
        PassphraseOptions {
            words,
            separator: ".".to_owned(),
            ..PassphraseOptions::default()
        }
    }

    #[test]
    fn default_passphrase_has_six_hyphen_separated_words() {
        let words = wordlist();
        for _ in 0..ITERATIONS {
            let value = passphrase(&PassphraseOptions::default());
            assert!(value.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
            assert!(!value.starts_with('-') && !value.ends_with('-'));
            // Four list words contain a hyphen themselves, so only check the lower bound.
            assert!(value.split('-').count() >= 6, "{}", value.as_str());
            assert!(
                value.split('-').all(|part| !part.is_empty()),
                "{}",
                value.as_str()
            );
            assert!(value.split('-').any(|part| words.contains(part)));
        }
    }

    #[test]
    fn passphrase_word_count_and_membership() {
        let words = wordlist();
        for count in MIN_WORDS..=MAX_WORDS {
            let value = passphrase(&dotted(count));
            let parts: Vec<&str> = value.split('.').collect();
            assert_eq!(parts.len(), usize::from(count), "{}", value.as_str());
            for part in parts {
                assert!(words.contains(part), "{part:?} is not in the wordlist");
            }
        }
    }

    #[test]
    fn rejects_word_counts_outside_3_to_20() {
        for count in [0, 1, 2, 21, 255] {
            assert_invalid(
                generate_passphrase(&dotted(count)),
                "passphrase must have 3..=20 words",
            );
        }
    }

    #[test]
    fn passphrase_supports_custom_multi_character_and_empty_separators() {
        let words = wordlist();
        let value = passphrase(&PassphraseOptions {
            separator: " :: ".to_owned(),
            ..dotted(5)
        });
        let parts: Vec<&str> = value.split(" :: ").collect();
        assert_eq!(parts.len(), 5, "{}", value.as_str());
        assert!(parts.iter().all(|part| words.contains(part)));

        let joined = passphrase(&PassphraseOptions {
            separator: String::new(),
            ..dotted(4)
        });
        assert!(joined.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
        assert!((4 * 3..=4 * EFF_MAX_WORD_LEN).contains(&joined.len()));
    }

    #[test]
    fn capitalize_uppercases_only_the_first_letter_of_every_word() {
        let words = wordlist();
        for _ in 0..ITERATIONS {
            let value = passphrase(&PassphraseOptions {
                capitalize: true,
                ..dotted(8)
            });
            for part in value.split('.') {
                let first = part.chars().next().expect("word is not empty");
                assert!(first.is_ascii_uppercase(), "{part:?}");
                let restored = format!("{}{}", first.to_ascii_lowercase(), &part[1..]);
                assert!(words.contains(restored.as_str()), "{part:?}");
            }
        }
    }

    #[test]
    fn words_stay_lowercase_without_capitalize() {
        let value = passphrase(&dotted(20));
        assert!(value.bytes().all(|b| !b.is_ascii_uppercase()));
    }

    #[test]
    fn include_number_appends_exactly_one_digit_to_one_word() {
        let words = wordlist();
        for _ in 0..ITERATIONS {
            let value = passphrase(&PassphraseOptions {
                include_number: true,
                ..dotted(6)
            });
            assert_eq!(
                value.bytes().filter(u8::is_ascii_digit).count(),
                1,
                "{}",
                value.as_str()
            );
            let parts: Vec<&str> = value.split('.').collect();
            assert_eq!(parts.len(), 6);
            let numbered: Vec<&&str> = parts
                .iter()
                .filter(|part| part.ends_with(|c: char| c.is_ascii_digit()))
                .collect();
            assert_eq!(numbered.len(), 1, "{}", value.as_str());
            for part in parts {
                let bare = part.trim_end_matches(|c: char| c.is_ascii_digit());
                assert!(words.contains(bare), "{part:?}");
            }
        }
    }

    #[test]
    fn include_number_hits_every_word_position() {
        let mut positions = HashSet::new();
        for _ in 0..600 {
            let value = passphrase(&PassphraseOptions {
                include_number: true,
                ..dotted(3)
            });
            let position = value
                .split('.')
                .position(|part| part.ends_with(|c: char| c.is_ascii_digit()))
                .expect("one word carries the digit");
            positions.insert(position);
        }
        assert_eq!(positions.len(), 3);
    }

    #[test]
    fn no_digits_without_include_number() {
        for _ in 0..ITERATIONS {
            let value = passphrase(&dotted(20));
            assert!(value.bytes().all(|b| !b.is_ascii_digit()));
        }
    }

    #[test]
    fn capitalize_and_number_combine() {
        let value = passphrase(&PassphraseOptions {
            capitalize: true,
            include_number: true,
            ..dotted(4)
        });
        assert!(
            value
                .split('.')
                .all(|part| part.starts_with(|c: char| c.is_ascii_uppercase()))
        );
        assert_eq!(value.bytes().filter(u8::is_ascii_digit).count(), 1);
    }

    #[test]
    fn thousand_passphrases_are_distinct() {
        let unique: HashSet<String> = (0..1000)
            .map(|_| passphrase(&PassphraseOptions::default()).to_string())
            .collect();
        assert_eq!(unique.len(), 1000);
    }

    #[test]
    fn word_choice_spreads_over_the_whole_list() {
        let list = wordlist();
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            seen.extend(passphrase(&dotted(20)).split('.').map(str::to_owned));
        }
        assert!(seen.iter().all(|word| list.contains(word.as_str())));
        // 20000 uniform draws leave about 600 of 7776 words unseen (sigma about 24); a
        // truncated index range would leave far more.
        assert!(seen.len() > 7000, "only {} distinct words", seen.len());
    }

    #[test]
    fn defaults_match_the_official_clients() {
        let options = PassphraseOptions::default();
        assert_eq!(options.words, 6);
        assert_eq!(options.separator, "-");
        assert!(!options.capitalize && !options.include_number);
    }
}
