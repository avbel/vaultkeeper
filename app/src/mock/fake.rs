//! Fake value generators for the mock: not cryptographically secure, never used outside `--mock`
//! and tests.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use bwl_gen::generator::{PassphraseOptions, PasswordOptions};
use zeroize::Zeroizing;

use crate::hooks::{HookError, HookResult, PasswordGenerator, SshKeyTool};

/// SplitMix64; deterministic for a given seed.
#[derive(Debug, Clone)]
pub struct Prng(u64);

impl Prng {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-enough index below `bound` (bound > 0).
    pub fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound.max(1)).unwrap_or(u64::MAX);
        usize::try_from(self.next_u64() % bound).unwrap_or(0)
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.next_u64() % 100 < percent
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

#[must_use]
pub fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SPECIAL: &str = "!@#$%^&*";
const AMBIGUOUS: &str = "Il1O0";

const WORDS: [&str; 48] = [
    "anchor", "basil", "cobalt", "dune", "ember", "fjord", "garnet", "harbor", "iris", "juniper",
    "kelp", "lantern", "meadow", "nectar", "orbit", "pebble", "quartz", "raven", "saffron",
    "tundra", "umber", "velvet", "willow", "xenon", "yonder", "zephyr", "acorn", "breeze",
    "canyon", "drift", "echo", "falcon", "glacier", "hollow", "island", "jasper", "kindle",
    "lumen", "maple", "nimbus", "oasis", "prairie", "quill", "ridge", "summit", "timber", "upland",
    "vista",
];

/// Seeded from the clock and a counter so consecutive calls differ.
#[derive(Default)]
pub struct MockGenerator {
    counter: AtomicU64,
}

impl MockGenerator {
    fn prng(&self) -> Prng {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| u64::from(elapsed.subsec_nanos()));
        Prng::new(
            nanos
                ^ self
                    .counter
                    .fetch_add(1, Ordering::Relaxed)
                    .wrapping_mul(0x2545_F491),
        )
    }
}

fn charset(set: &str, avoid_ambiguous: bool) -> Vec<char> {
    set.chars()
        .filter(|c| !avoid_ambiguous || !AMBIGUOUS.contains(*c))
        .collect()
}

impl PasswordGenerator for MockGenerator {
    fn password(&self, options: &PasswordOptions) -> HookResult<Zeroizing<String>> {
        let sets: Vec<(Vec<char>, usize)> = [
            (options.uppercase, UPPER, 1),
            (options.lowercase, LOWER, 1),
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
        ]
        .into_iter()
        .filter(|(enabled, _, _)| *enabled)
        .map(|(_, set, minimum)| (charset(set, options.avoid_ambiguous), minimum))
        .collect();
        if sets.is_empty() {
            return Err(HookError::Failed(
                "Select at least one character set".to_owned(),
            ));
        }
        let length = usize::from(options.length.clamp(5, 128));
        let mut prng = self.prng();
        let mut chars: Vec<char> = sets
            .iter()
            .flat_map(|(set, minimum)| (0..*minimum).map(|_| *prng.pick(set)).collect::<Vec<_>>())
            .collect();
        let all: Vec<char> = sets
            .iter()
            .flat_map(|(set, _)| set.iter().copied())
            .collect();
        while chars.len() < length {
            chars.push(*prng.pick(&all));
        }
        chars.truncate(length);
        for index in (1..chars.len()).rev() {
            chars.swap(index, prng.below(index + 1));
        }
        Ok(Zeroizing::new(chars.into_iter().collect()))
    }

    fn passphrase(&self, options: &PassphraseOptions) -> HookResult<Zeroizing<String>> {
        let mut prng = self.prng();
        let count = usize::from(options.words.clamp(3, 20));
        let number_at = prng.below(count);
        let words: Vec<String> = (0..count)
            .map(|index| {
                let word = *prng.pick(&WORDS);
                let mut word = if options.capitalize {
                    let mut chars = word.chars();
                    chars.next().map_or_else(String::new, |first| {
                        first.to_uppercase().chain(chars).collect()
                    })
                } else {
                    word.to_owned()
                };
                if options.include_number && index == number_at {
                    word.push(char::from(b'0' + u8::try_from(prng.below(10)).unwrap_or(0)));
                }
                word
            })
            .collect();
        Ok(Zeroizing::new(words.join(&options.separator)))
    }
}

pub struct MockSshKeys;

impl SshKeyTool for MockSshKeys {
    fn generate(&self) -> HookResult<(Zeroizing<String>, String, String)> {
        let seed = MockGenerator::default().prng().next_u64();
        Ok(fake_ssh_key(seed, "bw-lite"))
    }
}

/// Plausible-looking but invalid OpenSSH key material.
#[must_use]
pub fn fake_ssh_key(seed: u64, comment: &str) -> (Zeroizing<String>, String, String) {
    let mut prng = Prng::new(seed);
    let blob: String = (0..43)
        .map(|_| {
            char::from(
                *prng.pick(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
            )
        })
        .collect();
    let private = format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB{blob}\n-----END OPENSSH PRIVATE KEY-----\n"
    );
    let public = format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{blob} {comment}");
    let fingerprint = format!("SHA256:{}", &blob[..43.min(blob.len())]);
    (Zeroizing::new(private), public, fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_is_deterministic() {
        let mut a = Prng::new(7);
        let mut b = Prng::new(7);
        assert_eq!(a.next_u64(), b.next_u64());
        assert_ne!(Prng::new(8).next_u64(), Prng::new(7).next_u64());
    }

    #[test]
    fn password_respects_length_and_sets() {
        let generator = MockGenerator::default();
        let options = PasswordOptions {
            length: 20,
            uppercase: false,
            lowercase: true,
            numbers: true,
            special: true,
            min_numbers: 3,
            min_special: 2,
            avoid_ambiguous: true,
        };
        let password = generator.password(&options).expect("password");
        assert_eq!(password.chars().count(), 20);
        assert!(password.chars().all(|c| !c.is_ascii_uppercase()));
        assert!(password.chars().filter(char::is_ascii_digit).count() >= 3);
        assert!(password.chars().filter(|c| SPECIAL.contains(*c)).count() >= 2);
        assert!(password.chars().all(|c| !AMBIGUOUS.contains(c)));
    }

    #[test]
    fn password_needs_a_character_set() {
        let options = PasswordOptions {
            uppercase: false,
            lowercase: false,
            numbers: false,
            special: false,
            ..PasswordOptions::default()
        };
        assert!(MockGenerator::default().password(&options).is_err());
    }

    #[test]
    fn passphrase_word_count_and_separator() {
        let options = PassphraseOptions {
            words: 4,
            separator: "_".to_owned(),
            capitalize: true,
            include_number: true,
        };
        let phrase = MockGenerator::default()
            .passphrase(&options)
            .expect("phrase");
        let words: Vec<&str> = phrase.split('_').collect();
        assert_eq!(words.len(), 4);
        assert!(
            words
                .iter()
                .all(|word| word.chars().next().is_some_and(char::is_uppercase))
        );
        assert_eq!(phrase.chars().filter(char::is_ascii_digit).count(), 1);
    }

    #[test]
    fn fake_ssh_keys_look_like_openssh() {
        let (private, public, fingerprint) = fake_ssh_key(1, "me@host");
        assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(public.starts_with("ssh-ed25519 ") && public.ends_with(" me@host"));
        assert!(fingerprint.starts_with("SHA256:"));
    }
}
