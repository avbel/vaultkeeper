//! Secret-free, bounded duplicate detection for save candidates.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const WINDOW: Duration = Duration::from_mins(10);
const MAX_ENTRIES: usize = 1024;

pub struct SaveDedupe {
    key: Zeroizing<[u8; 32]>,
    seen: VecDeque<(Instant, [u8; 32])>,
}

impl Default for SaveDedupe {
    fn default() -> Self {
        Self {
            key: Zeroizing::new(rand::random()),
            seen: VecDeque::new(),
        }
    }
}

impl SaveDedupe {
    /// True means this candidate is new and may proceed. When the table is full, fail closed.
    pub fn admit(&mut self, origin: &str, username: &str, password: &str, now: Instant) -> bool {
        self.seen
            .retain(|(seen, _)| now.saturating_duration_since(*seen) < WINDOW);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.key.as_ref())
            .expect("HMAC accepts keys of any size");
        mac.update(origin.as_bytes());
        mac.update(&[0]);
        mac.update(username.as_bytes());
        mac.update(&[0]);
        mac.update(password.as_bytes());
        let digest: [u8; 32] = mac.finalize().into_bytes().into();
        if self.seen.iter().any(|(_, hash)| *hash == digest) || self.seen.len() == MAX_ENTRIES {
            return false;
        }
        self.seen.push_back((now, digest));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deduplicates_and_expires() {
        let now = Instant::now();
        let mut dedupe = SaveDedupe::default();
        assert!(dedupe.admit("https://example.com", "user", "secret", now));
        assert!(!dedupe.admit("https://example.com", "user", "secret", now));
        assert!(dedupe.admit("https://example.com", "user", "different", now));
        assert!(dedupe.admit("https://other.example", "user", "secret", now));
        assert!(dedupe.admit("https://example.com", "user", "secret", now + WINDOW));
    }

    #[test]
    fn capacity_fails_closed_until_entries_expire() {
        let now = Instant::now();
        let mut dedupe = SaveDedupe::default();
        for n in 0..MAX_ENTRIES {
            assert!(dedupe.admit("https://example.com", "user", &n.to_string(), now));
        }
        assert!(!dedupe.admit("https://example.com", "user", "new", now));
        assert!(dedupe.admit("https://example.com", "user", "new", now + WINDOW));
    }
}
