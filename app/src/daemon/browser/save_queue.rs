//! Bounded, short-lived save candidates held while a vault is locked.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use super::dispatch::Candidate;

const MAX_PENDING: usize = 3;
const LIFETIME: Duration = Duration::from_mins(10);

struct Pending {
    received: Instant,
    candidate: Candidate,
}

/// A queue belongs to one account and must not survive a logout or account change.
/// Its owner must schedule `expire` at `next_expiry`, even when no requests arrive.
pub struct SaveQueue {
    account: String,
    pending: VecDeque<Pending>,
}

impl SaveQueue {
    #[must_use]
    pub fn new(account: String) -> Self {
        Self {
            account,
            pending: VecDeque::new(),
        }
    }

    /// Reject new entries when full; dropping the rejected value wipes its password.
    pub fn push(&mut self, account: &str, candidate: Candidate, now: Instant) -> bool {
        if self.account != account {
            self.pending.clear();
            return false;
        }
        self.expire(now);
        if self.pending.len() >= MAX_PENDING {
            return false;
        }
        self.pending.push_back(Pending {
            received: now,
            candidate,
        });
        true
    }

    /// A changed account discards all pending candidates rather than returning them.
    pub fn take(&mut self, account: &str, now: Instant) -> Vec<Candidate> {
        if self.account != account {
            self.pending.clear();
            return Vec::new();
        }
        self.expire(now);
        self.pending
            .drain(..)
            .map(|entry| entry.candidate)
            .collect()
    }

    pub fn clear(&mut self) {
        self.pending.clear();
    }

    #[must_use]
    pub fn next_expiry(&self) -> Option<Instant> {
        self.pending
            .iter()
            .filter_map(|entry| entry.received.checked_add(LIFETIME))
            .min()
    }

    pub fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|entry| now.saturating_duration_since(entry.received) < LIFETIME);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_ipc::browser::protocol::SaveKind;
    use zeroize::Zeroizing;

    fn candidate() -> Candidate {
        Candidate {
            browser: "Firefox".into(),
            origin: "https://example.com".into(),
            path: "/".into(),
            username: "user".into(),
            password: Zeroizing::new("secret".into()),
            kind: SaveKind::Login,
        }
    }

    #[test]
    fn bounds_expiry_and_account() {
        let now = Instant::now();
        let mut queue = SaveQueue::new("account-a".into());
        for _ in 0..3 {
            assert!(queue.push("account-a", candidate(), now));
        }
        assert!(!queue.push("account-a", candidate(), now));
        assert_eq!(
            queue
                .take("account-a", now + Duration::from_secs(599))
                .len(),
            3
        );
        assert!(queue.push("account-a", candidate(), now));
        assert!(queue.take("account-a", now + LIFETIME).is_empty());
        assert!(queue.push("account-a", candidate(), now));
        assert!(queue.take("account-b", now).is_empty());
        assert!(queue.take("account-a", now).is_empty());
        assert!(queue.push("account-a", candidate(), now));
        assert!(!queue.push("account-b", candidate(), now));
        assert!(queue.take("account-a", now).is_empty());
    }
}
