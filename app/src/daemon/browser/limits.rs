//! Per-connection request and cancellation limits.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(60);
const MAX_ORIGINS: usize = 20;

struct Bucket {
    tokens: f64,
    capacity: u32,
    updated: Instant,
}

impl Bucket {
    fn new(capacity: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(capacity),
            capacity,
            updated: now,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * f64::from(self.capacity) / WINDOW.as_secs_f64())
            .min(f64::from(self.capacity));
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[derive(Default)]
struct Origin {
    cancellations: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

pub struct Limits {
    fills: Bucket,
    saves: Bucket,
    app_opens: Bucket,
    origins: HashMap<String, Origin>,
}

impl Limits {
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            fills: Bucket::new(20, now),
            saves: Bucket::new(10, now),
            app_opens: Bucket::new(6, now),
            origins: HashMap::new(),
        }
    }

    pub fn fill(&mut self, origin: &str, now: Instant) -> bool {
        self.origins.retain(|_, state| {
            state
                .cancellations
                .retain(|time| now.saturating_duration_since(*time) < WINDOW);
            state.blocked_until.is_some_and(|deadline| now < deadline)
                || !state.cancellations.is_empty()
        });
        if self.origins.len() >= MAX_ORIGINS && !self.origins.contains_key(origin) {
            return false;
        }
        if self
            .origins
            .get(origin)
            .is_some_and(|state| state.blocked_until.is_some_and(|deadline| now < deadline))
        {
            return false;
        }
        self.fills.take(now)
    }

    /// Covers `open_app` and `unlock`: both put one of our windows in front of the user.
    pub fn open_app(&mut self, now: Instant) -> bool {
        self.app_opens.take(now)
    }

    pub fn save(&mut self, now: Instant) -> bool {
        self.saves.take(now)
    }

    pub fn cancelled(&mut self, origin: &str, now: Instant) {
        if !self.origins.contains_key(origin) && self.origins.len() >= MAX_ORIGINS {
            return;
        }
        let state = self.origins.entry(origin.to_owned()).or_default();
        state
            .cancellations
            .retain(|time| now.saturating_duration_since(*time) < WINDOW);
        state.cancellations.push_back(now);
        if state.cancellations.len() >= 3 {
            state.cancellations.clear();
            state.blocked_until = now.checked_add(WINDOW);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_buckets_refill_and_origin_cooldown_expires() {
        let now = Instant::now();
        let mut limits = Limits::new(now);
        for _ in 0..10 {
            assert!(limits.save(now));
        }
        assert!(!limits.save(now));
        assert!(limits.save(now + Duration::from_secs(6)));
        for _ in 0..3 {
            limits.cancelled("https://example.com", now);
        }
        assert!(!limits.fill("https://example.com", now + Duration::from_secs(59)));
        assert!(limits.fill("https://other.example", now));
        assert!(limits.fill("https://example.com", now + WINDOW));
    }

    #[test]
    fn full_origin_table_rejects_untracked_origins_until_expiry() {
        let now = Instant::now();
        let mut limits = Limits::new(now);
        for index in 0..MAX_ORIGINS {
            limits.cancelled(&format!("https://{index}.example"), now);
        }
        assert!(!limits.fill("https://new.example", now));
        assert!(limits.fill("https://new.example", now + WINDOW));
    }

    #[test]
    fn cancellation_window_excludes_expired_events() {
        let now = Instant::now();
        let mut limits = Limits::new(now);
        limits.cancelled("https://example.com", now);
        limits.cancelled("https://example.com", now + WINDOW);
        limits.cancelled("https://example.com", now + WINDOW);
        assert!(limits.fill("https://example.com", now + WINDOW));
    }
}
