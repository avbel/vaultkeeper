//! Copies secrets as concealed (`org.nspasteboard.ConcealedType`, excluded from history) and clears
//! them after a delay, but only if the clipboard still holds what we put there.
//!
//! Only a SHA-256 of the last copied text is kept. One background thread per [`SecretClipboard`]
//! sleeps until the next deadline; it never polls.
//!
//! A clear is due when either the monotonic or the wall clock passed its deadline: the monotonic
//! clock stops while the Mac sleeps and the wall clock can be set back, and clearing early is
//! harmless where clearing late is the defect. Call [`SecretClipboard::recheck`] on wake, because
//! the sleeping thread's timeout does not advance during system sleep either.

use std::{
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime},
};

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

type Digest = [u8; 32];

/// What [`SecretClipboard`] needs from a clipboard; [`SystemClipboard`] in production.
pub trait ClipboardBackend: Send + 'static {
    /// Puts `text` on the clipboard, excluded from clipboard history where the OS allows it.
    fn set_secret(&mut self, text: &str) -> Result<()>;
    /// `None` when the clipboard is empty or holds something other than text.
    fn text(&mut self) -> Result<Option<Zeroizing<String>>>;
    fn clear(&mut self) -> Result<()>;
}

/// The general pasteboard via arboard (macOS only).
pub struct SystemClipboard {
    #[cfg(target_os = "macos")]
    inner: arboard::Clipboard,
}

impl SystemClipboard {
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                inner: arboard::Clipboard::new().map_err(|err| clipboard_error(&err))?,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(Error::Unsupported)
        }
    }
}

#[cfg(target_os = "macos")]
fn clipboard_error(err: &arboard::Error) -> Error {
    Error::Clipboard(err.to_string())
}

#[cfg(target_os = "macos")]
impl ClipboardBackend for SystemClipboard {
    fn set_secret(&mut self, text: &str) -> Result<()> {
        use arboard::SetExtApple as _;

        self.inner
            .set()
            .exclude_from_history()
            .text(text)
            .map_err(|err| clipboard_error(&err))
    }

    fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
        match self.inner.get_text() {
            Ok(text) => Ok(Some(Zeroizing::new(text))),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(err) => Err(clipboard_error(&err)),
        }
    }

    fn clear(&mut self) -> Result<()> {
        self.inner.clear().map_err(|err| clipboard_error(&err))
    }
}

#[cfg(not(target_os = "macos"))]
impl ClipboardBackend for SystemClipboard {
    fn set_secret(&mut self, _text: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
        Err(Error::Unsupported)
    }

    fn clear(&mut self) -> Result<()> {
        Err(Error::Unsupported)
    }
}

fn digest(text: &str) -> Digest {
    Sha256::digest(text.as_bytes()).into()
}

/// Both clocks at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Now {
    monotonic: Instant,
    wall: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Deadline {
    monotonic: Instant,
    wall: SystemTime,
}

impl Deadline {
    fn after(now: Now, delay: Duration) -> Option<Self> {
        Some(Self {
            monotonic: now.monotonic.checked_add(delay)?,
            wall: now.wall.checked_add(delay)?,
        })
    }

    fn passed(&self, now: Now) -> bool {
        self.monotonic <= now.monotonic || self.wall <= now.wall
    }

    /// The shorter of the two remaining waits; zero once passed.
    fn remaining(&self, now: Now) -> Duration {
        let monotonic = self.monotonic.saturating_duration_since(now.monotonic);
        let wall = self.wall.duration_since(now.wall).unwrap_or_default();
        monotonic.min(wall)
    }
}

/// The last value we copied and when to clear it. Pure, so tests drive it with explicit instants.
#[derive(Debug, Default)]
struct Schedule {
    last_copied: Option<Digest>,
    deadline: Option<Deadline>,
}

impl Schedule {
    /// A copy replaces whatever was pending; `None` means "keep until replaced".
    fn copied(&mut self, text: &str, clear_after: Option<Duration>, now: Now) {
        self.last_copied = Some(digest(text));
        self.deadline = clear_after.and_then(|after| Deadline::after(now, after));
    }

    const fn next_deadline(&self) -> Option<Deadline> {
        self.deadline
    }

    /// The digest to clear if the deadline has passed.
    fn take_due(&mut self, now: Now) -> Option<Digest> {
        if self.deadline.is_some_and(|deadline| deadline.passed(now)) {
            return self.take_now();
        }
        None
    }

    /// Cancels the pending clear and returns the digest to clear immediately.
    const fn take_now(&mut self) -> Option<Digest> {
        self.deadline = None;
        self.last_copied.take()
    }
}

/// The wall clock; tests substitute one they can move forward without waiting.
pub type WallClock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClearOutcome {
    Cleared,
    NotOurs,
}

fn clear_if_holds(backend: &mut impl ClipboardBackend, ours: &Digest) -> Result<ClearOutcome> {
    let holds_ours = backend.text()?.is_some_and(|text| digest(&text) == *ours);
    if !holds_ours {
        return Ok(ClearOutcome::NotOurs);
    }
    backend.clear()?;
    Ok(ClearOutcome::Cleared)
}

struct State<B> {
    backend: B,
    schedule: Schedule,
    shutdown: bool,
}

struct Shared<B> {
    state: Mutex<State<B>>,
    wake: Condvar,
    wall: WallClock,
}

impl<B> Shared<B> {
    fn lock(&self) -> MutexGuard<'_, State<B>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn now(&self) -> Now {
        Now {
            monotonic: Instant::now(),
            wall: (self.wall)(),
        }
    }
}

pub struct SecretClipboard<B: ClipboardBackend = SystemClipboard> {
    shared: Arc<Shared<B>>,
    clearer: Option<JoinHandle<()>>,
}

impl SecretClipboard {
    pub fn new() -> Result<Self> {
        Self::with_backend(SystemClipboard::new()?)
    }
}

impl<B: ClipboardBackend> SecretClipboard<B> {
    pub fn with_backend(backend: B) -> Result<Self> {
        Self::with_clock(backend, Arc::new(SystemTime::now))
    }

    pub fn with_clock(backend: B, wall: WallClock) -> Result<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                backend,
                schedule: Schedule::default(),
                shutdown: false,
            }),
            wake: Condvar::new(),
            wall,
        });
        let worker = Arc::clone(&shared);
        let clearer = std::thread::Builder::new()
            .name("vk-clipboard".into())
            .spawn(move || run_clearer(&worker))?;
        Ok(Self {
            shared,
            clearer: Some(clearer),
        })
    }

    /// Replaces any pending clear from a previous copy. With `clear_after = None` the text stays
    /// until replaced or until [`Self::clear_if_ours`].
    pub fn copy(&self, text: &str, clear_after: Option<Duration>) -> Result<()> {
        let mut state = self.shared.lock();
        state.backend.set_secret(text)?;
        state.schedule.copied(text, clear_after, self.shared.now());
        drop(state);
        self.shared.wake.notify_one();
        Ok(())
    }

    /// Clears the clipboard now if it still holds our last copy and cancels the pending clear.
    /// Returns whether it cleared.
    pub fn clear_if_ours(&self) -> Result<bool> {
        let mut state = self.shared.lock();
        let Some(ours) = state.schedule.take_now() else {
            return Ok(false);
        };
        let outcome = clear_if_holds(&mut state.backend, &ours)?;
        Ok(outcome == ClearOutcome::Cleared)
    }

    /// Makes the clearer look at the clocks again; call it after the system woke from sleep.
    pub fn recheck(&self) {
        self.shared.wake.notify_one();
    }
}

impl<B: ClipboardBackend> Drop for SecretClipboard<B> {
    fn drop(&mut self) {
        self.shared.lock().shutdown = true;
        self.shared.wake.notify_one();
        if let Some(clearer) = self.clearer.take()
            && clearer.join().is_err()
        {
            tracing::error!("clipboard clearer thread panicked");
        }
    }
}

fn run_clearer<B: ClipboardBackend>(shared: &Shared<B>) {
    let mut state = shared.lock();
    while !state.shutdown {
        let now = shared.now();
        state = match state.schedule.next_deadline() {
            None => shared
                .wake
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner),
            Some(deadline) if !deadline.passed(now) => {
                let (state, _) = shared
                    .wake
                    .wait_timeout(state, deadline.remaining(now))
                    .unwrap_or_else(PoisonError::into_inner);
                state
            }
            Some(_) => {
                if let Some(ours) = state.schedule.take_due(now) {
                    clear_logged(&mut state.backend, &ours);
                }
                state
            }
        };
    }
    // A secret with a pending clear must not outlive the app.
    if state.schedule.next_deadline().is_some()
        && let Some(ours) = state.schedule.take_now()
    {
        clear_logged(&mut state.backend, &ours);
    }
}

fn clear_logged(backend: &mut impl ClipboardBackend, ours: &Digest) {
    match clear_if_holds(backend, ours) {
        Ok(ClearOutcome::Cleared) => tracing::debug!("cleared copied secret from clipboard"),
        Ok(ClearOutcome::NotOurs) => tracing::debug!("clipboard changed since copy; left as is"),
        Err(err) => tracing::warn!(error = %err, "could not clear clipboard"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct FakeClipboard {
        content: Arc<Mutex<Option<String>>>,
        fail_set: bool,
    }

    impl FakeClipboard {
        fn content(&self) -> Option<String> {
            self.content.lock().expect("fake lock").clone()
        }

        fn user_copies(&self, text: &str) {
            *self.content.lock().expect("fake lock") = Some(text.to_owned());
        }
    }

    impl ClipboardBackend for FakeClipboard {
        fn set_secret(&mut self, text: &str) -> Result<()> {
            if self.fail_set {
                return Err(Error::Clipboard("pasteboard refused".into()));
            }
            self.user_copies(text);
            Ok(())
        }

        fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
            Ok(self.content().map(Zeroizing::new))
        }

        fn clear(&mut self) -> Result<()> {
            *self.content.lock().expect("fake lock") = None;
            Ok(())
        }
    }

    const THIRTY_SECONDS: Duration = Duration::from_secs(30);
    const SHORT: Duration = Duration::from_millis(20);

    fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
        let give_up = Instant::now() + Duration::from_secs(5);
        while Instant::now() < give_up {
            if condition() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        condition()
    }

    fn start() -> Now {
        Now {
            monotonic: Instant::now(),
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_762_600_000),
        }
    }

    /// Both clocks moved on by `seconds`.
    fn later(now: Now, seconds: u64) -> Now {
        let by = Duration::from_secs(seconds);
        Now {
            monotonic: now.monotonic + by,
            wall: now.wall + by,
        }
    }

    /// The daemon copies from a blocking-pool thread, not a main thread. Touches the real
    /// pasteboard, so it only runs on request:
    /// `cargo test -p vk-platform real_pasteboard -- --ignored` (save your clipboard first).
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "uses the real pasteboard"]
    fn real_pasteboard_copy_and_clear_from_worker_threads() {
        let probe = "vaultkeeper clipboard probe";
        let clipboard = std::thread::spawn(move || {
            let clipboard = SecretClipboard::new().expect("pasteboard");
            clipboard
                .copy(probe, Some(Duration::from_millis(300)))
                .expect("copy");
            clipboard
        })
        .join()
        .expect("copy thread");
        let mut reader = SystemClipboard::new().expect("pasteboard");
        assert_eq!(
            reader.text().expect("read").as_deref().map(String::as_str),
            Some(probe)
        );
        assert!(
            wait_until(|| reader.text().expect("read").is_none()),
            "cleared by the clearer thread"
        );
        drop(clipboard);
    }

    #[test]
    fn schedule_is_due_exactly_at_the_deadline() {
        let t0 = start();
        let mut schedule = Schedule::default();
        schedule.copied("hunter2", Some(THIRTY_SECONDS), t0);
        assert_eq!(
            schedule
                .next_deadline()
                .map(|deadline| deadline.remaining(t0)),
            Some(THIRTY_SECONDS)
        );
        assert_eq!(schedule.take_due(later(t0, 29)), None);
        assert_eq!(schedule.take_due(later(t0, 30)), Some(digest("hunter2")));
        assert_eq!(schedule.next_deadline(), None);
        assert_eq!(schedule.take_due(later(t0, 60)), None);
    }

    #[test]
    fn time_asleep_counts_although_the_monotonic_clock_stood_still() {
        let t0 = start();
        let mut schedule = Schedule::default();
        schedule.copied("hunter2", Some(THIRTY_SECONDS), t0);
        let after_an_hour_asleep = Now {
            monotonic: t0.monotonic + Duration::from_secs(1),
            wall: t0.wall + Duration::from_secs(3600),
        };
        assert_eq!(
            schedule.take_due(after_an_hour_asleep),
            Some(digest("hunter2"))
        );
    }

    #[test]
    fn a_wall_clock_set_back_does_not_postpone_the_clear() {
        let t0 = start();
        let mut schedule = Schedule::default();
        schedule.copied("hunter2", Some(THIRTY_SECONDS), t0);
        let clock_set_back_an_hour = Now {
            monotonic: t0.monotonic + THIRTY_SECONDS,
            wall: t0.wall - Duration::from_secs(3600),
        };
        let deadline = schedule.next_deadline().expect("pending");
        assert_eq!(
            deadline.remaining(Now {
                monotonic: t0.monotonic + Duration::from_secs(10),
                ..clock_set_back_an_hour
            }),
            Duration::from_secs(20),
            "waits for the shorter clock"
        );
        assert_eq!(
            schedule.take_due(clock_set_back_an_hour),
            Some(digest("hunter2"))
        );
    }

    #[test]
    fn a_new_copy_replaces_the_pending_clear() {
        let t0 = start();
        let mut schedule = Schedule::default();
        schedule.copied("first", Some(THIRTY_SECONDS), t0);
        schedule.copied("second", Some(THIRTY_SECONDS), later(t0, 10));
        assert_eq!(schedule.take_due(later(t0, 30)), None);
        assert_eq!(schedule.take_due(later(t0, 40)), Some(digest("second")));
    }

    #[test]
    fn a_copy_without_timeout_cancels_the_pending_clear() {
        let t0 = start();
        let mut schedule = Schedule::default();
        schedule.copied("first", Some(THIRTY_SECONDS), t0);
        schedule.copied("second", None, t0);
        assert_eq!(schedule.next_deadline(), None);
        assert_eq!(schedule.take_due(later(t0, 3600)), None);
        assert_eq!(schedule.take_now(), Some(digest("second")));
    }

    #[test]
    fn digest_is_sha256_of_the_text() {
        // FIPS 180-2 appendix B.1 test vector.
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let expected: Vec<u8> = (0..expected.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).expect("hex"))
            .collect();
        assert_eq!(digest("abc").as_slice(), expected);
    }

    #[test]
    fn clears_when_the_clipboard_still_holds_ours() {
        let mut fake = FakeClipboard::default();
        fake.user_copies("hunter2");
        assert_eq!(
            clear_if_holds(&mut fake, &digest("hunter2")).expect("clear"),
            ClearOutcome::Cleared
        );
        assert_eq!(fake.content(), None);
    }

    #[test]
    fn leaves_a_replaced_or_non_text_clipboard_alone() {
        let mut fake = FakeClipboard::default();
        fake.user_copies("something the user copied");
        assert_eq!(
            clear_if_holds(&mut fake, &digest("hunter2")).expect("clear"),
            ClearOutcome::NotOurs
        );
        assert_eq!(fake.content().as_deref(), Some("something the user copied"));

        let mut empty = FakeClipboard::default();
        assert_eq!(
            clear_if_holds(&mut empty, &digest("hunter2")).expect("clear"),
            ClearOutcome::NotOurs
        );
    }

    #[test]
    fn copied_text_is_cleared_after_the_delay() {
        let fake = FakeClipboard::default();
        let clipboard = SecretClipboard::with_backend(fake.clone()).expect("clipboard");
        clipboard.copy("hunter2", Some(SHORT)).expect("copy");
        assert_eq!(fake.content().as_deref(), Some("hunter2"));
        assert!(
            wait_until(|| fake.content().is_none()),
            "clipboard was not cleared"
        );
    }

    #[test]
    fn recheck_after_wake_clears_when_the_wall_clock_passed_the_deadline() {
        let fake = FakeClipboard::default();
        let wall = Arc::new(Mutex::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_762_600_000),
        ));
        let clock = Arc::clone(&wall);
        let clipboard = SecretClipboard::with_clock(
            fake.clone(),
            Arc::new(move || *clock.lock().expect("clock")),
        )
        .expect("clipboard");
        clipboard
            .copy("hunter2", Some(THIRTY_SECONDS))
            .expect("copy");
        *wall.lock().expect("clock") += Duration::from_secs(3600);
        clipboard.recheck();
        assert!(
            wait_until(|| fake.content().is_none()),
            "an hour asleep must clear a 30 s copy on wake"
        );
    }

    #[test]
    fn text_the_user_copied_meanwhile_survives_the_timer() {
        let fake = FakeClipboard::default();
        let clipboard = SecretClipboard::with_backend(fake.clone()).expect("clipboard");
        clipboard.copy("hunter2", Some(SHORT)).expect("copy");
        fake.user_copies("user text");
        std::thread::sleep(SHORT * 5);
        assert_eq!(fake.content().as_deref(), Some("user text"));
    }

    #[test]
    fn a_copy_without_timeout_is_not_cleared_by_the_previous_timer() {
        let fake = FakeClipboard::default();
        let clipboard = SecretClipboard::with_backend(fake.clone()).expect("clipboard");
        clipboard.copy("first", Some(SHORT)).expect("copy");
        clipboard.copy("second", None).expect("copy");
        std::thread::sleep(SHORT * 5);
        assert_eq!(fake.content().as_deref(), Some("second"));
    }

    #[test]
    fn a_failed_copy_reports_the_error() {
        let fake = FakeClipboard {
            fail_set: true,
            ..FakeClipboard::default()
        };
        let clipboard = SecretClipboard::with_backend(fake.clone()).expect("clipboard");
        assert!(matches!(
            clipboard.copy("hunter2", Some(SHORT)),
            Err(Error::Clipboard(_))
        ));
        assert_eq!(fake.content(), None);
    }

    #[test]
    fn clear_if_ours_clears_now_and_cancels_the_timer() {
        let fake = FakeClipboard::default();
        let clipboard = SecretClipboard::with_backend(fake.clone()).expect("clipboard");
        clipboard
            .copy("hunter2", Some(THIRTY_SECONDS))
            .expect("copy");
        assert!(clipboard.clear_if_ours().expect("clear"));
        assert_eq!(fake.content(), None);
        assert_eq!(clipboard.shared.lock().schedule.next_deadline(), None);
        assert!(!clipboard.clear_if_ours().expect("nothing left to clear"));
    }

    #[test]
    fn clear_if_ours_keeps_what_the_user_copied() {
        let fake = FakeClipboard::default();
        let clipboard = SecretClipboard::with_backend(fake.clone()).expect("clipboard");
        clipboard.copy("hunter2", None).expect("copy");
        fake.user_copies("user text");
        assert!(!clipboard.clear_if_ours().expect("clear"));
        assert_eq!(fake.content().as_deref(), Some("user text"));
    }

    #[test]
    fn dropping_flushes_a_pending_clear() {
        let fake = FakeClipboard::default();
        let clipboard = SecretClipboard::with_backend(fake.clone()).expect("clipboard");
        clipboard
            .copy("hunter2", Some(THIRTY_SECONDS))
            .expect("copy");
        drop(clipboard);
        assert_eq!(fake.content(), None);
    }

    #[test]
    fn dropping_keeps_a_copy_that_had_no_timeout() {
        let fake = FakeClipboard::default();
        let clipboard = SecretClipboard::with_backend(fake.clone()).expect("clipboard");
        clipboard.copy("username", None).expect("copy");
        drop(clipboard);
        assert_eq!(fake.content().as_deref(), Some("username"));
    }
}
