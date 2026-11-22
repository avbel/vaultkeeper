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

#[cfg(not(target_os = "linux"))]
use crate::Error;
use crate::Result;

#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{Capabilities, LinkKind, PortalClipboard};

type Digest = [u8; 32];

/// How often the clearer looks again while a copy holds the backend.
const COPY_IN_FLIGHT_RECHECK: Duration = Duration::from_millis(100);
/// A read or clear that failed (the data-control read timeout, a compositor or X11 error) is
/// tried again this soon, because a failed clear leaves the secret on the clipboard.
const CLEAR_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Bounds the retries, so a clipboard that is broken for good does not keep the clearer busy.
const MAX_CLEAR_RETRIES: u32 = 5;

/// What [`SecretClipboard`] needs from a clipboard; [`SystemClipboard`] in production.
pub trait ClipboardBackend: Send + 'static {
    /// Puts `text` on the clipboard, excluded from clipboard history where the OS allows it.
    fn set_secret(&mut self, text: &str) -> Result<()>;
    /// `None` when the clipboard is empty or holds something other than text.
    fn text(&mut self) -> Result<Option<Zeroizing<String>>>;
    fn clear(&mut self) -> Result<()>;
}

/// The general pasteboard: arboard on macOS and Windows, the clipboard chain on Linux.
pub struct SystemClipboard {
    #[cfg(any(target_os = "macos", windows))]
    inner: arboard::Clipboard,
    #[cfg(target_os = "linux")]
    inner: linux::LinuxClipboard,
}

impl SystemClipboard {
    pub fn new() -> Result<Self> {
        #[cfg(any(target_os = "macos", windows))]
        {
            Ok(Self {
                inner: arboard::Clipboard::new().map_err(|err| clipboard_error(&err))?,
            })
        }
        #[cfg(target_os = "linux")]
        {
            Self::with_portal(None)
        }
        #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
        {
            Err(Error::Unsupported)
        }
    }

    /// Probes the links and uses the strongest that works; `portal` is the GNOME link the app
    /// provides.
    #[cfg(target_os = "linux")]
    pub fn with_portal(portal: Option<Box<dyn PortalClipboard>>) -> Result<Self> {
        Ok(Self {
            inner: linux::open(portal)?,
        })
    }

    /// Which link is active and why the others were skipped.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub const fn chain_report(&self) -> &crate::security::ChainReport {
        self.inner.report()
    }
}

#[cfg(any(target_os = "macos", windows))]
fn clipboard_error(err: &arboard::Error) -> Error {
    Error::Clipboard(err.to_string())
}

#[cfg(any(target_os = "macos", windows))]
impl ClipboardBackend for SystemClipboard {
    fn set_secret(&mut self, text: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            use arboard::SetExtApple as _;

            self.inner
                .set()
                .exclude_from_history()
                .text(text)
                .map_err(|err| clipboard_error(&err))
        }
        // Every marker, not only `ExcludeClipboardContentFromMonitorProcessing`: older builds and
        // third-party clipboard managers honour different subsets (§7.4).
        #[cfg(windows)]
        {
            use arboard::SetExtWindows as _;

            let result = self
                .inner
                .set()
                .exclude_from_monitoring()
                .exclude_from_cloud()
                .exclude_from_history()
                .text(text);
            if let Err(err) = result {
                // The text may already be on the clipboard without its exclusion markers, where
                // history and cloud sync would pick it up.
                let ours = digest(text);
                let _ = clear_if_holds(self, &ours);
                return Err(clipboard_error(&err));
            }
            Ok(())
        }
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

#[cfg(target_os = "linux")]
impl ClipboardBackend for SystemClipboard {
    fn set_secret(&mut self, text: &str) -> Result<()> {
        self.inner.set_secret(text)
    }

    fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
        self.inner.text()
    }

    fn clear(&mut self) -> Result<()> {
        self.inner.clear()
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
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
    failed_clears: u32,
}

impl Schedule {
    /// A copy replaces whatever was pending; `None` means "keep until replaced".
    fn copied(&mut self, text: &str, clear_after: Option<Duration>, now: Now) {
        self.last_copied = Some(digest(text));
        self.deadline = clear_after.and_then(|after| Deadline::after(now, after));
        self.failed_clears = 0;
    }

    /// Puts back a clear that failed so it is tried again shortly; `false` once the retries are
    /// used up, leaving nothing pending.
    fn retry_after_failure(&mut self, ours: Digest, now: Now) -> bool {
        if self.failed_clears >= MAX_CLEAR_RETRIES {
            return false;
        }
        self.failed_clears += 1;
        self.last_copied = Some(ours);
        self.deadline = Deadline::after(now, CLEAR_RETRY_DELAY);
        self.deadline.is_some()
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
    /// Taken out while a copy is in flight: a copy can wait on a permission dialog (the GNOME
    /// portal), and lock-time clears must not queue behind it.
    backend: Option<B>,
    /// A clear was asked for while a copy was in flight; the copy clears itself when it lands.
    clear_requested: bool,
    schedule: Schedule,
    shutdown: bool,
}

struct Shared<B> {
    state: Mutex<State<B>>,
    wake: Condvar,
    /// Signalled when an in-flight copy hands the backend back.
    idle: Condvar,
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
                backend: Some(backend),
                clear_requested: false,
                schedule: Schedule::default(),
                shutdown: false,
            }),
            wake: Condvar::new(),
            idle: Condvar::new(),
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
    ///
    /// The lock is not held while the backend copies. A [`Self::clear_if_ours`] that arrives
    /// meanwhile is applied as soon as the copy lands.
    pub fn copy(&self, text: &str, clear_after: Option<Duration>) -> Result<()> {
        let mut held = self.take_backend();
        let result = held.get().set_secret(text);
        let mut state = self.shared.lock();
        let clear_requested = std::mem::take(&mut state.clear_requested);
        if result.is_ok() {
            state.schedule.copied(text, clear_after, self.shared.now());
        }
        if clear_requested && let Some(ours) = state.schedule.take_now() {
            let now = self.shared.now();
            log_clear(&clear_or_retry(held.get(), &mut state.schedule, ours, now));
        }
        held.restore(&mut state);
        drop(state);
        self.shared.idle.notify_all();
        self.shared.wake.notify_one();
        result
    }

    fn take_backend(&self) -> HeldBackend<'_, B> {
        let mut state = self.shared.lock();
        loop {
            if let Some(backend) = state.backend.take() {
                state.clear_requested = false;
                return HeldBackend {
                    shared: &self.shared,
                    backend: Some(backend),
                };
            }
            state = self
                .shared
                .idle
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Clears the clipboard now if it still holds our last copy and cancels the pending clear.
    /// Returns whether it cleared; while a copy is in flight it is cleared when that lands.
    pub fn clear_if_ours(&self) -> Result<bool> {
        let mut guard = self.shared.lock();
        let state = &mut *guard;
        let Some(backend) = state.backend.as_mut() else {
            state.clear_requested = true;
            return Ok(false);
        };
        let Some(ours) = state.schedule.take_now() else {
            return Ok(false);
        };
        let outcome = clear_or_retry(backend, &mut state.schedule, ours, self.shared.now())?;
        Ok(outcome == ClearOutcome::Cleared)
    }

    /// Makes the clearer look at the clocks again; call it after the system woke from sleep.
    pub fn recheck(&self) {
        self.shared.wake.notify_one();
    }
}

/// The backend while a copy has it. Dropping it, as an unwinding panic in the backend does,
/// hands it back; otherwise later copies would wait for it forever.
struct HeldBackend<'a, B> {
    shared: &'a Shared<B>,
    backend: Option<B>,
}

impl<B> HeldBackend<'_, B> {
    fn get(&mut self) -> &mut B {
        self.backend
            .as_mut()
            .expect("the backend is held until restore")
    }

    fn restore(mut self, state: &mut State<B>) {
        state.backend = self.backend.take();
    }
}

impl<B> Drop for HeldBackend<'_, B> {
    fn drop(&mut self) {
        if let Some(backend) = self.backend.take() {
            self.shared.lock().backend = Some(backend);
            self.shared.idle.notify_all();
        }
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
            Some(_) if state.backend.is_none() => {
                let (state, _) = shared
                    .wake
                    .wait_timeout(state, COPY_IN_FLIGHT_RECHECK)
                    .unwrap_or_else(PoisonError::into_inner);
                state
            }
            Some(_) => {
                let pending = &mut *state;
                if let Some(ours) = pending.schedule.take_due(now)
                    && let Some(backend) = pending.backend.as_mut()
                {
                    log_clear(&clear_or_retry(backend, &mut pending.schedule, ours, now));
                }
                state
            }
        };
    }
    // A secret with a pending clear must not outlive the app.
    if state.schedule.next_deadline().is_some()
        && let Some(ours) = state.schedule.take_now()
        && let Some(backend) = state.backend.as_mut()
    {
        clear_logged(backend, &ours);
    }
}

fn clear_logged(backend: &mut impl ClipboardBackend, ours: &Digest) {
    log_clear(&clear_if_holds(backend, ours));
}

/// The lock must be held across the take that produced `ours` and this call, so a copy landing
/// in between cannot have its fresh schedule overwritten by the retry.
fn clear_or_retry(
    backend: &mut impl ClipboardBackend,
    schedule: &mut Schedule,
    ours: Digest,
    now: Now,
) -> Result<ClearOutcome> {
    let result = clear_if_holds(backend, &ours);
    if result.is_err() && !schedule.retry_after_failure(ours, now) {
        tracing::error!("gave up clearing the clipboard after repeated failures");
    }
    result
}

fn log_clear(result: &Result<ClearOutcome>) {
    match result {
        Ok(ClearOutcome::Cleared) => tracing::debug!("cleared copied secret from clipboard"),
        Ok(ClearOutcome::NotOurs) => tracing::debug!("clipboard changed since copy; left as is"),
        Err(err) => tracing::warn!(error = %err, "could not clear clipboard"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[derive(Clone, Default)]
    struct FakeClipboard {
        content: Arc<Mutex<Option<String>>>,
        fail_set: bool,
        /// How many reads fail before reads work again.
        failing_reads: Arc<Mutex<usize>>,
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
            let mut failing = self.failing_reads.lock().expect("fake lock");
            if *failing > 0 {
                *failing -= 1;
                return Err(Error::Clipboard(
                    "the clipboard owner did not answer".into(),
                ));
            }
            drop(failing);
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

    /// Prints what the probes find in the current session:
    /// `cargo test -p vk-platform live_chain_report -- --ignored --nocapture`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "probes the real session"]
    #[allow(
        clippy::print_stdout,
        reason = "the output is the point of this manual probe"
    )]
    fn live_chain_report() {
        let clipboard = SystemClipboard::new().expect("a clipboard link");
        println!("{:#?}", clipboard.chain_report());
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
    fn a_failed_clear_is_retried_soon_and_given_up_after_the_bound() {
        let t0 = start();
        let mut schedule = Schedule::default();
        schedule.copied("hunter2", Some(THIRTY_SECONDS), t0);
        let ours = schedule.take_due(later(t0, 30)).expect("due");
        for attempt in 0..MAX_CLEAR_RETRIES {
            let now = later(t0, 31 + u64::from(attempt));
            assert!(schedule.retry_after_failure(ours, now), "retry {attempt}");
            assert_eq!(
                schedule
                    .next_deadline()
                    .map(|deadline| deadline.remaining(now)),
                Some(CLEAR_RETRY_DELAY)
            );
            assert_eq!(schedule.take_due(later(now, 1)), Some(ours));
        }
        assert!(!schedule.retry_after_failure(ours, later(t0, 60)));
        assert_eq!(schedule.next_deadline(), None);
    }

    #[test]
    fn a_new_copy_resets_the_retry_bound() {
        let t0 = start();
        let mut schedule = Schedule::default();
        for _ in 0..MAX_CLEAR_RETRIES {
            assert!(schedule.retry_after_failure(digest("first"), t0));
        }
        schedule.copied("second", Some(THIRTY_SECONDS), t0);
        assert!(schedule.retry_after_failure(digest("second"), t0));
    }

    #[test]
    fn a_clear_whose_read_failed_is_retried_by_the_clearer() {
        let fake = FakeClipboard::default();
        *fake.failing_reads.lock().expect("fake lock") = 1;
        let clipboard = SecretClipboard::with_backend(fake.clone()).expect("clipboard");
        clipboard.copy("hunter2", Some(SHORT)).expect("copy");
        assert!(
            wait_until(|| fake.content().is_none()),
            "the secret stayed on the clipboard after one failed read"
        );
    }

    #[test]
    fn a_failed_clear_if_ours_reports_the_error_and_still_clears_later() {
        let fake = FakeClipboard::default();
        let clipboard = SecretClipboard::with_backend(fake.clone()).expect("clipboard");
        clipboard.copy("hunter2", None).expect("copy");
        *fake.failing_reads.lock().expect("fake lock") = 1;
        assert!(clipboard.clear_if_ours().is_err());
        assert!(
            wait_until(|| fake.content().is_none()),
            "the lock-time clear was dropped after one failed read"
        );
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

    struct GatedFake {
        inner: FakeClipboard,
        entered: std::sync::mpsc::Sender<()>,
        gate: std::sync::mpsc::Receiver<()>,
    }

    impl ClipboardBackend for GatedFake {
        fn set_secret(&mut self, text: &str) -> Result<()> {
            self.entered.send(()).expect("test is listening");
            self.gate.recv().expect("test opens the gate");
            self.inner.set_secret(text)
        }

        fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
            self.inner.text()
        }

        fn clear(&mut self) -> Result<()> {
            self.inner.clear()
        }
    }

    #[test]
    fn a_clear_during_a_slow_copy_does_not_wait_and_wins_when_the_copy_lands() {
        let fake = FakeClipboard::default();
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let (open, gate) = std::sync::mpsc::channel();
        let clipboard = SecretClipboard::with_backend(GatedFake {
            inner: fake.clone(),
            entered,
            gate,
        })
        .expect("clipboard");
        std::thread::scope(|scope| {
            let copy = scope.spawn(|| clipboard.copy("hunter2", Some(THIRTY_SECONDS)));
            entered_rx.recv().expect("copy started");
            assert!(!clipboard.clear_if_ours().expect("returns at once"));
            open.send(()).expect("open gate");
            copy.join().expect("copy thread").expect("copy");
        });
        assert_eq!(fake.content(), None);
        assert_eq!(clipboard.shared.lock().schedule.next_deadline(), None);
    }

    struct PanicsOnce {
        inner: FakeClipboard,
        armed: bool,
    }

    impl ClipboardBackend for PanicsOnce {
        fn set_secret(&mut self, text: &str) -> Result<()> {
            assert!(!std::mem::take(&mut self.armed), "backend panicked");
            self.inner.set_secret(text)
        }

        fn text(&mut self) -> Result<Option<Zeroizing<String>>> {
            self.inner.text()
        }

        fn clear(&mut self) -> Result<()> {
            self.inner.clear()
        }
    }

    #[test]
    fn a_panicking_backend_is_handed_back_for_the_next_copy() {
        let fake = FakeClipboard::default();
        let clipboard = SecretClipboard::with_backend(PanicsOnce {
            inner: fake.clone(),
            armed: true,
        })
        .expect("clipboard");
        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            clipboard.copy("hunter2", Some(SHORT))
        }));
        assert!(first.is_err());
        clipboard
            .copy("second", Some(SHORT))
            .expect("copy after the panic");
        assert!(
            wait_until(|| fake.content().is_none()),
            "the clearer still works"
        );
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
