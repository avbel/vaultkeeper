//! The `xdg-activation` token that lets a new window take keyboard focus under Wayland (linux-plan
//! 3c, chain C10). One token is pending per process: the daemon holds the one a shortcut press or
//! a compositor binding brought, the UI the one the daemon forwarded. A token works once, so it is
//! taken, never copied, and `Debug` output never shows it.

use std::{
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use slint::winit_030::winit::{
    platform::startup_notify::WindowAttributesExtStartupNotify,
    window::{ActivationToken, WindowAttributes},
};
use vk_platform::single_instance::is_valid_activation_token;

const ENV_VAR: &str = "XDG_ACTIVATION_TOKEN";
/// A token that has waited longer was not meant for the window that opens now.
const TOKEN_LIFETIME: Duration = Duration::from_secs(10);

/// One token with the time it arrived.
struct Slot(Mutex<Option<(Instant, String)>>);

impl Slot {
    const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// Replaces the token; `None` and malformed tokens clear it, so a press without one never
    /// leaves the previous press's token behind for a later window.
    fn offer(&self, token: Option<String>) {
        let token = token.filter(|token| is_valid_activation_token(token));
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) =
            token.map(|token| (Instant::now(), token));
    }

    fn take(&self) -> Option<String> {
        let stored = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        take_fresh(stored, Instant::now())
    }
}

/// What the next window picks up: the daemon's token for the UI it starts, and in the UI the
/// token released for the command being handled.
static PENDING: Slot = Slot::new();
/// The UI's token between its `ActivationToken` command and the command it belongs to.
static HELD: Slot = Slot::new();

pub fn offer(token: Option<String>) {
    PENDING.offer(token);
}

#[must_use]
pub fn take() -> Option<String> {
    PENDING.take()
}

fn take_fresh(stored: Option<(Instant, String)>, now: Instant) -> Option<String> {
    stored
        .filter(|(stored, _)| now.saturating_duration_since(*stored) < TOKEN_LIFETIME)
        .map(|(_, token)| token)
}

/// The UI got a token ahead of the command it belongs to.
pub fn hold(token: String) {
    HELD.offer(Some(token));
}

/// Before a command runs: its windows may take the held token if the command opens one; any other
/// command drops it, so a token never outlives the command it was queued for.
pub fn release(opens_window: bool) {
    release_between(&HELD, &PENDING, opens_window);
}

/// After a command ran: whatever the command did not use must not reach a later window, such as an
/// SSH approval prompt.
pub fn discard() {
    PENDING.offer(None);
}

fn release_between(held: &Slot, pending: &Slot, opens_window: bool) {
    let token = held.take();
    pending.offer(token.filter(|_| opens_window));
}

/// The token a compositor binding left in this process's environment (`exec vaultkeeper
/// --search`), removed from it so no child inherits it but the UI the daemon hands it to on
/// purpose.
#[must_use]
pub fn take_from_environment() -> Option<String> {
    let token = std::env::var(ENV_VAR).ok();
    // SAFETY: called at the start of `daemon::run`, before the runtime, the single-instance
    // listener and the event loop start threads that could read the environment.
    unsafe { std::env::remove_var(ENV_VAR) };
    token.filter(|token| is_valid_activation_token(token))
}

/// Window-attribute hook for the UI's windows: the window created next carries the pending token,
/// which winit hands to the compositor when it maps the window.
#[must_use]
pub fn attach_pending(attributes: WindowAttributes) -> WindowAttributes {
    match take() {
        Some(token) => attributes.with_activation_token(ActivationToken::from_raw(token)),
        None => attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_token_is_taken_once() {
        let now = Instant::now();
        let stored = Some((now, "tok".to_owned()));
        assert_eq!(take_fresh(stored, now), Some("tok".to_owned()));
        assert_eq!(take_fresh(None, now), None);
    }

    #[test]
    fn a_token_that_waited_too_long_is_dropped() {
        let stored = Instant::now();
        let late = stored + TOKEN_LIFETIME;
        assert_eq!(take_fresh(Some((stored, "tok".to_owned())), late), None);
    }

    #[test]
    fn offering_replaces_or_clears_and_taking_empties() {
        let slot = Slot::new();
        slot.offer(Some("first".to_owned()));
        slot.offer(Some("second".to_owned()));
        assert_eq!(slot.take(), Some("second".to_owned()));
        assert_eq!(slot.take(), None);
        slot.offer(Some("stale".to_owned()));
        slot.offer(None);
        assert_eq!(slot.take(), None);
        slot.offer(Some("has space".to_owned()));
        assert_eq!(slot.take(), None);
    }

    #[test]
    fn the_held_token_goes_to_a_window_command_only() {
        let (held, pending) = (Slot::new(), Slot::new());
        held.offer(Some("tok".to_owned()));
        release_between(&held, &pending, true);
        assert_eq!(pending.take(), Some("tok".to_owned()));
        assert_eq!(held.take(), None, "released once");

        held.offer(Some("tok".to_owned()));
        release_between(&held, &pending, false);
        assert_eq!(
            pending.take(),
            None,
            "a command that opens no window drops it"
        );
        assert_eq!(held.take(), None);
    }

    #[test]
    fn a_command_without_a_held_token_clears_the_pending_one() {
        let (held, pending) = (Slot::new(), Slot::new());
        pending.offer(Some("leftover".to_owned()));
        release_between(&held, &pending, true);
        assert_eq!(pending.take(), None);
    }
}
