//! Whether the GlobalShortcuts portal serves the daemon's shortcuts, as the daemon last found
//! out; the hotkey chain of the security report reads it.

use std::sync::{Mutex, PoisonError};

static STATUS: Mutex<Option<Result<(), String>>> = Mutex::new(None);

pub fn set(status: Result<(), String>) {
    *STATUS.lock().unwrap_or_else(PoisonError::into_inner) = Some(status);
}

/// `None` until the daemon has tried the portal (or in a process that never does).
pub fn get() -> Option<Result<(), String>> {
    STATUS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}
