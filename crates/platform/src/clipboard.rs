//! Copies secrets as concealed (`org.nspasteboard.ConcealedType`, excluded from history) and clears
//! them after a delay, but only if the clipboard still holds what we put there.

use std::time::Duration;

use crate::Result;

pub struct SecretClipboard;

impl SecretClipboard {
    pub fn new() -> Result<Self> {
        todo!("step 6")
    }

    /// Replaces any pending clear from a previous copy.
    pub fn copy(&self, text: &str, clear_after: Option<Duration>) -> Result<()> {
        let _ = (text, clear_after);
        todo!("step 6")
    }
}
