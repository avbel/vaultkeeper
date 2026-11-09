//! The clipboard inside the daemon. It outlives every UI process, so the auto-clear timer and the
//! digest of the last copy live here: a UI that exits or is killed cannot leave a secret behind.

use std::time::Duration;

/// The daemon's concealed clipboard with auto-clear. Both methods may block briefly on the
/// pasteboard; the server calls them on the blocking pool.
pub trait ClipboardHost: Send + Sync + 'static {
    /// Puts `text` on the clipboard and clears it after `clear_after` if it still holds it.
    /// The error text is shown to the user.
    fn copy(&self, text: &str, clear_after: Option<Duration>) -> Result<(), String>;

    /// Clears the clipboard now if it still holds the last copied value.
    fn clear_if_ours(&self);
}
