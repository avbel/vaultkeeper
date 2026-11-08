//! Ensures one running instance; a second launch asks the first one to show its window.

use crate::Result;

/// Held for the process lifetime.
pub struct InstanceGuard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    ShowManager,
    ShowQuickPanel,
}

/// Returns the guard if we are the first instance; otherwise forwards `command` to the
/// running instance and returns [`crate::Error::AlreadyRunning`]. `on_command` runs on a
/// background thread for commands from later launches.
pub fn acquire(
    command: Command,
    on_command: impl Fn(Command) + Send + 'static,
) -> Result<InstanceGuard> {
    let _ = (command, on_command);
    todo!("step 6")
}
