//! Launch at login (LaunchAgent on macOS) with `--tray`.

use crate::Result;

pub fn set_enabled(enabled: bool) -> Result<()> {
    let _ = enabled;
    todo!("step 6")
}

pub fn is_enabled() -> Result<bool> {
    todo!("step 6")
}
