//! The global shortcuts: the Quick Panel (default ⌘⇧Space, Ctrl+Shift+Space on Windows and Linux)
//! and, if set, the Generator. macOS and Windows register them through `global-hotkey`; Linux
//! asks the desktop's GlobalShortcuts portal, which owns the binding.

#[cfg(not(target_os = "linux"))]
mod global;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", test))]
mod portal_plan;

#[cfg(not(target_os = "linux"))]
pub use global::Hotkey;
#[cfg(target_os = "linux")]
pub use linux::{Hotkey, configure_system_shortcuts, take_activation_token};

#[cfg(not(target_os = "linux"))]
pub fn configure_system_shortcuts() {}
