//! Windows security helpers shared by vk-platform, vk-ipc and vk-ssh.
//!
//! The SDDL builders and pure helpers compile and are tested on every target; anything that calls
//! Win32 lives behind `cfg(windows)`, so this crate still builds on macOS.

#[cfg(windows)]
pub mod authenticode;
pub mod identity;
pub mod sddl;
pub mod spawn;

#[cfg(windows)]
mod windows;

pub use identity::ImageIdentity;

#[cfg(windows)]
pub use spawn::{Child, SpawnOptions, spawn_hardened};
#[cfg(windows)]
pub use windows::{
    SecurityDescriptor, current_session_id, current_user_sid, image_path_of_pid, process_session_id,
};
