//! Daemon <-> UI process IPC.
//!
//! `vaultkeeper --daemon` owns the real vault and calls [`serve`]; the on-demand `vaultkeeper --ui`
//! process calls [`RemoteVault::connect`] and hands the [`RemoteVault`] to the Slint UI as its
//! `VaultService`.
//!
//! - **Transport:** a unix socket (mode 0600 in a 0700 directory) on Unix and a named pipe on
//!   Windows. The daemon accepts one UI process at a time and only peers running as its user
//!   from its own executable ([`SameExecutable`]).
//! - **Frames:** a u32 little-endian length (at most [`frame::MAX_FRAME_LEN`]), then a postcard
//!   body: [`protocol::UiMessage`] one way, [`protocol::DaemonMessage`] the other. Frame buffers
//!   are exactly sized `Zeroizing` vectors, and secret DTOs wipe themselves on drop.
//! - **No key material on the wire:** Touch ID enrolment and unlock run in the daemon through a
//!   [`TouchIdBackend`]; the UI never receives the user key or SSH private keys.
//! - **Clipboard:** copies go to the daemon ([`ClipboardHost`]), which owns the auto-clear timer
//!   and the "still ours" digest, so a clear survives the UI process exiting or being killed.
//! - **Site icons:** fetched and cached by the daemon ([`SiteIconHost`]), so the short-lived UI
//!   process does not refetch them every time it starts.
//! - **Calls** are multiplexed by id, so a slow sync does not hold up a search; the daemon runs
//!   up to 8 at once per connection.
//! - **Notices** ([`UiNotice`]: settings saved, user activity) go the other way without an answer,
//!   to the channel given in [`ServeOptions::with_notices`].
//! - **Latency** of a blocking round-trip (`search`, `reveal`, `totp`, `draft`), measured by
//!   `tests/latency.rs` (1000 `search` calls over 400 items, M-series Mac, 2026-11-08):
//!
//!   | build   | 1 row p50 / p99 | all 400 rows p50 / p99 |
//!   |---------|-----------------|------------------------|
//!   | release | 23 µs / 39 µs   | 142 µs / 183 µs        |
//!   | debug   | 60 µs / 76 µs   | 1.09 ms / 1.18 ms      |
//!
//!   Well inside one 60 Hz frame, so the UI thread calls them directly.

pub mod browser;
pub mod cli_access;
mod client;
mod clipboard;
#[cfg(target_os = "linux")]
pub mod daemon_check;
pub mod dto;
mod error;
pub mod frame;
mod generated;
mod peer;
#[cfg(target_os = "linux")]
pub mod pidfd;
pub mod protocol;
mod security;
mod server;
mod site_icons;
mod touch_id;
pub mod transport;

pub use client::{BrowserPromptEvent, EventStream, RemoteVault, SshApproval, UiEvent};
pub use clipboard::ClipboardHost;
pub use error::{ConvertError, IpcError, ipc_error};
pub use generated::{GeneratedDto, GeneratedHost, SaveFuture};
#[cfg(target_os = "macos")]
pub use peer::check_pid;
pub use peer::{PeerCredentials, PeerVerifier, SameExecutable, has_hardened_runtime};
#[cfg(unix)]
pub use peer::{parent_pid, process_executable};
pub use protocol::{
    BrowserPrompt, BrowserReply, HotkeyMode, PROTOCOL_VERSION, SshApprovalKind, SshDecision,
    SshPrompt, TouchIdFailure, TypingTarget, UiCommand, UiNotice,
};
pub use security::{ChainDto, ChainState, SecurityFuture, SecurityHost, SecurityReportDto};
pub use server::{
    DaemonEvent, ServeOptions, ServerHandle, UiSink, serve, serve_inherited, serve_with,
};
pub use site_icons::{IconFuture, SiteIcon, SiteIconHost};
pub use touch_id::TouchIdBackend;
