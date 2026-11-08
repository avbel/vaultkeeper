//! Daemon <-> UI process IPC.
//!
//! `bw-lite --daemon` owns the real vault and calls [`serve`]; the on-demand `bw-lite --ui`
//! process calls [`RemoteVault::connect`] and hands the [`RemoteVault`] to the Slint UI as its
//! `VaultService`.
//!
//! - **Transport:** a unix socket (mode 0600 in a 0700 directory). The daemon accepts one UI
//!   process at a time and only peers running as its uid from its own executable
//!   ([`SameExecutable`]).
//! - **Frames:** a u32 little-endian length (at most [`frame::MAX_FRAME_LEN`]), then a postcard
//!   body: [`protocol::UiMessage`] one way, [`protocol::DaemonMessage`] the other. Frame buffers
//!   are exactly sized `Zeroizing` vectors, and secret DTOs wipe themselves on drop.
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

#[cfg(not(unix))]
compile_error!("bwl-ipc talks over a unix domain socket; only unix targets are supported");

mod client;
pub mod dto;
mod error;
pub mod frame;
mod peer;
pub mod protocol;
mod server;

pub use client::{EventStream, RemoteVault, SshApproval, UiEvent};
pub use error::{ConvertError, IpcError, ipc_error};
pub use peer::{PeerCredentials, PeerVerifier, SameExecutable};
pub use protocol::{
    PROTOCOL_VERSION, SshApprovalKind, SshDecision, SshPrompt, UiCommand, UiNotice,
};
pub use server::{DaemonEvent, ServeOptions, ServerHandle, serve, serve_with};
