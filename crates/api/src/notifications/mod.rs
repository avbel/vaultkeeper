//! Live sync over Vaultwarden's websocket hub (`/notifications/hub`), SignalR MessagePack protocol.
//!
//! [`listen`] drives one connection and [`run_with_reconnect`] keeps one alive with backoff.
//! Both are cancel-safe: they own no spawned tasks, so dropping the future closes the socket.
//! The caller is expected to drop it while the machine sleeps and start a fresh connection (plus
//! a full sync) on wake; nothing here watches the clock beyond the stale-connection timeout.

mod frame;
mod listen;
mod reconnect;

use std::time::Duration;

use thiserror::Error;
use tokio_tungstenite::tungstenite;

pub use listen::{listen, listen_with};
pub use reconnect::{ReconnectOptions, run_with_reconnect};

/// What the server told us changed. Every variant except [`Notification::Connected`] and
/// [`Notification::LogOut`] only says "re-fetch"; the payload ids are hints, not data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    /// The hub handshake completed. Sent for the first connection and every reconnect: changes
    /// made while the socket was down were never delivered, so run a full sync.
    Connected,
    /// Cipher created or updated (Vaultwarden `SyncCipherCreate` / `SyncCipherUpdate`).
    CipherChanged {
        id: String,
    },
    /// Cipher permanently deleted (`SyncLoginDelete` / `SyncCipherDelete`).
    CipherDeleted {
        id: String,
    },
    FolderChanged {
        id: String,
    },
    FolderDeleted {
        id: String,
    },
    /// `SyncCiphers`, `SyncVault`, `SyncOrgKeys` and `SyncSettings`, or an event whose id is missing.
    VaultChanged,
    /// The session was revoked server-side (`LogOut`).
    LogOut,
    /// Any other `UpdateType` (sends, auth requests, ...), by number.
    Other(u8),
}

impl Notification {
    pub(crate) fn from_update(kind: u8, id: Option<String>) -> Self {
        match (kind, id) {
            (0 | 1, Some(id)) => Self::CipherChanged { id },
            (2 | 9, Some(id)) => Self::CipherDeleted { id },
            (3, Some(id)) => Self::FolderDeleted { id },
            (7 | 8, Some(id)) => Self::FolderChanged { id },
            (0..=10, None) | (4..=6 | 10, Some(_)) => Self::VaultChanged,
            (11, _) => Self::LogOut,
            (other, _) => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListenOptions {
    /// How often to send a SignalR ping and a WebSocket ping frame.
    pub ping_interval: Duration,
    /// Close the connection and report [`ListenError::Stale`] when no frame of any kind arrived
    /// for this long. Must exceed the server's own ping interval (Vaultwarden: 15 s).
    pub stale_after: Duration,
    /// Covers TCP connect, TLS, the WebSocket upgrade and the SignalR handshake together.
    pub handshake_timeout: Duration,
    /// Drop notifications caused by this device (Vaultwarden's `ContextId`): our own writes
    /// already updated local state. `LogOut` is never dropped.
    pub own_device_id: Option<String>,
}

impl Default for ListenOptions {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(15),
            stale_after: Duration::from_secs(35),
            handshake_timeout: Duration::from_secs(10),
            own_device_id: None,
        }
    }
}

/// Why a connection ended. Only the receiver being dropped ends [`listen`] with `Ok`.
#[derive(Debug, Error)]
pub enum ListenError {
    #[error("invalid server URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("unsupported server URL scheme {0:?}")]
    UnsupportedScheme(String),
    /// The hub rejected the access token (HTTP 401 on the upgrade): refresh it before retrying.
    #[error("unauthorized")]
    Unauthorized,
    /// The upgrade was refused for another reason, e.g. 404 when websockets are disabled.
    #[error("notifications endpoint answered HTTP {0}")]
    Status(u16),
    #[error("could not set up TLS: {0}")]
    Tls(String),
    #[error("websocket error: {0}")]
    WebSocket(Box<tungstenite::Error>),
    #[error("SignalR handshake failed: {0}")]
    Handshake(String),
    #[error("connecting and handshaking took longer than {0:?}")]
    HandshakeTimeout(Duration),
    #[error("malformed hub message: {0}")]
    Protocol(String),
    /// The WebSocket closed (close frame or end of stream).
    #[error("connection closed")]
    Closed,
    /// The hub sent a SignalR close message (type 7).
    #[error("server closed the hub connection{}", .0.as_deref().map(|e| format!(": {e}")).unwrap_or_default())]
    ServerClose(Option<String>),
    /// Nothing, not even a pong, arrived within `stale_after`.
    #[error("no data from the server for {0:?}")]
    Stale(Duration),
}

impl From<tungstenite::Error> for ListenError {
    fn from(error: tungstenite::Error) -> Self {
        match error {
            tungstenite::Error::Http(response) => match response.status().as_u16() {
                401 => Self::Unauthorized,
                status => Self::Status(status),
            },
            other => Self::WebSocket(Box::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_types_map_to_notifications() {
        let id = || Some("abc".to_owned());
        let changed = |id: &str| Notification::CipherChanged { id: id.into() };
        assert_eq!(Notification::from_update(0, id()), changed("abc"));
        assert_eq!(Notification::from_update(1, id()), changed("abc"));
        for kind in [2, 9] {
            assert_eq!(
                Notification::from_update(kind, id()),
                Notification::CipherDeleted { id: "abc".into() }
            );
        }
        assert_eq!(
            Notification::from_update(3, id()),
            Notification::FolderDeleted { id: "abc".into() }
        );
        for kind in [7, 8] {
            assert_eq!(
                Notification::from_update(kind, id()),
                Notification::FolderChanged { id: "abc".into() }
            );
        }
        for kind in [4, 5, 6, 10] {
            assert_eq!(
                Notification::from_update(kind, id()),
                Notification::VaultChanged
            );
            assert_eq!(
                Notification::from_update(kind, None),
                Notification::VaultChanged
            );
        }
        assert_eq!(Notification::from_update(11, None), Notification::LogOut);
    }

    #[test]
    fn unknown_update_types_are_reported_by_number() {
        let id = || Some("abc".to_owned());
        for kind in [12, 13, 14, 15, 16, 100, 255] {
            assert_eq!(
                Notification::from_update(kind, id()),
                Notification::Other(kind)
            );
        }
    }

    #[test]
    fn cipher_and_folder_events_without_an_id_fall_back_to_a_full_refresh() {
        for kind in [0, 1, 2, 3, 7, 8, 9] {
            assert_eq!(
                Notification::from_update(kind, None),
                Notification::VaultChanged,
                "{kind}"
            );
        }
    }

    #[test]
    fn default_options_match_the_vaultwarden_cadence() {
        let options = ListenOptions::default();
        assert_eq!(options.ping_interval, Duration::from_secs(15));
        assert_eq!(options.stale_after, Duration::from_secs(35));
        assert_eq!(options.handshake_timeout, Duration::from_secs(10));
        assert_eq!(options.own_device_id, None);
    }
}
