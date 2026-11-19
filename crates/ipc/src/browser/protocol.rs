//! Messages exchanged with browser native hosts and extensions.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: u32 = 1;

/// The version of the extension requests (`hello.protocol`), which is not the host hop's
/// [`PROTOCOL_VERSION`]. 2 added `fill.auto`: an older daemon would ignore the flag and show the
/// picker on page load, so the two sides must not talk across versions.
pub const EXTENSION_PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostHello {
    pub protocol: u32,
    pub caller: Caller,
    pub parent: ParentInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Caller {
    Chromium { origin: String },
    Firefox { extension_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentInfo {
    pub pid: i32,
    pub executable: String,
    pub browser: Option<KnownBrowser>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownBrowser {
    Chrome,
    Edge,
    Firefox,
}

impl KnownBrowser {
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Chrome => "Google Chrome",
            Self::Edge => "Microsoft Edge",
            Self::Firefox => "Firefox",
        }
    }

    /// Edge installs the extension from the Chrome Web Store, so it calls the host as Chromium.
    #[must_use]
    pub const fn serves(self, caller: &Caller) -> bool {
        matches!(
            (self, caller),
            (Self::Chrome | Self::Edge, Caller::Chromium { .. })
                | (Self::Firefox, Caller::Firefox { .. })
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HostWelcome {
    Refused { ok: bool, reason: Refusal },
    Welcome { ok: bool },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    Disabled,
    Version,
    UnverifiedParent,
    Busy,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Hello {
        id: u64,
        protocol: u32,
        extension_version: String,
        public_key: String,
    },
    Prove {
        id: u64,
        signature: String,
    },
    Status {
        id: u64,
    },
    Fill {
        id: u64,
        origin: String,
        path: String,
        choose: bool,
        fields: FillFields,
        /// A fill the extension started on page load. The daemon answers it only from what is
        /// already remembered, without any window, and says `no_auto` otherwise.
        #[serde(default)]
        auto: bool,
    },
    SaveCandidate {
        id: u64,
        origin: String,
        path: String,
        username: String,
        password: Zeroizing<String>,
        kind: SaveKind,
    },
    Unlock {
        id: u64,
    },
    OpenApp {
        id: u64,
        view: AppView,
    },
    /// `navigator.credentials.create` of a page; `options` is its `publicKey` in JSON form.
    PasskeyCreate {
        id: u64,
        origin: String,
        options: serde_json::Value,
    },
    /// `navigator.credentials.get` of a page; `options` is its `publicKey` in JSON form.
    PasskeyGet {
        id: u64,
        origin: String,
        options: serde_json::Value,
    },
    /// The page gave up: ends this connection's passkey request for `origin`, if one runs.
    PasskeyCancel {
        id: u64,
        origin: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FillFields {
    pub username: bool,
    pub password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaveKind {
    Login,
    Change,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppView {
    Manager,
    Settings,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response<T> {
    Success { id: u64, ok: bool, result: T },
    Failure { id: u64, ok: bool, error: ErrorCode },
}

/// A passkey answer: `RegistrationResponseJSON` or `AuthenticationResponseJSON`.
#[derive(Serialize, Deserialize)]
pub struct PasskeyResult {
    pub credential: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct FillResult {
    pub username: Option<Zeroizing<String>>,
    pub password: Option<Zeroizing<String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    UnknownType,
    Unpaired,
    Denied,
    Cancelled,
    Timeout,
    Locked,
    LoggedOut,
    NoLogin,
    Busy,
    RateLimited,
    InsecurePage,
    Offline,
    Internal,
    /// Not a request for the vault: the browser's own WebAuthn should answer it.
    Fallback,
    /// WebAuthn `NotAllowedError`: the user declined.
    NotAllowed,
    /// WebAuthn `InvalidStateError`: the vault already holds a passkey the site excluded.
    InvalidState,
    /// An automatic fill that is not allowed or has nothing to fill. Not a failure to show.
    NoAuto,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    State { state: State, theme: Theme },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Unlocked,
    Locked,
    LoggedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    Light,
    Dark,
    System,
}
