//! Messages exchanged over the socket.
//!
//! Compatibility rule: [`UiMessage::Hello`], [`DaemonMessage::Refused`] and [`Refusal`] keep their
//! variant positions and fields forever, so a UI and a daemon of different versions can still
//! tell each other that they differ. Everything else may change with [`PROTOCOL_VERSION`].

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::dto::{
    AccountDto, AttachmentDto, CollectionDto, CopyFieldDto, FilterDto, FolderDto, ItemDraftDto,
    ItemSummaryDto, LoginRequestDto, LoginStepDto, OrganizationDto, SessionStateDto, TotpCodeDto,
    TwoFactorAnswerDto, WireError,
};

pub const PROTOCOL_VERSION: u32 = 10;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Login waits on the KDF and the server, sync and attachments on transfers, a Touch ID unlock
/// on the user.
const LONG_TIMEOUT: Duration = Duration::from_mins(10);

/// UI -> daemon.
#[derive(Serialize, Deserialize)]
pub enum UiMessage {
    /// First message on every connection.
    Hello {
        protocol_version: u32,
    },
    Request {
        id: u64,
        call: Call,
    },
    SshApprovalReply {
        request_id: u64,
        approved: bool,
        /// "Remember for this key until lock" was ticked.
        remember: bool,
    },
    /// Fire-and-forget news from the UI process; never answered.
    Notice(UiNotice),
    BrowserPromptReply {
        request_id: u64,
        reply: BrowserReply,
    },
}

/// What the UI process tells the daemon outside of `VaultService` calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UiNotice {
    /// `settings.json` was rewritten; the daemon re-reads it (hotkey, lock timeout, SSH agent).
    SettingsChanged,
    /// The user typed or clicked in a UI window; resets the lock timeout.
    Activity,
    /// The UI's main loop got to the daemon's event `seq` (see [`Event::Command`]), so the daemon
    /// can tell a hung UI from a slow one. Covers every earlier event too, so a dropped notice is
    /// made up for by the next.
    Alive(u64),
    /// A native modal dialog (file panel) holds the main loop; `false` when it closed.
    Modal(bool),
    /// A Settings shortcut recorder waits for a key (`false`: it stopped). The daemon's global
    /// hotkeys would take the press first, so they are off meanwhile.
    ShortcutRecording(bool),
    /// Not sent by a UI: the server queues it when a UI session ends, however it ended, so
    /// whatever the UI turned on (a hotkey pause) can be undone.
    Disconnected,
}

/// Daemon -> UI.
#[derive(Serialize, Deserialize)]
pub enum DaemonMessage {
    /// Sent instead of [`DaemonMessage::Welcome`]; the daemon closes the socket right after.
    Refused(Refusal),
    Welcome(Box<Welcome>),
    Response {
        id: u64,
        result: Result<Reply, WireError>,
    },
    Event(Event),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    VersionMismatch {
        daemon: u32,
    },
    /// Another UI process holds the connection.
    Busy,
}

/// The handshake answer; it fills the client cache before the first call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub protocol_version: u32,
    /// Current value of the vault's `changes()` counter.
    pub revision: u64,
    pub snapshot: Snapshot,
}

/// What the UI reads synchronously and often, cached in the UI process. The daemon sends a fresh
/// one before every `Changed` and before the response to any state-changing call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub state: SessionStateDto,
    pub accounts: Vec<AccountDto>,
    pub is_offline: bool,
    /// Unix seconds of the last finished sync.
    pub last_sync: Option<u64>,
    pub folders: Result<Vec<FolderDto>, WireError>,
    pub organizations: Result<Vec<OrganizationDto>, WireError>,
    pub collections: Result<Vec<CollectionDto>, WireError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Event {
    Snapshot(Box<Snapshot>),
    /// New value of the vault's `changes()` counter.
    Changed(u64),
    OfflineChanged(bool),
    /// `seq` is the daemon's number for a command or SSH approval, increasing in the order it
    /// queued them; the UI acknowledges it with [`UiNotice::Alive`] from its main loop.
    Command {
        seq: u64,
        command: UiCommand,
    },
    /// Answer with [`UiMessage::SshApprovalReply`] carrying the same `request_id`.
    SshApproval {
        seq: u64,
        request_id: u64,
        prompt: SshPrompt,
    },
    /// Stands in for event `seq` that was withdrawn before it got here (an SSH approval the agent
    /// stopped waiting for); nothing to show, but it is acknowledged like the others.
    Skipped(u64),
    /// The daemon is quitting; the UI process should exit.
    Shutdown,
    BrowserPrompt {
        seq: u64,
        request_id: u64,
        prompt: BrowserPrompt,
    },
}

/// The app that was in front when the user asked for the Quick Panel; auto-type gives the focus
/// back to it and types there.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypingTarget {
    pub pid: i32,
    pub name: String,
}

/// What the daemon asks the UI process to show.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UiCommand {
    ShowManager,
    /// `target` is read by the daemon when the request arrives: the UI process activates itself
    /// when it starts or shows a window, so by the time it sees the command the app the user
    /// was in is no longer in front.
    ShowQuickPanel {
        target: Option<TypingTarget>,
    },
    ShowUnlock,
    ShowLogin,
    ShowSettings,
    ShowGenerator,
    /// The lock screen, with Touch ID offered once right away; after the unlock nothing else
    /// opens. For "Ask to unlock on start" and for SSH requests before the first unlock.
    UnlockInTray,
    /// The daemon rewrote `settings.json` (theme from the tray menu); re-read it.
    ReloadSettings,
    /// The global hotkey: open the Quick Panel, or close it when it is open. `target` as for
    /// [`UiCommand::ShowQuickPanel`].
    ToggleQuickPanel {
        target: Option<TypingTarget>,
    },
    /// The tray's "Sync now" ended; `error` is why it failed. Sent only to a running UI, which
    /// shows it if a window is open.
    SyncFinished {
        error: Option<String>,
    },
    /// A message from a daemon-side flow (a browser save that failed). Never opens a window on
    /// its own: it waits for the next one.
    Toast {
        text: String,
        error: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SshApprovalKind {
    /// A sign request for one key.
    Sign,
    /// The agent wants to list keys before the vault was first unlocked.
    List,
}

/// The user's answer to an SSH approval. Dropping the sender instead counts as deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SshDecision {
    pub approved: bool,
    /// Approve this key again without asking until the vault locks.
    pub remember: bool,
}

impl SshDecision {
    pub const DENY: Self = Self {
        approved: false,
        remember: false,
    };

    #[must_use]
    pub const fn approve(remember: bool) -> Self {
        Self {
            approved: true,
            remember,
        }
    }
}

/// Everything the approval window shows; the daemon resolves key names and fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshPrompt {
    pub kind: SshApprovalKind,
    pub process: String,
    pub pid: Option<u32>,
    pub key_name: String,
    pub fingerprint: String,
    /// e.g. "git commit signing" or "agent forwarding".
    pub purpose: Option<String>,
    /// The app in front when the request arrived (usually the terminal running ssh); it gets
    /// the front back once the prompt is answered.
    pub return_to: Option<TypingTarget>,
}

/// Browser prompt content is supplied by the daemon, not by a web page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserPrompt {
    Pair {
        browser: String,
        fingerprint: String,
    },
    Fill {
        browser: String,
        host: String,
        insecure: bool,
        matches: Vec<ItemSummaryDto>,
        touch_id: bool,
        return_to: Option<TypingTarget>,
    },
    Save {
        browser: String,
        host: String,
        username: String,
        update_of: Option<ItemSummaryDto>,
        choices: Vec<ItemSummaryDto>,
        return_to: Option<TypingTarget>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserReply {
    Dismissed,
    PairApproved,
    Fill {
        item_id: Arc<str>,
        confirmed_other_site: bool,
    },
    Save {
        target: Option<Arc<str>>,
    },
    NeverForSite,
}

/// Why a Touch ID enrolment or unlock in the daemon did not happen. Vault errors (locked, wrong
/// key) travel as [`WireError`] instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum TouchIdFailure {
    #[error("Touch ID is not available")]
    Unavailable,
    #[error("cancelled")]
    Cancelled,
    /// The enrolment can never work again (fingerprints changed, corrupt file); the daemon has
    /// already removed it.
    #[error("fingerprints changed since enrolment")]
    Invalidated,
    /// The UI asked for an account that is no longer the active one.
    #[error("the active account changed")]
    AccountChanged,
    #[error("{0}")]
    Failed(String),
}

/// One variant per `VaultService` method, except that key material never crosses the socket:
/// Touch ID enrolment and unlock run inside the daemon, and SSH keys stay with its agent.
/// Paths travel as raw OS bytes.
#[derive(Serialize, Deserialize)]
pub enum Call {
    State,
    Changes,
    Login {
        request: LoginRequestDto,
        two_factor: Option<TwoFactorAnswerDto>,
        new_device_otp: Option<String>,
    },
    SendEmailCode,
    UnlockWithPassword(Zeroizing<String>),
    /// Wraps the unlocked vault's user key for `account_id` (which must be the active account)
    /// in the Secure Enclave. Never prompts.
    EnrollTouchId {
        account_id: String,
    },
    /// The daemon shows the Touch ID prompt, unwraps the key and unlocks `account_id`.
    UnlockWithTouchId {
        account_id: String,
    },
    VerifyMasterPassword(Zeroizing<String>),
    Lock,
    Logout,
    Accounts,
    SwitchAccount(String),
    BeginAddAccount,
    Sync,
    IsOffline,
    Search {
        query: String,
        filter: FilterDto,
    },
    Folders,
    Organizations,
    Collections,
    Reveal {
        id: Arc<str>,
        field: CopyFieldDto,
    },
    Totp {
        id: Arc<str>,
        unix_time: u64,
    },
    Draft(Arc<str>),
    Save {
        id: Option<Arc<str>>,
        draft: Box<ItemDraftDto>,
    },
    Attachments(Arc<str>),
    DownloadAttachment {
        id: Arc<str>,
        attachment_id: String,
        dest: Vec<u8>,
    },
    UploadAttachment {
        id: Arc<str>,
        source: Vec<u8>,
    },
    DeleteAttachment {
        id: Arc<str>,
        attachment_id: String,
    },
    AssignCollections {
        id: Arc<str>,
        organization_id: String,
        collection_ids: Vec<Arc<str>>,
    },
    Trash(Arc<str>),
    Restore(Arc<str>),
    DeletePermanently(Arc<str>),
    CreateFolder(String),
    RenameFolder {
        id: String,
        name: String,
    },
    DeleteFolder(String),
    ProbeServer(String),
    /// The daemon puts `text` on the clipboard and owns its auto-clear.
    CopyToClipboard {
        text: Zeroizing<String>,
        clear_after_secs: Option<u64>,
    },
    /// Clears the clipboard if it still holds the daemon's last copy.
    ClearClipboard,
}

impl Call {
    /// How long the client waits for the response.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        match self {
            Self::Login { .. }
            | Self::UnlockWithTouchId { .. }
            | Self::Sync
            | Self::DownloadAttachment { .. }
            | Self::UploadAttachment { .. }
            | Self::DeleteAttachment { .. } => LONG_TIMEOUT,
            _ => DEFAULT_TIMEOUT,
        }
    }

    /// Calls that may change what [`Snapshot`] holds; the daemon refreshes the client's cache
    /// before it answers them, even when the vault did not bump its change counter.
    #[must_use]
    pub const fn changes_state(&self) -> bool {
        !matches!(
            self,
            Self::State
                | Self::Changes
                | Self::EnrollTouchId { .. }
                | Self::VerifyMasterPassword(_)
                | Self::Accounts
                | Self::IsOffline
                | Self::Search { .. }
                | Self::Folders
                | Self::Organizations
                | Self::Collections
                | Self::Reveal { .. }
                | Self::Totp { .. }
                | Self::Draft(_)
                | Self::Attachments(_)
                | Self::DownloadAttachment { .. }
                | Self::ProbeServer(_)
                | Self::CopyToClipboard { .. }
                | Self::ClearClipboard
        )
    }
}

/// The successful result of a [`Call`].
#[derive(Serialize, Deserialize)]
pub enum Reply {
    Unit,
    Bool(bool),
    Revision(u64),
    State(SessionStateDto),
    LoginStep(LoginStepDto),
    TouchId(Result<(), TouchIdFailure>),
    Accounts(Vec<AccountDto>),
    Items(Vec<ItemSummaryDto>),
    Folders(Vec<FolderDto>),
    Organizations(Vec<OrganizationDto>),
    Collections(Vec<CollectionDto>),
    Secret(Zeroizing<String>),
    Totp(TotpCodeDto),
    Draft(Box<ItemDraftDto>),
    ItemId(Arc<str>),
    Attachments(Vec<AttachmentDto>),
    Attachment(AttachmentDto),
    Folder(FolderDto),
    ServerProbe { version: Option<String> },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{HEADER_LEN, decode, encode};

    #[test]
    fn handshake_variants_keep_their_wire_positions() {
        let refused = encode(&DaemonMessage::Refused(Refusal::VersionMismatch {
            daemon: 7,
        }))
        .expect("encode");
        // Refused = variant 0, VersionMismatch = variant 0, then the version as a varint.
        assert_eq!(&refused[HEADER_LEN..], &[0, 0, 7]);
        let busy = encode(&DaemonMessage::Refused(Refusal::Busy)).expect("encode");
        assert_eq!(&busy[HEADER_LEN..], &[0, 1]);
    }

    #[test]
    fn network_calls_get_the_long_timeout() {
        assert_eq!(Call::Sync.timeout(), LONG_TIMEOUT);
        assert_eq!(
            Call::UploadAttachment {
                id: "i".into(),
                source: Vec::new()
            }
            .timeout(),
            LONG_TIMEOUT
        );
        assert_eq!(
            Call::UnlockWithTouchId {
                account_id: "a".to_owned()
            }
            .timeout(),
            LONG_TIMEOUT,
            "the user may take a while to touch the sensor"
        );
        assert_eq!(Call::Folders.timeout(), DEFAULT_TIMEOUT);
        assert_eq!(Call::Lock.timeout(), DEFAULT_TIMEOUT);
    }

    #[test]
    fn reads_do_not_change_state_and_writes_do() {
        assert!(!Call::State.changes_state());
        assert!(
            !Call::Search {
                query: String::new(),
                filter: FilterDto::default()
            }
            .changes_state()
        );
        assert!(Call::Lock.changes_state());
        assert!(Call::UnlockWithPassword(Zeroizing::new(String::new())).changes_state());
        assert!(Call::SwitchAccount("a".to_owned()).changes_state());
        assert!(Call::CreateFolder("x".to_owned()).changes_state());
        assert!(!Call::ProbeServer("https://vault.example".to_owned()).changes_state());
        let account_id = "a".to_owned();
        assert!(
            !Call::EnrollTouchId {
                account_id: account_id.clone()
            }
            .changes_state()
        );
        assert!(Call::UnlockWithTouchId { account_id }.changes_state());
        assert!(
            !Call::CopyToClipboard {
                text: Zeroizing::new("x".to_owned()),
                clear_after_secs: Some(30)
            }
            .changes_state()
        );
        assert!(!Call::ClearClipboard.changes_state());
    }

    #[test]
    fn notices_decode_back() {
        let frame = encode(&UiMessage::Notice(UiNotice::SettingsChanged)).expect("encode");
        let UiMessage::Notice(notice) = decode(&frame[HEADER_LEN..]).expect("decode") else {
            panic!("wrong message");
        };
        assert_eq!(notice, UiNotice::SettingsChanged);
    }

    #[test]
    fn quick_panel_commands_carry_their_typing_target() {
        let safari = TypingTarget {
            pid: 812,
            name: "Safari".to_owned(),
        };
        for command in [
            UiCommand::ToggleQuickPanel {
                target: Some(safari.clone()),
            },
            UiCommand::ShowQuickPanel {
                target: Some(safari.clone()),
            },
            UiCommand::ToggleQuickPanel { target: None },
        ] {
            let frame = encode(&DaemonMessage::Event(Event::Command {
                seq: 3,
                command: command.clone(),
            }))
            .expect("encode");
            let DaemonMessage::Event(Event::Command {
                seq: 3,
                command: back,
            }) = decode(&frame[HEADER_LEN..]).expect("decode")
            else {
                panic!("wrong message");
            };
            assert_eq!(back, command);
        }
    }

    #[test]
    fn requests_decode_back() {
        let frame = encode(&UiMessage::Request {
            id: 9,
            call: Call::Reveal {
                id: "item".into(),
                field: CopyFieldDto::Custom(2),
            },
        })
        .expect("encode");
        let UiMessage::Request {
            id: 9,
            call: Call::Reveal { id, field },
        } = decode(&frame[HEADER_LEN..]).expect("decode")
        else {
            panic!("wrong message");
        };
        assert_eq!((id.as_ref(), field), ("item", CopyFieldDto::Custom(2)));
    }
}
