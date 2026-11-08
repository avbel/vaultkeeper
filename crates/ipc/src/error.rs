use std::{io, time::Duration};

use thiserror::Error;

use crate::frame::MAX_FRAME_LEN;

/// Transport and protocol failures. Vault errors travel as [`crate::dto::WireError`] instead.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("IPC socket error: {0}")]
    Io(#[from] io::Error),
    #[error("IPC frame of {len} bytes exceeds the {MAX_FRAME_LEN}-byte limit")]
    FrameTooLarge { len: usize },
    #[error("cannot encode IPC message: {0}")]
    Encode(#[source] postcard::Error),
    #[error("malformed IPC message: {0}")]
    Decode(#[source] postcard::Error),
    #[error("IPC protocol mismatch: this process speaks version {ours}, the other side {theirs}")]
    VersionMismatch { ours: u32, theirs: u32 },
    #[error("another UI process is already connected to the daemon")]
    Busy,
    #[error("IPC protocol violation: {0}")]
    Protocol(&'static str),
    #[error("lost the connection to the bw-lite daemon")]
    Disconnected,
    #[error("the bw-lite daemon did not answer within {0:?}")]
    Timeout(Duration),
    #[error("invalid data over IPC: {0}")]
    Convert(#[from] ConvertError),
}

/// A DTO that decoded fine but does not map onto a model value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConvertError {
    #[error("invalid server URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("unknown two-factor provider {0}")]
    UnknownProvider(u8),
    #[error("custom field index {0} is out of range")]
    FieldIndex(u64),
}

impl IpcError {
    fn io_kind(&self) -> io::ErrorKind {
        match self {
            Self::Io(error) => error.kind(),
            Self::Disconnected => io::ErrorKind::ConnectionAborted,
            Self::Timeout(_) => io::ErrorKind::TimedOut,
            Self::Busy => io::ErrorKind::AddrInUse,
            Self::FrameTooLarge { .. }
            | Self::Encode(_)
            | Self::Decode(_)
            | Self::VersionMismatch { .. }
            | Self::Protocol(_)
            | Self::Convert(_) => io::ErrorKind::InvalidData,
        }
    }
}

/// `VaultService` methods can only return the vault's error type, so IPC failures travel as
/// `Error::Io` with the [`IpcError`] as source; [`ipc_error`] gets it back.
impl From<IpcError> for bwl_vault::Error {
    fn from(error: IpcError) -> Self {
        Self::Io(io::Error::new(error.io_kind(), error))
    }
}

/// The IPC failure behind a vault error returned by [`crate::RemoteVault`], if it was one.
#[must_use]
pub fn ipc_error(error: &bwl_vault::Error) -> Option<&IpcError> {
    match error {
        bwl_vault::Error::Io(io) => io.get_ref()?.downcast_ref::<IpcError>(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnect_becomes_a_connection_aborted_io_error_that_downcasts_back() {
        let error = bwl_vault::Error::from(IpcError::Disconnected);
        let bwl_vault::Error::Io(io) = &error else {
            panic!("expected an I/O error, got {error:?}");
        };
        assert_eq!(io.kind(), io::ErrorKind::ConnectionAborted);
        assert!(!error.is_offline(), "a dead daemon is not offline mode");
        assert!(matches!(ipc_error(&error), Some(IpcError::Disconnected)));
        assert_eq!(
            error.to_string(),
            "storage error: lost the connection to the bw-lite daemon"
        );
    }

    #[test]
    fn timeout_keeps_its_kind_and_duration() {
        let error = bwl_vault::Error::from(IpcError::Timeout(Duration::from_secs(30)));
        let bwl_vault::Error::Io(io) = &error else {
            panic!("expected an I/O error");
        };
        assert_eq!(io.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            error.to_string(),
            "storage error: the bw-lite daemon did not answer within 30s"
        );
    }

    #[test]
    fn vault_errors_are_not_ipc_errors() {
        assert!(ipc_error(&bwl_vault::Error::Locked).is_none());
        let plain_io = bwl_vault::Error::Io(io::Error::other("disk full"));
        assert!(ipc_error(&plain_io).is_none());
    }
}
