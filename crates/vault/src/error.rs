use std::fmt;

use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("vault is locked")]
    Locked,
    #[error("not logged in")]
    LoggedOut,
    #[error("invalid master password")]
    InvalidPassword,
    #[error("item not found")]
    NotFound,
    #[error("item has no such field")]
    NoSuchField,
    #[error("item is read-only")]
    ReadOnly,
    #[error(transparent)]
    Api(#[from] bwl_api::Error),
    #[error(transparent)]
    Crypto(#[from] bwl_crypto::Error),
    #[error(transparent)]
    Gen(#[from] bwl_gen::Error),
    #[error("storage error: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt cache: {0}")]
    Cache(#[from] serde_json::Error),
}

/// Shown when a write is refused because the server is unreachable. It travels as a 503 so
/// [`Error::is_offline`] (and `bwl_api::Error::is_offline`) recognise it.
pub const OFFLINE_MESSAGE: &str = "Offline: the vault is read-only until the server is reachable";
const OFFLINE_STATUS: u16 = 503;

impl Error {
    /// True for transport failures, gateway errors and writes refused while offline.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        matches!(self, Self::Api(error) if error.is_offline())
    }

    pub(crate) fn offline() -> Self {
        Self::Api(bwl_api::Error::Server {
            status: OFFLINE_STATUS,
            message: OFFLINE_MESSAGE.to_owned(),
        })
    }

    /// The server answered with data this client can't use (a missing key, a bad id).
    pub(crate) fn protocol(message: &'static str) -> Self {
        Self::Api(bwl_api::Error::Decode(serde::de::Error::custom(message)))
    }

    /// A refusal that the UI shows verbatim, for operations this client does not offer.
    pub(crate) fn unsupported(message: &'static str) -> Self {
        Self::Api(bwl_api::Error::Server {
            status: 400,
            message: message.to_owned(),
        })
    }

    pub(crate) fn task(error: tokio::task::JoinError) -> Self {
        Self::Io(std::io::Error::other(error))
    }
}

/// Every step of a log out that failed. The log out still ran all the other steps; the trait
/// method reports this as `Error::Io` with this value as the source (downcast with
/// `io::Error::get_ref`).
#[derive(Debug)]
pub struct LogoutErrors(pub Vec<Error>);

impl fmt::Display for LogoutErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "log out finished with {} error(s)", self.0.len())?;
        for error in &self.0 {
            write!(f, "; {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for LogoutErrors {}

impl From<LogoutErrors> for Error {
    fn from(errors: LogoutErrors) -> Self {
        Self::Io(std::io::Error::other(errors))
    }
}

/// A master-key or user-key mismatch shows up as a failed MAC (type 2) or bad padding (type 0).
pub(crate) fn wrong_key_as_invalid_password(error: bwl_crypto::Error) -> Error {
    match error {
        bwl_crypto::Error::MacMismatch | bwl_crypto::Error::Decrypt => Error::InvalidPassword,
        other => Error::Crypto(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_error_is_recognised_as_offline_by_both_crates() {
        let error = Error::offline();
        assert!(error.is_offline());
        let Error::Api(api) = &error else {
            panic!("expected an API error");
        };
        assert!(api.is_offline());
        assert_eq!(
            error.to_string(),
            format!("server error (503): {OFFLINE_MESSAGE}")
        );
    }

    #[test]
    fn other_errors_are_not_offline() {
        assert!(!Error::Locked.is_offline());
        assert!(!Error::protocol("bad").is_offline());
        assert!(!Error::unsupported("no").is_offline());
        assert!(!Error::Api(bwl_api::Error::Unauthorized).is_offline());
    }

    #[test]
    fn logout_errors_keep_every_failure_and_downcast_back() {
        let error: Error = LogoutErrors(vec![Error::NotFound, Error::Locked]).into();
        assert_eq!(
            error.to_string(),
            "storage error: log out finished with 2 error(s); item not found; vault is locked"
        );
        let Error::Io(io) = &error else {
            panic!("expected an I/O error");
        };
        let inner = io.get_ref().and_then(|e| e.downcast_ref::<LogoutErrors>());
        assert_eq!(inner.map(|errors| errors.0.len()), Some(2));
    }

    #[test]
    fn mac_and_padding_failures_mean_a_wrong_password() {
        assert!(matches!(
            wrong_key_as_invalid_password(bwl_crypto::Error::MacMismatch),
            Error::InvalidPassword
        ));
        assert!(matches!(
            wrong_key_as_invalid_password(bwl_crypto::Error::Decrypt),
            Error::InvalidPassword
        ));
        assert!(matches!(
            wrong_key_as_invalid_password(bwl_crypto::Error::InvalidKeyLength(3)),
            Error::Crypto(_)
        ));
    }
}
