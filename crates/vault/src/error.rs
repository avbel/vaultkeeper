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
    /// A write refused because the server is unreachable; the cached vault stays readable.
    #[error("{OFFLINE_MESSAGE}")]
    Offline,
    /// The item changed elsewhere since the draft was read; nothing was saved.
    #[error("{CONFLICT_MESSAGE}")]
    Conflict,
    /// The server asked a known account for a weaker KDF than the cached one; no password hash
    /// was derived or sent.
    #[error("{KDF_DOWNGRADE_MESSAGE}")]
    KdfDowngrade,
    #[error(transparent)]
    Api(#[from] vk_api::Error),
    #[error(transparent)]
    Crypto(#[from] vk_crypto::Error),
    #[error(transparent)]
    Gen(#[from] vk_gen::Error),
    #[error("storage error: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt cache: {0}")]
    Cache(#[from] serde_json::Error),
    /// Every step of a log out that failed; the other steps still ran.
    #[error(transparent)]
    Logout(LogoutErrors),
}

/// What [`Error::Conflict`] displays.
pub const CONFLICT_MESSAGE: &str =
    "This item was changed elsewhere since you opened it; your edits were not saved";

/// What [`Error::KdfDowngrade`] displays.
pub const KDF_DOWNGRADE_MESSAGE: &str = "The server asks for a weaker master password encryption \
     than this account used before, so the password was not sent. If you lowered it yourself, \
     log out of this account in vaultkeeper and log in again";

/// What [`Error::Offline`] displays.
pub const OFFLINE_MESSAGE: &str = "Offline: the vault is read-only until the server is reachable";

impl Error {
    /// True for transport failures, gateway errors and writes refused while offline.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        match self {
            Self::Offline => true,
            Self::Api(error) => error.is_offline(),
            _ => false,
        }
    }

    /// The server answered with data this client can't use (a missing key, a bad id).
    pub(crate) fn protocol(message: &'static str) -> Self {
        Self::Api(vk_api::Error::Decode(serde::de::Error::custom(message)))
    }

    /// A refusal that the UI shows verbatim, for operations this client does not offer.
    pub(crate) fn unsupported(message: &'static str) -> Self {
        Self::Api(vk_api::Error::Server {
            status: 400,
            message: message.to_owned(),
        })
    }

    pub(crate) fn task(error: tokio::task::JoinError) -> Self {
        Self::Io(std::io::Error::other(error))
    }
}

/// Every step of a log out that failed. The log out still ran all the other steps; the trait
/// method reports this as [`Error::Logout`].
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
        Self::Logout(errors)
    }
}

/// A master-key or user-key mismatch shows up as a failed MAC (type 2) or bad padding (type 0).
pub(crate) fn wrong_key_as_invalid_password(error: vk_crypto::Error) -> Error {
    match error {
        vk_crypto::Error::MacMismatch | vk_crypto::Error::Decrypt => Error::InvalidPassword,
        other => Error::Crypto(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_writes_are_offline_and_say_so() {
        assert!(Error::Offline.is_offline());
        assert_eq!(Error::Offline.to_string(), OFFLINE_MESSAGE);
    }

    #[test]
    fn gateway_statuses_from_the_api_are_offline() {
        let gateway = Error::Api(vk_api::Error::Server {
            status: 503,
            message: "Service Unavailable".to_owned(),
        });
        assert!(gateway.is_offline());
    }

    #[test]
    fn other_errors_are_not_offline() {
        assert!(!Error::Locked.is_offline());
        assert!(!Error::protocol("bad").is_offline());
        assert!(!Error::unsupported("no").is_offline());
        assert!(!Error::Api(vk_api::Error::Unauthorized).is_offline());
    }

    #[test]
    fn logout_errors_keep_every_failure() {
        let error: Error = LogoutErrors(vec![Error::NotFound, Error::Locked]).into();
        assert_eq!(
            error.to_string(),
            "log out finished with 2 error(s); item not found; vault is locked"
        );
        let Error::Logout(errors) = &error else {
            panic!("expected the collected log out errors, got {error:?}");
        };
        assert_eq!(errors.0.len(), 2);
        assert!(!error.is_offline());
    }

    #[test]
    fn mac_and_padding_failures_mean_a_wrong_password() {
        assert!(matches!(
            wrong_key_as_invalid_password(vk_crypto::Error::MacMismatch),
            Error::InvalidPassword
        ));
        assert!(matches!(
            wrong_key_as_invalid_password(vk_crypto::Error::Decrypt),
            Error::InvalidPassword
        ));
        assert!(matches!(
            wrong_key_as_invalid_password(vk_crypto::Error::InvalidKeyLength(3)),
            Error::Crypto(_)
        ));
    }
}
