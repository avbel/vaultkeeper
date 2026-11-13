use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not supported on this platform")]
    Unsupported,
    #[error("biometric authentication was cancelled or failed")]
    BiometricFailed,
    /// Enrolled fingerprints changed; the user must unlock with the master password and re-enroll.
    #[error("biometric key is no longer valid")]
    BiometricInvalidated,
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("clipboard error: {0}")]
    Clipboard(String),
    #[error("autostart error: {0}")]
    Autostart(String),
    #[error("another instance is already running")]
    AlreadyRunning,
    #[error("code signature: {0}")]
    CodeSignature(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
