use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid WebAuthn options: {0}")]
    InvalidOptions(#[from] serde_json::Error),
    #[error("invalid base64url data")]
    Base64,
    #[error("invalid passkey private key")]
    InvalidKey,
    #[error("cannot generate a passkey: {0}")]
    Random(String),
}
