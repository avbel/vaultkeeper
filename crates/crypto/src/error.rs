use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("KDF parameters are below the safe minimum: {0}")]
    KdfTooWeak(&'static str),
    #[error("KDF parameters are above the supported maximum: {0}")]
    KdfOutOfRange(&'static str),
    #[error("key derivation failed")]
    Kdf,
    #[error("unsupported KDF type {0}")]
    UnsupportedKdf(u8),
    #[error("invalid key length {0}")]
    InvalidKeyLength(usize),
    #[error("malformed EncString: {0}")]
    MalformedEncString(&'static str),
    #[error("unsupported EncString type {0}")]
    UnsupportedEncType(u8),
    #[error("MAC verification failed")]
    MacMismatch,
    #[error("a MAC key is required for this EncString type")]
    MissingMacKey,
    #[error("unauthenticated (type 0) EncString rejected for a key that has a MAC key")]
    MacRequired,
    #[error("decryption failed")]
    Decrypt,
    #[error("decrypted data is not valid UTF-8")]
    InvalidUtf8,
    #[error("invalid RSA private key")]
    InvalidPrivateKey,
    #[error("I/O error while streaming encrypted data: {0}")]
    Io(#[from] std::io::Error),
}
