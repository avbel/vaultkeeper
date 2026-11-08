use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("KDF parameters are below the safe minimum: {0}")]
    KdfTooWeak(&'static str),
    #[error("key derivation failed")]
    Kdf,
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
    #[error("decryption failed")]
    Decrypt,
    #[error("decrypted data is not valid UTF-8")]
    InvalidUtf8,
    #[error("invalid RSA private key")]
    InvalidPrivateKey,
}
