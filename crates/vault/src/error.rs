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
