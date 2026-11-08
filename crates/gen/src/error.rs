use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid TOTP secret or URI: {0}")]
    InvalidTotp(&'static str),
    #[error("invalid generator options: {0}")]
    InvalidOptions(&'static str),
}
