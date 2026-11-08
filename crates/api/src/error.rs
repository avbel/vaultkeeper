use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid server URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("unexpected response: {0}")]
    Decode(#[from] serde_json::Error),
    /// Server returned an error model (`message` / `error_description`).
    #[error("server error ({status}): {message}")]
    Server { status: u16, message: String },
    /// Access token expired or revoked; caller should refresh or re-login.
    #[error("unauthorized")]
    Unauthorized,
}
