use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid server URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("server URL refused: {0}")]
    InvalidServerUrl(&'static str),
    #[error("unexpected response: {0}")]
    Decode(#[from] serde_json::Error),
    /// Server returned an error model (`message` / `error_description`).
    #[error("server error ({status}): {message}")]
    Server { status: u16, message: String },
    /// Access token expired or revoked; caller should refresh or re-login.
    #[error("unauthorized")]
    Unauthorized,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// An attachment URL named a host other than the configured server, so nothing was sent.
    #[error("refusing to contact untrusted host {0}")]
    UntrustedUrl(String),
}

impl Error {
    /// True when the server could not be reached or did not answer: transport failures,
    /// timeouts and gateway statuses (502/503/504) from a proxy in front of a dead server.
    /// The vault uses this to fall back to offline mode instead of reporting a hard failure.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        match self {
            Self::Http(error) => !(error.is_builder() || error.is_redirect()),
            Self::Server { status, .. } => matches!(status, 502..=504),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_statuses_count_as_offline() {
        for status in [502, 503, 504] {
            let error = Error::Server {
                status,
                message: String::new(),
            };
            assert!(error.is_offline(), "{status}");
        }
    }

    #[test]
    fn application_errors_are_not_offline() {
        let server = Error::Server {
            status: 400,
            message: "bad".into(),
        };
        assert!(!server.is_offline());
        assert!(!Error::Unauthorized.is_offline());
        assert!(!Error::UntrustedUrl("evil.example".into()).is_offline());
    }
}
