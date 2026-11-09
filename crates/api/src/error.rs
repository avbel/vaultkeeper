use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("network error: {0}")]
    Http(reqwest::Error),
    /// The server answered but the TLS handshake failed: an expired or untrusted certificate,
    /// a name mismatch, or plain HTTP on an HTTPS port. Not offline, retrying won't help.
    #[error("secure connection failed: {0}")]
    Tls(String),
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

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        match tls_failure(&error) {
            Some(detail) => Self::Tls(detail),
            None => Self::Http(error),
        }
    }
}

/// Finds a rustls error in the chain. reqwest wraps it in an `io::Error`, whose `source()`
/// skips the wrapped error, so io errors are opened with `get_ref` instead.
fn tls_failure(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(tls) = error.downcast_ref::<rustls::Error>() {
            return Some(describe_tls(tls));
        }
        current = match error.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => error.source(),
        };
    }
    None
}

fn describe_tls(error: &rustls::Error) -> String {
    use rustls::CertificateError;

    match error {
        rustls::Error::InvalidCertificate(CertificateError::Expired) => {
            "the server's certificate has expired".to_owned()
        }
        rustls::Error::InvalidCertificate(CertificateError::NotValidYet) => {
            "the server's certificate is not valid yet (check the clock)".to_owned()
        }
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer) => {
            "the server's certificate is not trusted (unknown issuer)".to_owned()
        }
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        ) => "the server's certificate is for a different host name".to_owned(),
        rustls::Error::InvalidCertificate(CertificateError::Revoked) => {
            "the server's certificate has been revoked".to_owned()
        }
        // The macOS verifier reports most rejections this way, with the system's own text,
        // e.g. "“vault.example.com” certificate is expired: -67818".
        rustls::Error::InvalidCertificate(CertificateError::Other(other)) => {
            format!("the server's certificate was rejected: {other}")
        }
        other => other.to_string(),
    }
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
        assert!(!Error::Tls("expired".into()).is_offline());
    }

    #[derive(Debug, thiserror::Error)]
    #[error("client error")]
    struct Wrapper(#[source] std::io::Error);

    #[test]
    fn a_certificate_error_inside_an_io_error_is_found_and_described() {
        let io = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired),
        );
        assert_eq!(
            tls_failure(&Wrapper(io)).as_deref(),
            Some("the server's certificate has expired")
        );
        let unknown = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        assert_eq!(
            tls_failure(&unknown).as_deref(),
            Some("the server's certificate is not trusted (unknown issuer)")
        );
    }

    #[test]
    fn plain_transport_errors_are_not_tls_failures() {
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert_eq!(tls_failure(&Wrapper(refused)), None);
    }
}
