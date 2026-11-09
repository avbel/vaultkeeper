//! Wire mirror of `bwl_vault::Error`.
//!
//! The UI matches on vault and API error variants and calls `is_offline()`, so the tree is
//! rebuilt on the client side variant for variant. Where an inner value cannot be rebuilt the
//! nearest equivalent is used:
//! - `Api(Http)`: `reqwest::Error` has no public constructor. A transport failure (the server is
//!   unreachable) becomes [`Error::Offline`], so `error.is_offline()` stays true in the UI
//!   process; any other `Http` error becomes `Api(Io(..))` with the original text.
//! - `&'static str` payloads (crypto and generator errors) are mapped back through tables of the
//!   messages those crates use; an unknown message becomes [`UNKNOWN_DETAIL`].
//! - `Io` errors keep their kind (for the common kinds) and their text, not their source chain.

use std::io;

use bwl_vault::Error;
use serde::{Deserialize, Serialize, de::Error as _};

use crate::ConvertError;

/// Stands in for a `&'static str` detail that is not in the lookup tables.
pub const UNKNOWN_DETAIL: &str = "reported by the daemon";

const GEN_MESSAGES: &[&str] = &[
    "only otpauth://totp URIs are supported",
    "missing secret parameter",
    "unsupported algorithm",
    "digits must be 6..=10",
    "period must be a positive number of seconds",
    "empty secret",
    "secret is not valid base32",
    "password length must be 5..=128",
    "minimum counts must be 0..=9",
    "at least one character set must be enabled",
    "required characters exceed the password length",
    "passphrase must have 3..=20 words",
];

const CRYPTO_MESSAGES: &[&str] = &[
    "wrong number of parts",
    "invalid type header",
    "invalid base64",
    "RSA ciphertext is empty",
    "encrypted buffer is empty",
    "encrypted buffer is shorter than its header",
];

const URL_ERRORS: &[url::ParseError] = &[
    url::ParseError::EmptyHost,
    url::ParseError::IdnaError,
    url::ParseError::InvalidPort,
    url::ParseError::InvalidIpv4Address,
    url::ParseError::InvalidIpv6Address,
    url::ParseError::InvalidDomainCharacter,
    url::ParseError::RelativeUrlWithoutBase,
    url::ParseError::RelativeUrlWithCannotBeABaseBase,
    url::ParseError::SetHostOnCannotBeABaseUrl,
    url::ParseError::Overflow,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireError {
    Locked,
    LoggedOut,
    InvalidPassword,
    NotFound,
    NoSuchField,
    ReadOnly,
    Api(ApiErrorDto),
    Crypto(CryptoErrorDto),
    Gen(GenErrorDto),
    Io(IoErrorDto),
    Cache(String),
    Offline,
    Conflict,
    Logout(Vec<WireError>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiErrorDto {
    Http { message: String, offline: bool },
    Url(String),
    Decode(String),
    Server { status: u16, message: String },
    Unauthorized,
    Io(IoErrorDto),
    UntrustedUrl(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoErrorDto {
    KdfTooWeak(String),
    KdfOutOfRange(String),
    Kdf,
    UnsupportedKdf(u8),
    InvalidKeyLength(u64),
    MalformedEncString(String),
    UnsupportedEncType(u8),
    MacMismatch,
    MissingMacKey,
    MacRequired,
    Decrypt,
    InvalidUtf8,
    InvalidPrivateKey,
    Io(IoErrorDto),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GenErrorDto {
    InvalidTotp(String),
    InvalidOptions(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoErrorDto {
    pub kind: IoKind,
    pub message: String,
}

/// The `io::ErrorKind`s worth telling apart in the UI; the rest travel as `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IoKind {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    InvalidInput,
    InvalidData,
    TimedOut,
    UnexpectedEof,
    Interrupted,
    Unsupported,
    OutOfMemory,
    StorageFull,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    BrokenPipe,
    Other,
}

impl From<&Error> for WireError {
    fn from(error: &Error) -> Self {
        match error {
            Error::Locked => Self::Locked,
            Error::LoggedOut => Self::LoggedOut,
            Error::InvalidPassword => Self::InvalidPassword,
            Error::NotFound => Self::NotFound,
            Error::NoSuchField => Self::NoSuchField,
            Error::ReadOnly => Self::ReadOnly,
            Error::Api(api) => Self::Api(api.into()),
            Error::Crypto(crypto) => Self::Crypto(crypto.into()),
            Error::Gen(bwl_gen::Error::InvalidTotp(detail)) => {
                Self::Gen(GenErrorDto::InvalidTotp((*detail).to_owned()))
            }
            Error::Gen(bwl_gen::Error::InvalidOptions(detail)) => {
                Self::Gen(GenErrorDto::InvalidOptions((*detail).to_owned()))
            }
            Error::Io(io) => Self::Io(io.into()),
            Error::Cache(json) => Self::Cache(json.to_string()),
            Error::Offline => Self::Offline,
            Error::Conflict => Self::Conflict,
            Error::Logout(errors) => Self::Logout(errors.0.iter().map(Self::from).collect()),
        }
    }
}

impl From<WireError> for Error {
    fn from(error: WireError) -> Self {
        match error {
            WireError::Locked => Self::Locked,
            WireError::LoggedOut => Self::LoggedOut,
            WireError::InvalidPassword => Self::InvalidPassword,
            WireError::NotFound => Self::NotFound,
            WireError::NoSuchField => Self::NoSuchField,
            WireError::ReadOnly => Self::ReadOnly,
            WireError::Conflict => Self::Conflict,
            WireError::Offline | WireError::Api(ApiErrorDto::Http { offline: true, .. }) => {
                Self::Offline
            }
            WireError::Api(api) => Self::Api(api.into()),
            WireError::Crypto(crypto) => Self::Crypto(crypto.into()),
            WireError::Gen(GenErrorDto::InvalidTotp(detail)) => {
                Self::Gen(bwl_gen::Error::InvalidTotp(lookup(GEN_MESSAGES, &detail)))
            }
            WireError::Gen(GenErrorDto::InvalidOptions(detail)) => Self::Gen(
                bwl_gen::Error::InvalidOptions(lookup(GEN_MESSAGES, &detail)),
            ),
            WireError::Io(io) => Self::Io(io.into()),
            WireError::Cache(message) => Self::Cache(serde_json::Error::custom(message)),
            WireError::Logout(errors) => Self::Logout(bwl_vault::LogoutErrors(
                errors.into_iter().map(Self::from).collect(),
            )),
        }
    }
}

/// Server-side: a request whose DTO does not map onto the model.
impl From<ConvertError> for WireError {
    fn from(error: ConvertError) -> Self {
        match error {
            ConvertError::Url(url) => Self::Api(ApiErrorDto::Url(url.to_string())),
            other => Self::Io(IoErrorDto {
                kind: IoKind::InvalidInput,
                message: other.to_string(),
            }),
        }
    }
}

impl WireError {
    /// For daemon-side failures that are not vault errors, such as a panicked task.
    pub(crate) fn internal(message: String) -> Self {
        Self::Io(IoErrorDto {
            kind: IoKind::Other,
            message,
        })
    }
}

impl From<&bwl_api::Error> for ApiErrorDto {
    fn from(error: &bwl_api::Error) -> Self {
        match error {
            bwl_api::Error::Http(_) => Self::Http {
                message: error.to_string(),
                offline: error.is_offline(),
            },
            bwl_api::Error::Url(url) => Self::Url(url.to_string()),
            bwl_api::Error::Decode(json) => Self::Decode(json.to_string()),
            bwl_api::Error::Server { status, message } => Self::Server {
                status: *status,
                message: message.clone(),
            },
            bwl_api::Error::Unauthorized => Self::Unauthorized,
            bwl_api::Error::Io(io) => Self::Io(io.into()),
            bwl_api::Error::UntrustedUrl(host) => Self::UntrustedUrl(host.clone()),
            bwl_api::Error::InvalidServerUrl(_) => Self::Server {
                status: 400,
                message: error.to_string(),
            },
        }
    }
}

impl From<ApiErrorDto> for bwl_api::Error {
    fn from(error: ApiErrorDto) -> Self {
        match error {
            ApiErrorDto::Http { message, offline } => {
                let kind = if offline {
                    io::ErrorKind::NotConnected
                } else {
                    io::ErrorKind::Other
                };
                Self::Io(io::Error::new(kind, message))
            }
            ApiErrorDto::Url(message) => Self::Url(
                URL_ERRORS
                    .iter()
                    .copied()
                    .find(|known| known.to_string() == message)
                    .unwrap_or(url::ParseError::EmptyHost),
            ),
            ApiErrorDto::Decode(message) => Self::Decode(serde_json::Error::custom(message)),
            ApiErrorDto::Server { status, message } => Self::Server { status, message },
            ApiErrorDto::Unauthorized => Self::Unauthorized,
            ApiErrorDto::Io(io) => Self::Io(io.into()),
            ApiErrorDto::UntrustedUrl(host) => Self::UntrustedUrl(host),
        }
    }
}

impl From<&bwl_crypto::Error> for CryptoErrorDto {
    fn from(error: &bwl_crypto::Error) -> Self {
        use bwl_crypto::Error as E;
        match error {
            E::KdfTooWeak(detail) => Self::KdfTooWeak((*detail).to_owned()),
            E::KdfOutOfRange(detail) => Self::KdfOutOfRange((*detail).to_owned()),
            E::Kdf => Self::Kdf,
            E::UnsupportedKdf(kind) => Self::UnsupportedKdf(*kind),
            E::InvalidKeyLength(len) => {
                Self::InvalidKeyLength(u64::try_from(*len).unwrap_or(u64::MAX))
            }
            E::MalformedEncString(detail) => Self::MalformedEncString((*detail).to_owned()),
            E::UnsupportedEncType(kind) => Self::UnsupportedEncType(*kind),
            E::MacMismatch => Self::MacMismatch,
            E::MissingMacKey => Self::MissingMacKey,
            E::MacRequired => Self::MacRequired,
            E::Decrypt => Self::Decrypt,
            E::InvalidUtf8 => Self::InvalidUtf8,
            E::InvalidPrivateKey => Self::InvalidPrivateKey,
            E::Io(io) => Self::Io(io.into()),
        }
    }
}

impl From<CryptoErrorDto> for bwl_crypto::Error {
    fn from(error: CryptoErrorDto) -> Self {
        match error {
            CryptoErrorDto::KdfTooWeak(_) => Self::KdfTooWeak(UNKNOWN_DETAIL),
            CryptoErrorDto::KdfOutOfRange(_) => Self::KdfOutOfRange(UNKNOWN_DETAIL),
            CryptoErrorDto::Kdf => Self::Kdf,
            CryptoErrorDto::UnsupportedKdf(kind) => Self::UnsupportedKdf(kind),
            CryptoErrorDto::InvalidKeyLength(len) => {
                Self::InvalidKeyLength(usize::try_from(len).unwrap_or(usize::MAX))
            }
            CryptoErrorDto::MalformedEncString(detail) => {
                Self::MalformedEncString(lookup(CRYPTO_MESSAGES, &detail))
            }
            CryptoErrorDto::UnsupportedEncType(kind) => Self::UnsupportedEncType(kind),
            CryptoErrorDto::MacMismatch => Self::MacMismatch,
            CryptoErrorDto::MissingMacKey => Self::MissingMacKey,
            CryptoErrorDto::MacRequired => Self::MacRequired,
            CryptoErrorDto::Decrypt => Self::Decrypt,
            CryptoErrorDto::InvalidUtf8 => Self::InvalidUtf8,
            CryptoErrorDto::InvalidPrivateKey => Self::InvalidPrivateKey,
            CryptoErrorDto::Io(io) => Self::Io(io.into()),
        }
    }
}

impl From<&io::Error> for IoErrorDto {
    fn from(error: &io::Error) -> Self {
        Self {
            kind: error.kind().into(),
            message: error.to_string(),
        }
    }
}

impl From<IoErrorDto> for io::Error {
    fn from(error: IoErrorDto) -> Self {
        Self::new(error.kind.into(), error.message)
    }
}

impl From<io::ErrorKind> for IoKind {
    fn from(kind: io::ErrorKind) -> Self {
        use io::ErrorKind as K;
        match kind {
            K::NotFound => Self::NotFound,
            K::PermissionDenied => Self::PermissionDenied,
            K::AlreadyExists => Self::AlreadyExists,
            K::InvalidInput => Self::InvalidInput,
            K::InvalidData => Self::InvalidData,
            K::TimedOut => Self::TimedOut,
            K::UnexpectedEof => Self::UnexpectedEof,
            K::Interrupted => Self::Interrupted,
            K::Unsupported => Self::Unsupported,
            K::OutOfMemory => Self::OutOfMemory,
            K::StorageFull => Self::StorageFull,
            K::ConnectionRefused => Self::ConnectionRefused,
            K::ConnectionReset => Self::ConnectionReset,
            K::ConnectionAborted => Self::ConnectionAborted,
            K::NotConnected => Self::NotConnected,
            K::BrokenPipe => Self::BrokenPipe,
            _ => Self::Other,
        }
    }
}

impl From<IoKind> for io::ErrorKind {
    fn from(kind: IoKind) -> Self {
        match kind {
            IoKind::NotFound => Self::NotFound,
            IoKind::PermissionDenied => Self::PermissionDenied,
            IoKind::AlreadyExists => Self::AlreadyExists,
            IoKind::InvalidInput => Self::InvalidInput,
            IoKind::InvalidData => Self::InvalidData,
            IoKind::TimedOut => Self::TimedOut,
            IoKind::UnexpectedEof => Self::UnexpectedEof,
            IoKind::Interrupted => Self::Interrupted,
            IoKind::Unsupported => Self::Unsupported,
            IoKind::OutOfMemory => Self::OutOfMemory,
            IoKind::StorageFull => Self::StorageFull,
            IoKind::ConnectionRefused => Self::ConnectionRefused,
            IoKind::ConnectionReset => Self::ConnectionReset,
            IoKind::ConnectionAborted => Self::ConnectionAborted,
            IoKind::NotConnected => Self::NotConnected,
            IoKind::BrokenPipe => Self::BrokenPipe,
            IoKind::Other => Self::Other,
        }
    }
}

fn lookup(table: &[&'static str], message: &str) -> &'static str {
    table
        .iter()
        .copied()
        .find(|known| *known == message)
        .unwrap_or(UNKNOWN_DETAIL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{HEADER_LEN, decode, encode};

    /// Daemon error -> wire -> client error, as `RemoteVault` sees it.
    fn proxied(error: &Error) -> Error {
        let frame = encode(&WireError::from(error)).expect("encode");
        Error::from(decode::<WireError>(&frame[HEADER_LEN..]).expect("decode"))
    }

    #[test]
    fn plain_vault_variants_round_trip() {
        for error in [
            Error::Locked,
            Error::LoggedOut,
            Error::InvalidPassword,
            Error::NotFound,
            Error::NoSuchField,
            Error::ReadOnly,
        ] {
            let back = proxied(&error);
            assert_eq!(
                std::mem::discriminant(&back),
                std::mem::discriminant(&error)
            );
        }
    }

    #[test]
    fn edit_conflict_round_trips_with_its_message() {
        let back = proxied(&Error::Conflict);
        assert!(matches!(back, Error::Conflict), "{back:?}");
        assert_eq!(back.to_string(), bwl_vault::CONFLICT_MESSAGE);
    }

    #[test]
    fn offline_write_refusal_round_trips() {
        let back = proxied(&Error::Offline);
        assert!(matches!(back, Error::Offline), "{back:?}");
        assert!(back.is_offline());
        assert_eq!(back.to_string(), bwl_vault::OFFLINE_MESSAGE);
    }

    #[test]
    fn gateway_status_keeps_status_message_and_offline_flag() {
        let back = proxied(&Error::Api(bwl_api::Error::Server {
            status: 502,
            message: "Bad Gateway".to_owned(),
        }));
        assert!(back.is_offline());
        assert!(matches!(
            &back,
            Error::Api(bwl_api::Error::Server { status: 502, message }) if message == "Bad Gateway"
        ));
    }

    #[tokio::test]
    async fn an_unreachable_server_is_still_offline_after_the_trip() {
        // A real reqwest transport failure: nothing listens on the discard port.
        let failure = reqwest::Client::new()
            .get("http://127.0.0.1:9/alive")
            .send()
            .await
            .expect_err("nothing listens on port 9");
        let error = Error::Api(bwl_api::Error::Http(failure));
        assert!(error.is_offline(), "precondition: {error:?}");
        let back = proxied(&error);
        assert!(matches!(back, Error::Offline), "{back:?}");
        assert!(back.is_offline());
    }

    #[test]
    fn logout_errors_keep_every_step() {
        let error = Error::Logout(bwl_vault::LogoutErrors(vec![
            Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "keychain locked",
            )),
            Error::NotFound,
        ]));
        let back = proxied(&error);
        let Error::Logout(bwl_vault::LogoutErrors(steps)) = &back else {
            panic!("expected Logout, got {back:?}");
        };
        assert_eq!(steps.len(), 2);
        assert!(matches!(&steps[0], Error::Io(io) if io.kind() == io::ErrorKind::PermissionDenied));
        assert!(matches!(steps[1], Error::NotFound));
        assert_eq!(back.to_string(), error.to_string());
    }

    #[test]
    fn server_unauthorized_untrusted_and_api_io_errors_round_trip() {
        let back = proxied(&Error::Api(bwl_api::Error::Server {
            status: 400,
            message: "Username or password is incorrect".to_owned(),
        }));
        assert!(matches!(
            &back,
            Error::Api(bwl_api::Error::Server { status: 400, message })
                if message == "Username or password is incorrect"
        ));
        assert!(!back.is_offline());
        assert!(matches!(
            proxied(&Error::Api(bwl_api::Error::Unauthorized)),
            Error::Api(bwl_api::Error::Unauthorized)
        ));
        assert!(matches!(
            proxied(&Error::Api(bwl_api::Error::UntrustedUrl("evil.example".to_owned()))),
            Error::Api(bwl_api::Error::UntrustedUrl(host)) if host == "evil.example"
        ));
        let back = proxied(&Error::Api(bwl_api::Error::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset by peer",
        ))));
        let Error::Api(bwl_api::Error::Io(io)) = &back else {
            panic!("expected Api(Io), got {back:?}");
        };
        assert_eq!(io.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(back.to_string(), "i/o error: reset by peer");
    }

    #[test]
    fn offline_http_errors_become_offline_and_others_api_io_with_their_text() {
        let unreachable = WireError::Api(ApiErrorDto::Http {
            message: "network error: error sending request".to_owned(),
            offline: true,
        });
        let back = Error::from(unreachable);
        assert!(matches!(back, Error::Offline), "{back:?}");
        assert!(back.is_offline());
        let builder = WireError::Api(ApiErrorDto::Http {
            message: "network error: builder error".to_owned(),
            offline: false,
        });
        let back = Error::from(builder);
        let Error::Api(bwl_api::Error::Io(io)) = &back else {
            panic!("expected Api(Io), got {back:?}");
        };
        assert_eq!(io.kind(), io::ErrorKind::Other);
        assert_eq!(back.to_string(), "i/o error: network error: builder error");
        assert!(!back.is_offline());
    }

    #[test]
    fn url_decode_and_cache_errors_keep_their_variant_and_text() {
        let back = proxied(&Error::Api(bwl_api::Error::Url(
            url::ParseError::InvalidPort,
        )));
        assert!(matches!(
            back,
            Error::Api(bwl_api::Error::Url(url::ParseError::InvalidPort))
        ));
        let json = serde_json::from_str::<u8>("x").expect_err("invalid JSON");
        let text = json.to_string();
        let back = proxied(&Error::Api(bwl_api::Error::Decode(json)));
        assert_eq!(back.to_string(), format!("unexpected response: {text}"));
        let json = serde_json::from_str::<u8>("[").expect_err("invalid JSON");
        let text = json.to_string();
        let back = proxied(&Error::Cache(json));
        assert!(matches!(&back, Error::Cache(_)));
        assert_eq!(back.to_string(), format!("corrupt cache: {text}"));
    }

    #[test]
    fn crypto_errors_round_trip() {
        use bwl_crypto::Error as C;
        let cases = [
            C::Kdf,
            C::UnsupportedKdf(9),
            C::InvalidKeyLength(17),
            C::MalformedEncString("invalid base64"),
            C::UnsupportedEncType(6),
            C::MacMismatch,
            C::MissingMacKey,
            C::MacRequired,
            C::Decrypt,
            C::InvalidUtf8,
            C::InvalidPrivateKey,
        ];
        for error in cases {
            let text = error.to_string();
            let back = proxied(&Error::Crypto(error));
            assert!(matches!(back, Error::Crypto(_)));
            assert_eq!(back.to_string(), text);
        }
        let back = proxied(&Error::Crypto(C::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "early eof",
        ))));
        assert_eq!(
            back.to_string(),
            "I/O error while streaming encrypted data: early eof"
        );
    }

    #[test]
    fn unknown_static_details_fall_back_to_a_generic_text() {
        let back = proxied(&Error::Crypto(bwl_crypto::Error::KdfTooWeak(
            "PBKDF2 iterations below 600000",
        )));
        assert!(matches!(
            back,
            Error::Crypto(bwl_crypto::Error::KdfTooWeak(UNKNOWN_DETAIL))
        ));
        let back = proxied(&Error::Crypto(bwl_crypto::Error::MalformedEncString(
            "a message added later",
        )));
        assert!(matches!(
            back,
            Error::Crypto(bwl_crypto::Error::MalformedEncString(UNKNOWN_DETAIL))
        ));
    }

    #[test]
    fn generator_errors_keep_known_messages() {
        let back = proxied(&Error::Gen(bwl_gen::Error::InvalidTotp(
            "secret is not valid base32",
        )));
        assert_eq!(
            back.to_string(),
            "invalid TOTP secret or URI: secret is not valid base32"
        );
        let back = proxied(&Error::Gen(bwl_gen::Error::InvalidOptions(
            "passphrase must have 3..=20 words",
        )));
        assert!(matches!(
            back,
            Error::Gen(bwl_gen::Error::InvalidOptions(
                "passphrase must have 3..=20 words"
            ))
        ));
    }

    #[test]
    fn totp_messages_from_the_generator_crate_are_all_known() {
        // Each of these inputs hits a different InvalidTotp message in bwl-gen.
        for input in [
            "",
            "otpauth://hotp/x?secret=JBSWY3DP",
            "otpauth://totp/x",
            "!!!",
        ] {
            let error = bwl_gen::totp::Totp::parse(input).expect_err("invalid secret");
            let wire = WireError::from(&Error::Gen(error));
            let back = Error::from(wire);
            assert!(
                !back.to_string().contains(UNKNOWN_DETAIL),
                "{input:?}: {back}"
            );
        }
    }

    #[test]
    fn storage_errors_keep_kind_and_text() {
        let error = Error::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Permission denied (os error 13)",
        ));
        let back = proxied(&error);
        let Error::Io(io) = &back else {
            panic!("expected Io");
        };
        assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            back.to_string(),
            "storage error: Permission denied (os error 13)"
        );
        let back = proxied(&Error::Io(io::Error::new(io::ErrorKind::Deadlock, "odd")));
        let Error::Io(io) = &back else {
            panic!("expected Io");
        };
        assert_eq!(io.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn convert_errors_become_request_errors() {
        assert_eq!(
            WireError::from(ConvertError::Url(url::ParseError::EmptyHost)),
            WireError::Api(ApiErrorDto::Url("empty host".to_owned()))
        );
        assert_eq!(
            WireError::from(ConvertError::UnknownProvider(4)),
            WireError::Io(IoErrorDto {
                kind: IoKind::InvalidInput,
                message: "unknown two-factor provider 4".to_owned(),
            })
        );
    }
}
