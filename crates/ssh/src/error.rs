use std::path::PathBuf;

/// Failures of [`crate::SshAgent`] that callers may want to tell apart; they travel inside
/// `anyhow::Error` and can be recovered with `downcast_ref`.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("the SSH agent must be started from inside a Tokio runtime")]
    NoRuntime,
    #[error("another SSH agent is already serving {}", .0.display())]
    AlreadyRunning(PathBuf),
    #[error("{} exists and is not a socket", .0.display())]
    NotASocket(PathBuf),
    #[error("cannot prepare {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the SSH agent is not running")]
    NotRunning,
}

/// Why a pasted key could not be turned into an OpenSSH key; recover it with `downcast_ref`.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("the input is not a private key")]
    NotAPrivateKey,
    #[error("unsupported key format: {0}")]
    UnsupportedFormat(String),
    #[error("unsupported key algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("the key is encrypted, a passphrase is required")]
    PassphraseRequired,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error(
        "encrypted PEM and PKCS#8 keys are not supported; remove the passphrase first, \
         for example with `ssh-keygen -p -N '' -f <key>`"
    )]
    EncryptedPemUnsupported,
    #[error("malformed or unsupported {0} private key")]
    Malformed(&'static str),
    #[error("cannot encode the key: {0}")]
    Encode(#[source] ssh_key::Error),
}
