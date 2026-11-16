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
    /// Windows only: another program owns the OpenSSH pipe.
    #[error("{}", pipe_taken_message(*.service_running))]
    PipeTaken {
        /// Windows' own "OpenSSH Authentication Agent" service is running.
        service_running: bool,
    },
}

const SERVICE_RUNNING_MESSAGE: &str = "Windows' OpenSSH Authentication Agent is already running and owns the SSH agent pipe. To use Vaultkeeper's agent, run in an administrator PowerShell: Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled \u{2014} then turn the SSH agent on again.";

const OTHER_OWNER_MESSAGE: &str = "Another program already serves the Windows SSH agent pipe (\\\\.\\pipe\\openssh-ssh-agent). Close it, then turn the SSH agent on again.";

const fn pipe_taken_message(service_running: bool) -> &'static str {
    if service_running {
        SERVICE_RUNNING_MESSAGE
    } else {
        OTHER_OWNER_MESSAGE
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_service_gets_the_commands_to_disable_it() {
        let message = AgentError::PipeTaken {
            service_running: true,
        }
        .to_string();

        assert!(message.contains("Stop-Service ssh-agent"));
        assert!(message.contains("Set-Service ssh-agent -StartupType Disabled"));
    }

    #[test]
    fn another_owner_gets_the_generic_message() {
        let message = AgentError::PipeTaken {
            service_running: false,
        }
        .to_string();

        assert!(message.contains(r"\\.\pipe\openssh-ssh-agent"));
        assert!(!message.contains("Stop-Service"));
    }
}
