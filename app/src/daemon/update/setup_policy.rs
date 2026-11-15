//! The portable part of the Windows installer hand-off: when an update may run and how.

/// Inno Setup switches: no wizard, no message boxes, and never reboot the machine; the installer
/// stops a running daemon itself with `--quit`.
const SETUP_ARGS: [&str; 3] = ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"];

#[must_use]
pub fn setup_args() -> Vec<String> {
    SETUP_ARGS.iter().map(|arg| (*arg).to_owned()).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("this build is not Authenticode-signed, so it never updates itself")]
    RunningUnsigned,
    #[error("the downloaded installer has no valid Authenticode signature")]
    InstallerUnsigned,
}

/// Both the running exe and the downloaded installer must carry a valid Authenticode chain, on
/// top of the Ed25519 signature that the caller has already checked. The publisher is not
/// compared (§8.3): the Ed25519 key is the trust anchor, Authenticode only keeps Smart App
/// Control happy.
pub const fn decide(running_signed: bool, installer_signed: bool) -> Result<(), Refusal> {
    if !running_signed {
        return Err(Refusal::RunningUnsigned);
    }
    if !installer_signed {
        return Err(Refusal::InstallerUnsigned);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_installer_runs_silently_without_rebooting() {
        assert_eq!(
            setup_args(),
            ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
        );
    }

    #[test]
    fn only_signed_builds_install_signed_installers() {
        assert_eq!(decide(true, true), Ok(()));
        assert_eq!(decide(false, true), Err(Refusal::RunningUnsigned));
        assert_eq!(decide(true, false), Err(Refusal::InstallerUnsigned));
        assert_eq!(decide(false, false), Err(Refusal::RunningUnsigned));
    }
}
