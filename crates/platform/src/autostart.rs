//! Launch at login (LaunchAgent on macOS) with `--tray`.
//!
//! The agent file is `~/Library/LaunchAgents/bw-lite.plist` and points at the current
//! executable, so enabling again after the app moved updates the path.

use crate::Result;

#[cfg(target_os = "macos")]
const LABEL: &str = "bw-lite";
#[cfg(target_os = "macos")]
const TRAY_ARG: &str = "--tray";

pub fn set_enabled(enabled: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let agent = macos::launcher(&macos::current_exe()?)?;
        if enabled {
            agent.enable()
        } else {
            agent.disable()
        }
        .map_err(|err| macos::autostart_error(&err))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = enabled;
        Err(crate::Error::Unsupported)
    }
}

pub fn is_enabled() -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        let agent = macos::launcher(&macos::current_exe()?)?;
        agent
            .is_enabled()
            .map_err(|err| macos::autostart_error(&err))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(crate::Error::Unsupported)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::path::{Path, PathBuf};

    use auto_launch::{AutoLaunch, AutoLaunchBuilder, MacOSLaunchMode};

    use super::{LABEL, TRAY_ARG};
    use crate::{Error, Result};

    pub(super) fn autostart_error(err: &auto_launch::Error) -> Error {
        Error::Autostart(err.to_string())
    }

    pub(super) fn current_exe() -> Result<PathBuf> {
        Ok(std::env::current_exe()?.canonicalize()?)
    }

    pub(super) fn launcher(exe: &Path) -> Result<AutoLaunch> {
        let path = exe.to_str().ok_or_else(|| {
            Error::Autostart(format!("executable path is not UTF-8: {}", exe.display()))
        })?;
        // auto-launch writes the path into the plist XML without escaping.
        if path.contains(['&', '<', '>']) {
            return Err(Error::Autostart(format!(
                "executable path contains characters a LaunchAgent cannot hold: {path}"
            )));
        }
        AutoLaunchBuilder::new()
            .set_app_name(LABEL)
            .set_app_path(path)
            .set_macos_launch_mode(MacOSLaunchMode::LaunchAgent)
            .set_args(&[TRAY_ARG])
            .build()
            .map_err(|err| autostart_error(&err))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn launcher_runs_the_given_exe_with_tray_flag() {
            let agent = launcher(Path::new(
                "/Applications/bw-lite.app/Contents/MacOS/bw-lite",
            ))
            .expect("launcher");
            assert_eq!(agent.get_app_name(), "bw-lite");
            assert_eq!(
                agent.get_app_path(),
                "/Applications/bw-lite.app/Contents/MacOS/bw-lite"
            );
            assert_eq!(agent.get_args(), ["--tray"]);
        }

        #[test]
        fn launcher_rejects_paths_that_would_break_the_plist() {
            for path in ["/tmp/a&b/bw-lite", "/tmp/<x>/bw-lite"] {
                assert!(
                    matches!(launcher(Path::new(path)), Err(Error::Autostart(_))),
                    "{path}"
                );
            }
        }

        #[test]
        fn current_exe_is_absolute() {
            assert!(current_exe().expect("current exe").is_absolute());
        }
    }
}
