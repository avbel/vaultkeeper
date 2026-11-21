//! Linux half of autostart: an XDG autostart entry (linux-plan.md 3g, chain C11 link 3), which
//! GNOME, KDE and UWSM sessions such as Omarchy's start at login. Stock Sway reads none, so
//! Settings shows the `exec` line for it instead. The Background portal and a systemd user unit
//! (links 1 and 2) can join once the VM runs show a desktop that needs them.

use std::path::{Path, PathBuf};

use super::TRAY_ARG;
use crate::{
    Error, Result,
    desktop_file::{APP_ID, config_home, exec_quote},
};

/// The autostart entry for `exe` (the stable install path). Never carries
/// `--skip-security-issues`: an accepted issue set is what lets a login start proceed.
pub(super) fn render(exe: &Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Vaultkeeper\n\
         Exec={} {TRAY_ARG}\n\
         Icon={APP_ID}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        exec_quote(exe)
    )
}

/// A user who switched the entry off in their desktop's startup settings gets `Hidden=true` or
/// `X-GNOME-Autostart-enabled=false` written into it; that counts as off.
pub(super) fn is_on(entry: &str) -> bool {
    !entry.lines().any(|line| {
        matches!(
            line.trim(),
            "Hidden=true" | "X-GNOME-Autostart-enabled=false"
        )
    })
}

fn entry_path() -> Result<PathBuf> {
    config_home()
        .map(|config| config.join(format!("autostart/{APP_ID}.desktop")))
        .ok_or_else(|| Error::Autostart("neither XDG_CONFIG_HOME nor HOME is set".to_owned()))
}

fn install_path() -> Result<PathBuf> {
    crate::install_kind::current_install_path()
        .ok_or_else(|| Error::Autostart("cannot locate the running executable".to_owned()))
}

fn write(path: &Path, exe: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    crate::fs::write_private_atomic(path, render(exe).as_bytes())?;
    Ok(())
}

pub(super) fn set_enabled(enabled: bool) -> Result<()> {
    let path = entry_path()?;
    if enabled {
        return write(&path, &install_path()?);
    }
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

pub(super) fn is_enabled() -> Result<bool> {
    match std::fs::read_to_string(entry_path()?) {
        Ok(entry) => Ok(is_on(&entry)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn started_by_login_agent() -> bool {
    std::env::args_os().any(|arg| arg.to_str() == Some(TRAY_ARG))
}

/// Rewrites an enabled entry that names another executable; a switched-off one stays as it is.
pub(super) fn refresh() -> Result<bool> {
    let path = entry_path()?;
    let Ok(entry) = std::fs::read_to_string(&path) else {
        return Ok(false);
    };
    let exe = install_path()?;
    if !is_on(&entry) || entry == render(&exe) {
        return Ok(false);
    }
    write(&path, &exe)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_starts_the_tray_from_the_install_path() {
        let entry = render(Path::new(
            "/home/linuxbrew/.linuxbrew/opt/vaultkeeper/bin/vaultkeeper",
        ));
        assert!(entry.contains(
            "\nExec=/home/linuxbrew/.linuxbrew/opt/vaultkeeper/bin/vaultkeeper --tray\n"
        ));
        assert!(!entry.contains("--skip-security-issues"));
        assert!(is_on(&entry));
    }

    #[test]
    fn desktops_switch_it_off_in_the_file() {
        let entry = render(Path::new("/usr/bin/vaultkeeper"));
        assert!(!is_on(&format!("{entry}Hidden=true\n")));
        assert!(!is_on(&entry.replace(
            "X-GNOME-Autostart-enabled=true",
            "X-GNOME-Autostart-enabled=false"
        )));
    }
}
