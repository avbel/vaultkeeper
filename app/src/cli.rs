//! Command-line flags.

use crate::settings::ThemeChoice;

pub const USAGE: &str = "usage: vaultkeeper [--daemon | --tray | --quick]
       vaultkeeper --mock [--tray] [--offline] [--unlocked] [--theme system|light|dark] [--demo-ssh]
               [--size WxH] [--select QUERY] [--quick]

  (no flag)    start vaultkeeper (or ask the running one) and open the vault window
  --daemon     run in the menu bar only; windows open on demand
  --tray       same as --daemon (what start at login uses)
  --quick      open the Quick Panel
  --mock       run on the built-in mock vault (master password: mock)
  --offline    mock: start with the server unreachable
  --unlocked   mock: start with the first account unlocked
  --theme      override the theme setting for this run
  --demo-ssh   mock: show an SSH sign request a few seconds after start
  --size       Manager window size in logical pixels, e.g. 760x480
  --select     open the Manager on the first item matching QUERY
  --quick      open the Quick Panel at start";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Args {
    pub mock: bool,
    pub daemon: bool,
    /// The window process the daemon starts; never typed by hand.
    pub ui: bool,
    /// With `--ui`: no unlock happened since the daemon started.
    pub first_unlock: bool,
    pub tray: bool,
    pub offline: bool,
    pub unlocked: bool,
    pub theme: Option<ThemeChoice>,
    pub demo_ssh: bool,
    pub size: Option<(u32, u32)>,
    pub select: Option<String>,
    pub quick: bool,
    pub help: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliError {
    #[error("unknown argument `{0}`\n\n{USAGE}")]
    Unknown(String),
    #[error("--theme needs one of system, light, dark\n\n{USAGE}")]
    Theme,
    #[error("--size needs WIDTHxHEIGHT, e.g. 760x480\n\n{USAGE}")]
    Size,
    #[error("--select needs a search query\n\n{USAGE}")]
    Select,
}

fn parse_size(text: Option<&str>) -> Result<(u32, u32), CliError> {
    let (width, height) = text
        .and_then(|text| text.split_once('x'))
        .ok_or(CliError::Size)?;
    Ok((
        width.parse().map_err(|_| CliError::Size)?,
        height.parse().map_err(|_| CliError::Size)?,
    ))
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Args, CliError> {
    let mut parsed = Args::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mock" => parsed.mock = true,
            "--daemon" => parsed.daemon = true,
            "--ui" => parsed.ui = true,
            "--first-unlock" => parsed.first_unlock = true,
            "--tray" => parsed.tray = true,
            "--offline" => parsed.offline = true,
            "--unlocked" => parsed.unlocked = true,
            "--demo-ssh" => parsed.demo_ssh = true,
            "--quick" => parsed.quick = true,
            "--size" => parsed.size = Some(parse_size(args.next().as_deref())?),
            "--select" => parsed.select = Some(args.next().ok_or(CliError::Select)?),
            "-h" | "--help" => parsed.help = true,
            "--theme" => {
                parsed.theme = Some(match args.next().as_deref() {
                    Some("system") => ThemeChoice::System,
                    Some("light") => ThemeChoice::Light,
                    Some("dark") => ThemeChoice::Dark,
                    _ => return Err(CliError::Theme),
                });
            }
            _ => return Err(CliError::Unknown(arg)),
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Args, CliError> {
        parse(list.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn parses_flags() {
        let parsed = args(&["--mock", "--tray", "--theme", "dark", "--offline"]).expect("args");
        assert!(parsed.mock && parsed.tray && parsed.offline);
        assert_eq!(parsed.theme, Some(ThemeChoice::Dark));
        assert!(!parsed.unlocked && !parsed.demo_ssh);
        assert_eq!(args(&[]).expect("empty"), Args::default());
    }

    #[test]
    fn parses_screenshot_flags() {
        let parsed =
            args(&["--size", "760x480", "--select", "tailscale", "--quick"]).expect("args");
        assert_eq!(parsed.size, Some((760, 480)));
        assert_eq!(parsed.select.as_deref(), Some("tailscale"));
        assert!(parsed.quick);
        assert_eq!(args(&["--size", "760"]), Err(CliError::Size));
        assert_eq!(args(&["--size", "ax480"]), Err(CliError::Size));
        assert_eq!(args(&["--select"]), Err(CliError::Select));
    }

    #[test]
    fn parses_process_modes() {
        let daemon = args(&["--daemon"]).expect("daemon");
        assert!(daemon.daemon && !daemon.ui && !daemon.mock);
        let ui = args(&["--ui", "--first-unlock"]).expect("ui");
        assert!(ui.ui && ui.first_unlock);
        assert!(!args(&["--ui"]).expect("ui").first_unlock);
    }

    #[test]
    fn rejects_unknown_and_bad_theme() {
        assert_eq!(
            args(&["--nope"]),
            Err(CliError::Unknown("--nope".to_owned()))
        );
        assert_eq!(args(&["--theme"]), Err(CliError::Theme));
        assert_eq!(args(&["--theme", "blue"]), Err(CliError::Theme));
    }
}

/// Which process to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Mock,
    Ui { first_unlock: bool },
    Daemon(crate::daemon::routing::Launch),
}

impl Args {
    #[must_use]
    pub const fn mode(&self) -> Mode {
        use crate::daemon::routing::Launch;
        if self.mock {
            Mode::Mock
        } else if self.ui {
            Mode::Ui {
                first_unlock: self.first_unlock,
            }
        } else if self.daemon || self.tray {
            Mode::Daemon(Launch::Tray)
        } else if self.quick {
            Mode::Daemon(Launch::QuickPanel)
        } else {
            Mode::Daemon(Launch::Manager)
        }
    }
}

#[cfg(test)]
mod mode_tests {
    use super::*;
    use crate::daemon::routing::Launch;

    fn mode(list: &[&str]) -> Mode {
        parse(list.iter().map(|arg| (*arg).to_owned()))
            .expect("args")
            .mode()
    }

    #[test]
    fn flags_pick_the_process() {
        assert_eq!(mode(&[]), Mode::Daemon(Launch::Manager));
        assert_eq!(mode(&["--tray"]), Mode::Daemon(Launch::Tray), "autostart");
        assert_eq!(mode(&["--daemon"]), Mode::Daemon(Launch::Tray));
        assert_eq!(mode(&["--quick"]), Mode::Daemon(Launch::QuickPanel));
        assert_eq!(
            mode(&["--ui"]),
            Mode::Ui {
                first_unlock: false
            }
        );
        assert_eq!(
            mode(&["--ui", "--first-unlock"]),
            Mode::Ui { first_unlock: true }
        );
        assert_eq!(mode(&["--mock", "--tray"]), Mode::Mock);
    }
}
