//! Command-line flags.

use crate::settings::ThemeChoice;

pub const USAGE: &str = "usage: bw-lite [--mock] [--tray] [--offline] [--unlocked] [--theme system|light|dark] [--demo-ssh]
               [--size WxH] [--select QUERY] [--quick]

  --mock       run on the built-in mock vault (master password: mock)
  --tray       start with no window, only the tray icon
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
    fn rejects_unknown_and_bad_theme() {
        assert_eq!(
            args(&["--nope"]),
            Err(CliError::Unknown("--nope".to_owned()))
        );
        assert_eq!(args(&["--theme"]), Err(CliError::Theme));
        assert_eq!(args(&["--theme", "blue"]), Err(CliError::Theme));
    }
}
