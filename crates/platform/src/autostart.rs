//! Launch at login (a LaunchAgent on macOS) with `--tray`.
//!
//! The agent file is `~/Library/LaunchAgents/vaultkeeper.plist`, written here rather than through a
//! library so it can carry `KeepAlive { SuccessfulExit = false }`: launchd restarts vaultkeeper after
//! a crash or an abort (non-zero exit or a signal) but not after Quit, which exits with 0. It points
//! at the current executable, so enabling again after the app moved updates the path, and
//! [`refresh`] brings an agent written by an older version of this executable up to date.

use std::path::{Path, PathBuf};

use crate::Result;

const LABEL: &str = "vaultkeeper";
const TRAY_ARG: &str = "--tray";

pub fn set_enabled(enabled: bool) -> Result<()> {
    let plist = plist_path()?;
    if enabled {
        write_agent(&plist, &current_exe()?)
    } else {
        match std::fs::remove_file(&plist) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }
}

pub fn is_enabled() -> Result<bool> {
    Ok(plist_path()?.is_file())
}

/// Rewrites an enabled agent that starts this executable but differs from what this version
/// writes (an older one without `KeepAlive`). An agent for another executable (the installed
/// app, while a dev build runs) is left alone. Returns whether it rewrote it.
pub fn refresh() -> Result<bool> {
    let plist = plist_path()?;
    let Ok(current) = std::fs::read_to_string(&plist) else {
        return Ok(false);
    };
    let exe = current_exe()?;
    let wanted = agent_plist(&exe)?;
    let ours = exe
        .to_str()
        .is_some_and(|exe| current.contains(&format!("<string>{}</string>", xml_escape(exe))));
    if !ours || current == wanted {
        return Ok(false);
    }
    crate::fs::write_private_atomic(&plist, wanted.as_bytes())?;
    Ok(true)
}

fn plist_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "home directory not found")
        })?;
    Ok(PathBuf::from(home)
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

fn current_exe() -> Result<PathBuf> {
    Ok(std::env::current_exe()?.canonicalize()?)
}

fn write_agent(plist: &Path, exe: &Path) -> Result<()> {
    let contents = agent_plist(exe)?;
    if let Some(dir) = plist.parent() {
        std::fs::create_dir_all(dir)?;
    }
    crate::fs::write_private_atomic(plist, contents.as_bytes())?;
    Ok(())
}

/// The agent's property list (launchd.plist(5)).
fn agent_plist(exe: &Path) -> Result<String> {
    let exe = exe.to_str().ok_or_else(|| {
        crate::Error::Autostart(format!("executable path is not UTF-8: {}", exe.display()))
    })?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>{arg}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
</dict>
</plist>
"#,
        label = LABEL,
        exe = xml_escape(exe),
        arg = TRAY_ARG,
    ))
}

fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_characters_in_the_path_are_escaped() {
        assert_eq!(
            xml_escape(r#"/Apps/A&B <x> "q" 'a'/vaultkeeper"#),
            "/Apps/A&amp;B &lt;x&gt; &quot;q&quot; &apos;a&apos;/vaultkeeper"
        );
    }

    #[test]
    fn the_agent_runs_the_given_exe_in_the_tray_and_restarts_only_after_a_failure() {
        let plist = agent_plist(Path::new(
            "/Applications/Vaultkeeper.app/Contents/MacOS/vaultkeeper",
        ))
        .expect("plist");
        assert!(plist.contains(
            "<array>\n    <string>/Applications/Vaultkeeper.app/Contents/MacOS/vaultkeeper</string>\n    \
             <string>--tray</string>\n  </array>"
        ));
        assert!(plist.contains(
            "<key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>"
        ));
    }

    #[test]
    fn current_exe_is_absolute() {
        assert!(current_exe().expect("current exe").is_absolute());
    }
}
