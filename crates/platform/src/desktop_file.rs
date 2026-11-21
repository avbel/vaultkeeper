//! Shared pieces of the freedesktop files Vaultkeeper writes on Linux: the launcher entry and the
//! autostart entry (Desktop Entry and Base Directory specifications).

use std::path::{Path, PathBuf};

pub const APP_ID: &str = "io.github.avbel.Vaultkeeper";

/// Desktop Entry Specification quoting for an `Exec=` program path: a path with reserved
/// characters goes in double quotes, with `"`, `` ` ``, `$` and `\` escaped.
#[must_use]
pub fn exec_quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    let reserved = |c: char| c.is_whitespace() || "\"'\\><~|&;$*?#()`".contains(c);
    if !text.chars().any(reserved) {
        return text.into_owned();
    }
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for c in text.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

/// `$XDG_DATA_HOME`, or `~/.local/share`.
#[must_use]
pub fn data_home() -> Option<PathBuf> {
    base_dir("XDG_DATA_HOME", ".local/share")
}

/// `$XDG_CONFIG_HOME`, or `~/.config`.
#[must_use]
pub fn config_home() -> Option<PathBuf> {
    base_dir("XDG_CONFIG_HOME", ".config")
}

/// `$XDG_STATE_HOME`, or `~/.local/state`.
#[must_use]
pub fn state_home() -> Option<PathBuf> {
    base_dir("XDG_STATE_HOME", ".local/state")
}

/// `$XDG_CACHE_HOME`, or `~/.cache`.
#[must_use]
pub fn cache_home() -> Option<PathBuf> {
    base_dir("XDG_CACHE_HOME", ".cache")
}

/// A relative or empty value is ignored, as the spec requires.
fn base_dir(variable: &str, fallback: &str) -> Option<PathBuf> {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(fallback)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_with_reserved_characters_are_quoted_and_escaped() {
        assert_eq!(
            exec_quote(Path::new("/opt/vk/bin/vaultkeeper")),
            "/opt/vk/bin/vaultkeeper"
        );
        assert_eq!(
            exec_quote(Path::new("/home/me/My Apps/vaultkeeper")),
            "\"/home/me/My Apps/vaultkeeper\""
        );
        assert_eq!(exec_quote(Path::new("/a$b/vk")), "\"/a\\$b/vk\"");
    }
}
