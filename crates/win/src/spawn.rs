//! Hardened child-process creation for Windows.
//!
//! The command-line quoting sits here rather than behind `cfg(windows)` because it is the part most
//! likely to be got wrong, and testing the exact bytes is only possible on the machine we build on.
//! The Win32 half lives in `spawn/windows.rs`.

use std::ffi::OsStr;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{Child, SpawnOptions, spawn_hardened};

/// Quotes one argument with the rules `CommandLineToArgvW` and the MSVC CRT use to split
/// `argv[0]`: quotes only when needed, then double the backslashes before a quote (and before the
/// closing quote), since a backslash is literal unless it precedes a quote.
#[must_use]
pub fn quote_arg(arg: &str) -> String {
    let mut units = Vec::with_capacity(arg.len() + 2);
    let encoded: Vec<u16> = arg.encode_utf16().collect();
    quote_units(&encoded, &mut units);
    String::from_utf16(&units).expect("quoting valid UTF-8 yields valid UTF-16")
}

/// Builds a NUL-terminated command line for `CommandLineToArgvW`: the exe, then each argument,
/// space separated.
#[must_use]
pub fn command_line(exe: &OsStr, args: &[impl AsRef<OsStr>]) -> Vec<u16> {
    let mut units = Vec::new();
    append_os(exe, &mut units);
    for arg in args {
        units.push(u16::from(b' '));
        append_os(arg.as_ref(), &mut units);
    }
    units.push(0);
    units
}

#[cfg(windows)]
fn append_os(value: &OsStr, out: &mut Vec<u16>) {
    use std::os::windows::ffi::OsStrExt as _;

    let units: Vec<u16> = value.encode_wide().collect();
    quote_units(&units, out);
}

#[cfg(not(windows))]
fn append_os(value: &OsStr, out: &mut Vec<u16>) {
    // `quote_arg` takes `&str`, which is all the portable tests need; there is no wide view of an
    // `OsStr` off Windows.
    let text = value.to_string_lossy();
    let units: Vec<u16> = text.encode_utf16().collect();
    quote_units(&units, out);
}

pub(crate) fn quote_units(arg: &[u16], out: &mut Vec<u16>) {
    const SPACE: u16 = 0x20;
    const TAB: u16 = 0x09;
    const QUOTE: u16 = 0x22;
    const BACKSLASH: u16 = 0x5c;

    let needs_quotes = arg.is_empty()
        || arg
            .iter()
            .any(|&unit| unit == SPACE || unit == TAB || unit == QUOTE);
    if !needs_quotes {
        out.extend_from_slice(arg);
        return;
    }

    out.push(QUOTE);
    let mut backslashes = 0_usize;
    for &unit in arg {
        if unit == BACKSLASH {
            backslashes += 1;
        } else if unit == QUOTE {
            push_repeated(BACKSLASH, backslashes * 2 + 1, out);
            out.push(QUOTE);
            backslashes = 0;
        } else {
            push_repeated(BACKSLASH, backslashes, out);
            out.push(unit);
            backslashes = 0;
        }
    }
    // A backslash immediately before the closing quote would escape it, so it is doubled too.
    push_repeated(BACKSLASH, backslashes * 2, out);
    out.push(QUOTE);
}

fn push_repeated(unit: u16, count: usize, out: &mut Vec<u16>) {
    out.extend(std::iter::repeat_n(unit, count));
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::{command_line, quote_arg};

    #[test]
    fn simple_arguments_are_not_quoted() {
        assert_eq!(quote_arg("simple"), "simple");
        assert_eq!(quote_arg("C:\\Windows\\System32"), "C:\\Windows\\System32");
        assert_eq!(quote_arg("a\\b"), "a\\b");
    }

    #[test]
    fn empty_arguments_keep_their_place() {
        assert_eq!(quote_arg(""), "\"\"");
    }

    #[test]
    fn whitespace_triggers_quotes() {
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg("a\tb"), "\"a\tb\"");
    }

    #[test]
    fn embedded_quotes_are_escaped() {
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn backslashes_before_a_quote_are_doubled_and_the_quote_escaped() {
        assert_eq!(quote_arg("a\\\"b"), "\"a\\\\\\\"b\"");
    }

    #[test]
    fn trailing_backslashes_are_doubled_inside_quotes() {
        assert_eq!(quote_arg("a b\\"), "\"a b\\\\\"");
    }

    #[test]
    fn a_command_line_quotes_each_argument_and_ends_with_nul() {
        let args = ["--ui-pipe".to_owned(), "12 34".to_owned()];
        let line = command_line(OsStr::new("C:\\Program Files\\vk.exe"), &args);

        assert_eq!(*line.last().expect("terminating NUL"), 0);
        let text = String::from_utf16(&line[..line.len() - 1]).expect("valid UTF-16");
        assert_eq!(text, "\"C:\\Program Files\\vk.exe\" --ui-pipe \"12 34\"");
    }
}
