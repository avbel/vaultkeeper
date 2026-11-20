//! Launch at login with `--tray`.
//!
//! macOS uses `~/Library/LaunchAgents/vaultkeeper.plist`; Windows uses the per-user Run key under
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, where Settings → Apps → Startup records a
//! user's "off" in `Explorer\StartupApproved\Run`.
//!
//! The LaunchAgent is written here rather than through a library so it can carry
//! `KeepAlive { SuccessfulExit = false }`: launchd restarts vaultkeeper after a crash or an abort
//! (non-zero exit or a signal) but not after Quit, which exits with 0. It points at the current
//! executable, so enabling again after the app moved updates the path, and [`refresh`] brings an
//! agent written by an older version of this executable up to date.

use crate::Result;

#[cfg(any(target_os = "macos", windows, test))]
const TRAY_ARG: &str = "--tray";

/// The Run key command: the exe quoted because its path may contain spaces, then `--tray`.
#[cfg(any(windows, test))]
fn run_command(exe: &std::path::Path) -> Result<String> {
    let exe = exe.to_str().ok_or_else(|| {
        crate::Error::Autostart(format!("executable path is not UTF-8: {}", exe.display()))
    })?;
    Ok(format!("\"{exe}\" {TRAY_ARG}"))
}

/// Whether a `StartupApproved\Run` value records the item as enabled.
///
/// Windows stores a 12-byte `REG_BINARY`: the first byte is 2 (or 6) when the user left the item
/// on and 3 (or 7) when they switched it off in Settings → Apps → Startup. An absent value means
/// no decision was recorded, so the Run entry still starts.
#[cfg(any(windows, test))]
fn startup_approved_is_on(value: &[u8]) -> bool {
    matches!(value.first(), None | Some(2 | 6))
}

pub fn set_enabled(enabled: bool) -> Result<()> {
    imp::set_enabled(enabled)
}

pub fn is_enabled() -> Result<bool> {
    imp::is_enabled()
}

/// Whether the login mechanism started this process rather than the user: on macOS launchd sets
/// `XPC_SERVICE_NAME` to the job's label, on Windows the Run value passes `--tray`.
#[must_use]
pub fn started_by_login_agent() -> bool {
    imp::started_by_login_agent()
}

/// Rewrites an enabled entry that starts a different executable than the one running now, which
/// is what an update or a move leaves behind. Returns whether it rewrote it.
pub fn refresh() -> Result<bool> {
    imp::refresh()
}

#[cfg(target_os = "macos")]
mod imp {
    use std::path::{Path, PathBuf};

    use crate::Result;

    use super::TRAY_ARG;

    const LABEL: &str = "vaultkeeper";

    pub(super) fn set_enabled(enabled: bool) -> Result<()> {
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

    pub(super) fn is_enabled() -> Result<bool> {
        Ok(plist_path()?.is_file())
    }

    /// LaunchServices launches get an `application.…` name, so only a launchd job matching the
    /// label is restarted by `KeepAlive` when it exits non-zero.
    pub(super) fn started_by_login_agent() -> bool {
        std::env::var("XPC_SERVICE_NAME").is_ok_and(|name| name == LABEL)
    }

    /// An agent for another executable (the installed app, while a dev build runs) is left alone.
    pub(super) fn refresh() -> Result<bool> {
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
}

#[cfg(windows)]
mod imp {
    use std::{io, path::PathBuf, ptr};

    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, WIN32_ERROR},
        System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, KEY_WRITE, REG_EXPAND_SZ,
            REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteValueW,
            RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
        },
    };

    use crate::Result;

    use super::TRAY_ARG;

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const APPROVED_KEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    const VALUE_NAME: &str = "Vaultkeeper";
    /// A concurrent writer is not expected for our own value; one retry still covers it.
    const SIZE_RETRIES: u32 = 2;

    /// Owns a registry key so every early return still closes it exactly once.
    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from `RegOpenKeyExW`/`RegCreateKeyExW` and nothing else owns
            // it, so it is closed once when this wrapper is dropped.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }

    pub(super) fn set_enabled(enabled: bool) -> Result<()> {
        if !enabled {
            delete_value(RUN_KEY, VALUE_NAME)?;
            // The approval record only exists to gate the Run value; drop it with the value.
            let _ = delete_value(APPROVED_KEY, VALUE_NAME);
            return Ok(());
        }

        let command = super::run_command(&current_exe()?)?;
        set_value(RUN_KEY, VALUE_NAME, REG_SZ, &utf16_bytes(&command))?;
        // A "switched off" mark survives the Run value and would keep the new command off, so an
        // explicit enable overrides the earlier Settings decision.
        let _ = delete_value(APPROVED_KEY, VALUE_NAME);
        Ok(())
    }

    pub(super) fn is_enabled() -> Result<bool> {
        if read_string(RUN_KEY, VALUE_NAME)?.is_none() {
            return Ok(false);
        }
        match read_value(APPROVED_KEY, VALUE_NAME)? {
            Some((_, data)) => Ok(super::startup_approved_is_on(&data)),
            None => Ok(true),
        }
    }

    pub(super) fn started_by_login_agent() -> bool {
        std::env::args_os().any(|arg| arg.to_str() == Some(TRAY_ARG))
    }

    pub(super) fn refresh() -> Result<bool> {
        let Some(current) = read_string(RUN_KEY, VALUE_NAME)? else {
            return Ok(false);
        };
        let wanted = super::run_command(&current_exe()?)?;
        if current == wanted {
            return Ok(false);
        }
        set_value(RUN_KEY, VALUE_NAME, REG_SZ, &utf16_bytes(&wanted))?;
        Ok(true)
    }

    /// `canonicalize` would add a `\\?\` verbatim prefix, which does not belong in a Run value;
    /// `current_exe` already returns an absolute path.
    fn current_exe() -> Result<PathBuf> {
        Ok(std::env::current_exe()?)
    }

    fn open_key(path: &str, access: u32) -> io::Result<Key> {
        let path = wide(path);
        let mut handle = ptr::null_mut();
        // SAFETY: `path` is NUL-terminated and outlives the call; `handle` is a valid out-pointer
        // the API fills only on success.
        let status =
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, access, &raw mut handle) };
        if status == ERROR_SUCCESS {
            Ok(Key(handle))
        } else {
            Err(os_error(status))
        }
    }

    fn create_key(path: &str) -> io::Result<Key> {
        let path = wide(path);
        let mut handle = ptr::null_mut();
        let mut disposition = 0;
        // SAFETY: the class and security attributes are optional and passed as null; `path` is
        // NUL-terminated and both out-pointers are valid for the call.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                ptr::null(),
                &raw mut handle,
                &raw mut disposition,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(Key(handle))
        } else {
            Err(os_error(status))
        }
    }

    fn set_value(path: &str, name: &str, kind: u32, data: &[u8]) -> io::Result<()> {
        let key = create_key(path)?;
        let name = wide(name);
        let len = u32::try_from(data.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry value is longer than 4 GiB",
            )
        })?;
        // SAFETY: `name` is NUL-terminated, `data` stays alive for `len` bytes across the call and
        // the key was opened with write access.
        let status = unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, kind, data.as_ptr(), len) };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(os_error(status))
        }
    }

    fn delete_value(path: &str, name: &str) -> io::Result<()> {
        let key = match open_key(path, KEY_SET_VALUE) {
            Ok(key) => key,
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        let name = wide(name);
        // SAFETY: `name` is NUL-terminated and the key is open with KEY_SET_VALUE.
        let status = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
        if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(os_error(status))
        }
    }

    fn read_string(path: &str, name: &str) -> io::Result<Option<String>> {
        let Some((kind, data)) = read_value(path, name)? else {
            return Ok(None);
        };
        if kind != REG_SZ && kind != REG_EXPAND_SZ {
            return Ok(None);
        }
        Ok(Some(decode_utf16(&data)))
    }

    fn read_value(path: &str, name: &str) -> io::Result<Option<(u32, Vec<u8>)>> {
        let key = match open_key(path, KEY_READ) {
            Ok(key) => key,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let name = wide(name);
        let mut kind = 0;
        let mut len = 0;
        // SAFETY: a null buffer with a zero length asks only for the size, and both out-pointers
        // are valid for the call.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                ptr::null(),
                &raw mut kind,
                ptr::null_mut(),
                &raw mut len,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(os_error(status));
        }

        for _ in 0..SIZE_RETRIES {
            let mut data = vec![0_u8; usize::try_from(len).unwrap_or(usize::MAX)];
            let mut actual = len;
            // SAFETY: `data` has room for `actual` bytes; the API writes at most that many and
            // updates `actual` to the value's size.
            let status = unsafe {
                RegQueryValueExW(
                    key.0,
                    name.as_ptr(),
                    ptr::null(),
                    &raw mut kind,
                    data.as_mut_ptr(),
                    &raw mut actual,
                )
            };
            if status == ERROR_SUCCESS {
                data.truncate(usize::try_from(actual).unwrap_or(usize::MAX));
                return Ok(Some((kind, data)));
            }
            if status != ERROR_MORE_DATA {
                return Err(os_error(status));
            }
            // The value grew between the probe and the read; `actual` holds the new size.
            len = actual;
        }
        Err(io::Error::other(
            "registry value kept growing while it was being read",
        ))
    }

    fn is_not_found(error: &io::Error) -> bool {
        error.raw_os_error() == Some(error_code(ERROR_FILE_NOT_FOUND))
    }

    fn os_error(status: WIN32_ERROR) -> io::Error {
        io::Error::from_raw_os_error(error_code(status))
    }

    const fn error_code(status: WIN32_ERROR) -> i32 {
        status.cast_signed()
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn utf16_bytes(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn decode_utf16(data: &[u8]) -> String {
        let (pairs, _) = data.as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
        let end = units
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(units.len());
        String::from_utf16_lossy(&units[..end])
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn enabling_writes_the_run_value_and_disable_removes_it() {
            set_enabled(false).expect("clean slate");
            assert!(!is_enabled().expect("disabled"));

            set_enabled(true).expect("enable");
            assert!(is_enabled().expect("enabled"));
            let command = read_string(RUN_KEY, VALUE_NAME)
                .expect("read")
                .expect("value written");
            assert_eq!(
                command,
                super::super::run_command(&current_exe().expect("exe")).expect("command")
            );
            assert!(!refresh().expect("already current"));

            set_value(
                RUN_KEY,
                VALUE_NAME,
                REG_SZ,
                &utf16_bytes("old\\vaultkeeper.exe --tray"),
            )
            .expect("stale value");
            assert!(refresh().expect("moved exe is rewritten"));
            assert_eq!(
                read_string(RUN_KEY, VALUE_NAME)
                    .expect("read")
                    .expect("value"),
                super::super::run_command(&current_exe().expect("exe")).expect("command")
            );

            set_enabled(false).expect("disable");
            assert!(!is_enabled().expect("disabled again"));
            set_enabled(false).expect("disable when already off");
        }
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use crate::{Error, Result};

    pub(super) fn set_enabled(_enabled: bool) -> Result<()> {
        Err(Error::Unsupported)
    }

    pub(super) fn is_enabled() -> Result<bool> {
        Err(Error::Unsupported)
    }

    pub(super) const fn started_by_login_agent() -> bool {
        false
    }

    pub(super) fn refresh() -> Result<bool> {
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{run_command, startup_approved_is_on};

    #[test]
    fn the_run_command_quotes_the_exe_and_adds_the_tray_flag() {
        assert_eq!(
            run_command(Path::new(r"C:\Program Files\Vaultkeeper\vaultkeeper.exe"))
                .expect("command"),
            r#""C:\Program Files\Vaultkeeper\vaultkeeper.exe" --tray"#
        );
        assert_eq!(
            run_command(Path::new(r"C:\vk\vaultkeeper.exe")).expect("command"),
            r#""C:\vk\vaultkeeper.exe" --tray"#
        );
    }

    #[test]
    fn a_missing_or_enabled_startup_approval_counts_as_on() {
        assert!(startup_approved_is_on(&[]));
        assert!(startup_approved_is_on(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
        assert!(startup_approved_is_on(&[
            6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
        assert!(!startup_approved_is_on(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
        assert!(!startup_approved_is_on(&[
            7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
    }
}
