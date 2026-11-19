//! Where both processes keep their files under the data dir (`~/Library/Application Support/vaultkeeper`).

#[cfg(feature = "vw-it")]
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use vk_ipc::transport::Endpoint;

const UI_SOCKET: &str = "ui.sock";
const CLI_SOCKET: &str = "cli.sock";
const BROWSER_SOCKET: &str = "browser.sock";
const SSH_SOCKET: &str = "ssh-agent.sock";
#[cfg(any(windows, test))]
const OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
pub const BROWSER_PAIRINGS_FILE: &str = "browsers.json";
pub const BROWSER_CHOICES_FILE: &str = "browser-choices.json";
pub const SETTINGS_FILE: &str = "settings.json";
pub const DEVICE_FILE: &str = "device.json";
const ACCOUNTS_DIR: &str = "accounts";
const TOUCH_ID_FILE: &str = "touchid.bin";
/// Server user ids are UUIDs (36 chars); anything else must not become a path component.
const MAX_ACCOUNT_ID_LEN: usize = 64;

/// The data dir of both processes. Builds with the `vw-it` feature honour
/// `VAULTKEEPER_TEST_DATA_DIR`, so an e2e run keeps the real HOME (the login keychain does not work
/// under a fake one: it shows a dialog) but none of the real files.
pub fn data_dir() -> vk_platform::Result<PathBuf> {
    #[cfg(feature = "vw-it")]
    if let Some(dir) = std::env::var_os("VAULTKEEPER_TEST_DATA_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        return Ok(dir);
    }
    vk_platform::paths::data_dir()
}

/// Pipe names are global to the machine, so the user's SID keeps two users' daemons apart.
#[cfg(any(windows, test))]
fn pipe_name(sid: &str, kind: &str) -> String {
    format!(r"\\.\pipe\vaultkeeper.{sid}.{kind}")
}

#[cfg(windows)]
fn user_pipe(kind: &str) -> Endpoint {
    // The SID of the running user is always readable; an empty one would still be unique per kind
    // but shared across users, so fail loudly instead.
    let sid = vk_win::current_user_sid().expect("the current user's SID is readable");
    Endpoint::pipe(pipe_name(&sid, kind))
}

/// Daemon to UI process channel.
// Windows: the UI channel has no name; the daemon hands it to the UI process it spawns
// (plan step 2e), so this stays the Unix path until then.
#[must_use]
pub fn ui_endpoint(data_dir: &Path) -> Endpoint {
    Endpoint::path(data_dir.join(UI_SOCKET))
}

#[must_use]
pub fn cli_endpoint(data_dir: &Path) -> Endpoint {
    #[cfg(windows)]
    {
        let _ = (data_dir, CLI_SOCKET);
        user_pipe("cli")
    }
    #[cfg(not(windows))]
    {
        Endpoint::path(data_dir.join(CLI_SOCKET))
    }
}

#[must_use]
pub fn browser_endpoint(data_dir: &Path) -> Endpoint {
    #[cfg(windows)]
    {
        let _ = (data_dir, BROWSER_SOCKET);
        user_pipe("browser")
    }
    #[cfg(not(windows))]
    {
        Endpoint::path(data_dir.join(BROWSER_SOCKET))
    }
}

/// The single-instance rendezvous. Unix keeps it in `vk-platform`, which names its own files.
#[cfg(windows)]
#[must_use]
pub fn instance_endpoint() -> Endpoint {
    user_pipe("instance")
}

/// Windows ssh clients look for the OpenSSH agent at a fixed pipe name.
#[must_use]
pub fn ssh_endpoint(data_dir: &Path) -> Endpoint {
    #[cfg(windows)]
    {
        let _ = (data_dir, SSH_SOCKET);
        Endpoint::pipe(OPENSSH_AGENT_PIPE)
    }
    #[cfg(not(windows))]
    {
        Endpoint::path(data_dir.join(SSH_SOCKET))
    }
}

/// The file behind a socket endpoint, for the servers that still bind by path.
pub fn socket_path(endpoint: &Endpoint) -> std::io::Result<PathBuf> {
    endpoint.as_path().map(Path::to_path_buf).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("{endpoint} is not a socket file"),
        )
    })
}

/// `accounts/<account_id>/touchid.bin`, inside the account directory that log out deletes.
/// `None` for ids that are not plain `[A-Za-z0-9-]` names, so an id can never escape the
/// accounts directory.
#[must_use]
pub fn touch_id_file(data_dir: &Path, account_id: &str) -> Option<PathBuf> {
    let plain = !account_id.is_empty()
        && account_id.len() <= MAX_ACCOUNT_ID_LEN
        && account_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    plain.then(|| {
        data_dir
            .join(ACCOUNTS_DIR)
            .join(account_id)
            .join(TOUCH_ID_FILE)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_names_embed_the_sid_and_kind() {
        assert_eq!(
            pipe_name("S-1-5-21-1-2-3-1001", "cli"),
            r"\\.\pipe\vaultkeeper.S-1-5-21-1-2-3-1001.cli"
        );
        assert_ne!(pipe_name("S-1-5-18", "cli"), pipe_name("S-1-5-19", "cli"));
        assert_ne!(
            pipe_name("S-1-5-18", "cli"),
            pipe_name("S-1-5-18", "browser")
        );
        assert_eq!(OPENSSH_AGENT_PIPE, r"\\.\pipe\openssh-ssh-agent");
    }

    #[cfg(unix)]
    #[test]
    fn unix_endpoints_are_the_socket_files_in_the_data_dir() {
        let dir = Path::new("/data");
        for (endpoint, file) in [
            (ui_endpoint(dir), "ui.sock"),
            (cli_endpoint(dir), "cli.sock"),
            (browser_endpoint(dir), "browser.sock"),
            (ssh_endpoint(dir), "ssh-agent.sock"),
        ] {
            assert_eq!(endpoint.as_path(), Some(dir.join(file).as_path()));
        }
    }

    #[test]
    fn touch_id_lives_in_the_account_directory() {
        let dir = Path::new("/data");
        assert_eq!(
            touch_id_file(dir, "3bef05d6-9070-48b4-b320-a5d425eec9fd"),
            Some(PathBuf::from(
                "/data/accounts/3bef05d6-9070-48b4-b320-a5d425eec9fd/touchid.bin"
            ))
        );
    }

    #[test]
    fn ids_that_could_escape_are_refused() {
        let dir = Path::new("/data");
        for id in [
            "",
            "..",
            "../x",
            "a/b",
            "a\\b",
            "a.b",
            "a b",
            &"x".repeat(65),
        ] {
            assert_eq!(touch_id_file(dir, id), None, "{id:?}");
        }
    }
}
