//! Where both processes keep their files under the data dir (`~/Library/Application Support/vaultkeeper`).

#[cfg(feature = "vw-it")]
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

pub const UI_SOCKET: &str = "ui.sock";
pub const SSH_SOCKET: &str = "ssh-agent.sock";
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
