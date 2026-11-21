//! A RemoteDesktop grant's restore token. Clipboard and auto-type each keep theirs in a file of
//! its own so revoking one grant does not take the other with it. The file lives in the data
//! directory with mode 0600 and is read without following symlinks.

use std::{io::Read as _, os::unix::fs::OpenOptionsExt as _, path::PathBuf};

use vk_platform::fs::write_private_atomic;

/// Portal tokens are short; anything longer is not one of ours.
const MAX_TOKEN_BYTES: u64 = 4096;

pub struct TokenStore(PathBuf);

impl TokenStore {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self(path)
    }

    #[must_use]
    pub fn load(&self) -> Option<String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.0)
            .ok()?;
        // A planted FIFO or device would block or feed endless data.
        if !file.metadata().ok()?.is_file() {
            return None;
        }
        let mut token = String::new();
        file.take(MAX_TOKEN_BYTES).read_to_string(&mut token).ok()?;
        let token = token.trim();
        (!token.is_empty()).then(|| token.to_owned())
    }

    pub fn save(&self, token: &str) {
        if let Err(error) = write_private_atomic(&self.0, token.as_bytes()) {
            tracing::warn!(%error, "could not store the portal restore token");
        }
    }

    pub fn forget(&self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(%error, "could not remove the stale portal restore token"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, symlink};

    use super::*;

    const TOKEN_FILE: &str = "test-portal-token";

    fn in_dir(dir: &std::path::Path) -> TokenStore {
        TokenStore::new(dir.join(TOKEN_FILE))
    }

    #[test]
    fn a_saved_token_comes_back_with_mode_0600() {
        let dir = tempfile::tempdir().expect("dir");
        let store = in_dir(dir.path());
        assert_eq!(store.load(), None);
        store.save("abc123");
        assert_eq!(store.load().as_deref(), Some("abc123"));
        let mode = std::fs::metadata(dir.path().join(TOKEN_FILE))
            .expect("file")
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        store.forget();
        assert_eq!(store.load(), None);
    }

    #[test]
    fn a_symlinked_token_file_is_not_followed() {
        let dir = tempfile::tempdir().expect("dir");
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "planted").expect("write");
        symlink(&target, dir.path().join(TOKEN_FILE)).expect("link");
        assert_eq!(in_dir(dir.path()).load(), None);
    }

    #[test]
    fn a_fifo_in_place_of_the_token_file_is_ignored() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join(TOKEN_FILE);
        let c_path = std::ffi::CString::new(path.to_str().expect("utf8")).expect("c string");
        // SAFETY: `c_path` is a valid NUL-terminated path; mkfifo only creates a node.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert_eq!(in_dir(dir.path()).load(), None);
    }

    #[test]
    fn an_oversized_token_is_cut_at_the_cap() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join(TOKEN_FILE), "x".repeat(10_000)).expect("write");
        let token = in_dir(dir.path()).load().expect("token");
        assert_eq!(token.len(), 4096);
    }
}
