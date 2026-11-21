//! The auto-type RemoteDesktop grant's restore token, in a file of its own so a revoked
//! clipboard grant does not take the keyboard grant with it. The file lives in the data
//! directory with mode 0600 and is read without following symlinks.

use std::{
    io::Read as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

use vk_platform::fs::write_private_atomic;

use crate::os::layout::AUTOTYPE_PORTAL_TOKEN_FILE;

/// Portal tokens are short; anything longer is not one of ours.
const MAX_TOKEN_BYTES: u64 = 4096;

pub(super) struct TokenStore(PathBuf);

impl TokenStore {
    pub(super) fn in_dir(data_dir: &Path) -> Self {
        Self(data_dir.join(AUTOTYPE_PORTAL_TOKEN_FILE))
    }

    pub(super) fn load(&self) -> Option<String> {
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

    pub(super) fn save(&self, token: &str) {
        if let Err(error) = write_private_atomic(&self.0, token.as_bytes()) {
            tracing::warn!(%error, "could not store the auto-type portal restore token");
        }
    }

    pub(super) fn forget(&self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(%error, "could not remove the stale auto-type token"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, symlink};

    use super::*;

    #[test]
    fn a_saved_token_comes_back_with_mode_0600() {
        let dir = tempfile::tempdir().expect("dir");
        let store = TokenStore::in_dir(dir.path());
        assert_eq!(store.load(), None);
        store.save("abc123");
        assert_eq!(store.load().as_deref(), Some("abc123"));
        let mode = std::fs::metadata(dir.path().join(AUTOTYPE_PORTAL_TOKEN_FILE))
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
        symlink(&target, dir.path().join(AUTOTYPE_PORTAL_TOKEN_FILE)).expect("link");
        assert_eq!(TokenStore::in_dir(dir.path()).load(), None);
    }

    #[test]
    fn a_fifo_in_place_of_the_token_file_is_ignored() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join(AUTOTYPE_PORTAL_TOKEN_FILE);
        let c_path = std::ffi::CString::new(path.to_str().expect("utf8")).expect("c string");
        // SAFETY: `c_path` is a valid NUL-terminated path; mkfifo only creates a node.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert_eq!(TokenStore::in_dir(dir.path()).load(), None);
    }

    #[test]
    fn an_oversized_token_is_cut_at_the_cap() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(
            dir.path().join(AUTOTYPE_PORTAL_TOKEN_FILE),
            "x".repeat(10_000),
        )
        .expect("write");
        let token = TokenStore::in_dir(dir.path()).load().expect("token");
        assert_eq!(token.len(), 4096);
    }
}
