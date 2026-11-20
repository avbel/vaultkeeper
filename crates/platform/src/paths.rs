//! `~/Library/Application Support/vaultkeeper` on macOS (platform data dir elsewhere).

use std::path::{Path, PathBuf};

use directories::ProjectDirs;

use crate::Result;

const APP_DIR: &str = "vaultkeeper";

/// Creates the directory (mode 0700) if missing, and tightens its mode if it exists. On Windows an
/// existing directory is only verified later by the startup check.
pub fn data_dir() -> Result<PathBuf> {
    let dir = project_data_dir()?;
    crate::fs::create_private_dir_if_missing(&dir)?;
    Ok(dir)
}

/// Where the daemon's sockets and instance lock live. On Linux that is `$XDG_RUNTIME_DIR/vaultkeeper`
/// (per-session tmpfs, never in a backup, gone at logout); elsewhere, and for any data dir other
/// than the default one (tests, e2e runs), the data dir itself, so parallel runs never share
/// sockets. The caller creates it with [`crate::fs::ensure_private_dir`].
#[must_use]
pub fn socket_dir(data_dir: &Path) -> PathBuf {
    let runtime =
        if cfg!(target_os = "linux") && project_data_dir().is_ok_and(|dir| dir == data_dir) {
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
        } else {
            None
        };
    socket_dir_in(data_dir, runtime.as_deref())
}

/// The rule of [`socket_dir`] with the runtime dir passed in. An unset runtime dir keeps the
/// sockets in the data dir; the Linux startup gate reports it as a missing requirement.
#[must_use]
pub fn socket_dir_in(data_dir: &Path, runtime_dir: Option<&Path>) -> PathBuf {
    runtime_dir.map_or_else(|| data_dir.to_owned(), |runtime| runtime.join(APP_DIR))
}

// `from_path` keeps the name verbatim; `ProjectDirs::from` would derive it from qualifier and
// organization as well.
fn project_data_dir() -> Result<PathBuf> {
    ProjectDirs::from_path(PathBuf::from(APP_DIR))
        .map(|dirs| local_data_dir(&dirs).to_path_buf())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "home directory not found").into()
        })
}

// Roaming data would sync the sealed key blobs to other machines, where DPAPI cannot open them.
#[cfg(windows)]
fn local_data_dir(dirs: &ProjectDirs) -> &std::path::Path {
    dirs.data_local_dir()
}

#[cfg(not(windows))]
fn local_data_dir(dirs: &ProjectDirs) -> &std::path::Path {
    dirs.data_dir()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;

    #[cfg(unix)]
    #[test]
    fn sockets_go_to_the_runtime_dir_when_there_is_one() {
        let data = Path::new("/home/u/.local/share/vaultkeeper");
        assert_eq!(
            socket_dir_in(data, Some(Path::new("/run/user/1000"))),
            Path::new("/run/user/1000/vaultkeeper")
        );
        assert_eq!(socket_dir_in(data, None), data);
    }

    #[cfg(unix)]
    #[test]
    fn a_custom_data_dir_keeps_its_sockets() {
        let custom = Path::new("/tmp/vaultkeeper-test-1");
        assert_eq!(socket_dir(custom), custom);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn data_dir_is_application_support_vaultkeeper() {
        let home = std::env::var_os("HOME").expect("HOME is set");
        let expected = PathBuf::from(home).join("Library/Application Support/vaultkeeper");
        assert_eq!(project_data_dir().expect("data dir"), expected);
    }

    #[cfg(unix)]
    #[test]
    fn data_dir_exists_and_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = data_dir().expect("data dir");
        let mode = std::fs::metadata(&dir)
            .expect("metadata")
            .permissions()
            .mode();
        assert!(dir.is_dir());
        assert_eq!(mode & 0o777, 0o700);
    }
}
