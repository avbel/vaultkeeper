//! `~/Library/Application Support/vaultkeeper` on macOS (platform data dir elsewhere).

use std::path::PathBuf;

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
