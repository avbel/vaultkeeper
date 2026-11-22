//! Linux half of the startup permission checks (linux-plan.md 2a). Each path is opened with
//! `O_PATH | O_NOFOLLOW` and checked and repaired through that descriptor, so a path swapped for a
//! symlink between the check and the chmod is refused, never followed. `O_PATH` needs no read
//! permission, so a file the user owns but made unreadable (mode 0000) is repaired, not refused.

use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::AsRawFd as _,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
};

use super::{DIR_MODE, FILE_MODE, Refusal, Repair};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Dir,
    File,
}

pub(super) fn verify(path: &Path, kind: Kind) -> Result<Repair, Refusal> {
    let Some(file) = open(path, kind)? else {
        return Ok(Repair::None);
    };
    let io = |source| Refusal::Io {
        path: path.to_owned(),
        source,
    };
    let meta = file.metadata().map_err(io)?;
    // With O_PATH a trailing symlink is opened, not refused with ELOOP, and the chmod below
    // would follow it.
    if meta.file_type().is_symlink() {
        return Err(Refusal::Symlink {
            path: path.to_owned(),
        });
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(Refusal::ForeignOwner {
            path: path.to_owned(),
            uid: meta.uid(),
        });
    }
    let wanted = match kind {
        Kind::Dir => DIR_MODE,
        Kind::File => FILE_MODE,
    };
    if meta.mode() & 0o7777 == wanted {
        return Ok(Repair::None);
    }
    set_mode(&file, wanted).map_err(io)?;
    Ok(Repair::Rewritten {
        dacl: true,
        label: false,
        attribute: false,
    })
}

pub(super) fn verify_files<P: AsRef<Path>>(paths: &[P]) -> Result<Repair, Refusal> {
    paths.iter().try_fold(Repair::None, |repair, path| {
        let next = verify(path.as_ref(), Kind::File)?;
        Ok(if next == Repair::None { repair } else { next })
    })
}

/// `fchmod` fails with `EBADF` on an `O_PATH` descriptor and `fchmodat(AT_EMPTY_PATH)` needs
/// Linux 6.6, so the mode is set through the descriptor's `/proc` link, which names the inode the
/// descriptor holds rather than resolving the original path again.
fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    let through_fd = format!("/proc/self/fd/{}", file.as_raw_fd());
    std::fs::set_permissions(through_fd, std::fs::Permissions::from_mode(mode))
}

/// `None` for a missing path. A symlink as the last component is opened as the link itself, or
/// fails with `ENOTDIR` when `O_DIRECTORY` is set too.
fn open(path: &Path, kind: Kind) -> Result<Option<File>, Refusal> {
    let mut options = OpenOptions::new();
    // std needs an access mode; O_PATH ignores it and checks no permission on the file.
    options.read(true);
    let directory = if kind == Kind::Dir {
        libc::O_DIRECTORY
    } else {
        0
    };
    options.custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC | directory);
    match options.open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error)
            if error.raw_os_error() == Some(libc::ELOOP)
                || (error.raw_os_error() == Some(libc::ENOTDIR) && path.is_symlink()) =>
        {
            Err(Refusal::Symlink {
                path: path.to_owned(),
            })
        }
        Err(source) => Err(Refusal::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").mode() & 0o7777
    }

    #[test]
    fn wrong_modes_are_repaired_and_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod");
        let file = dir.path().join("settings.json");
        fs::write(&file, b"{}").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod");

        assert_ne!(verify(dir.path(), Kind::Dir).expect("dir"), Repair::None);
        assert_ne!(verify_files(&[&file]).expect("file"), Repair::None);
        assert_eq!(mode(dir.path()), 0o700);
        assert_eq!(mode(&file), 0o600);
        assert_eq!(verify(dir.path(), Kind::Dir).expect("again"), Repair::None);
    }

    #[test]
    fn missing_files_are_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            verify_files(&[dir.path().join("vault.json")]).expect("missing"),
            Repair::None
        );
    }

    #[test]
    fn symlinks_are_refused_not_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real");
        fs::create_dir(&target).expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("chmod");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(matches!(
            verify(&link, Kind::Dir),
            Err(Refusal::Symlink { .. })
        ));
        assert_eq!(mode(&target), 0o755, "the link target is untouched");
    }

    #[test]
    fn a_file_symlink_is_refused_not_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real.json");
        fs::write(&target, b"{}").expect("write");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("chmod");
        let link = dir.path().join("vault.json");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(matches!(
            verify_files(&[&link]),
            Err(Refusal::Symlink { .. })
        ));
        assert_eq!(mode(&target), 0o644, "the link target is untouched");
    }

    /// A root run (Docker) can open any mode anyway, so there it passes without the O_PATH open too.
    #[test]
    fn an_unreadable_file_and_dir_of_the_user_are_repaired_not_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("vault.json");
        fs::write(&file, b"{}").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).expect("chmod");
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).expect("dir");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod");

        assert_ne!(verify_files(&[&file]).expect("file"), Repair::None);
        assert_ne!(verify(&locked, Kind::Dir).expect("dir"), Repair::None);
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&locked), 0o700);
    }

    /// `/` is root-owned; a non-root run sees a foreign owner, a root run (Docker) owns it.
    #[test]
    fn foreign_owner_is_refused() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                verify(Path::new("/"), Kind::Dir),
                Err(Refusal::ForeignOwner { uid: 0, .. })
            ));
        }
    }
}
