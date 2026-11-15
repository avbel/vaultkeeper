//! Private on-disk state: owner-only directories and atomically replaced files.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

#[cfg(windows)]
mod windows;

#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// What a startup permission check changed, so the daemon and UI can log the repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Repair {
    #[default]
    None,
    /// Each flag records which part differed and was rewritten.
    Rewritten {
        dacl: bool,
        label: bool,
        attribute: bool,
    },
}

impl Repair {
    #[cfg(windows)]
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::None, other) => other,
            (this, Self::None) => this,
            (
                Self::Rewritten {
                    dacl: first_dacl,
                    label: first_label,
                    attribute: first_attribute,
                },
                Self::Rewritten {
                    dacl: second_dacl,
                    label: second_label,
                    attribute: second_attribute,
                },
            ) => Self::Rewritten {
                dacl: first_dacl || second_dacl,
                label: first_label || second_label,
                attribute: first_attribute || second_attribute,
            },
        }
    }
}

/// Why a startup permission check refused a path. A refusal stops startup: the path is not ours,
/// or someone was granted access that Vaultkeeper never gives.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    #[error("{} is a reparse point", path.display())]
    ReparsePoint { path: PathBuf },
    #[error("{} is owned by {owner}, not the user or Administrators", path.display())]
    Owner { path: PathBuf, owner: String },
    #[error("{} grants access to {sid}", path.display())]
    ForeignAce { path: PathBuf, sid: String },
    #[error("cannot check {}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
}

/// Checks ownership, DACL, mandatory label and index attribute of the data directory, repairing
/// them when the owner is right. On Unix this is a no-op until the Linux permission checks use it.
pub fn verify_private_dir(path: &Path) -> Result<Repair, Refusal> {
    #[cfg(windows)]
    {
        windows::verify_private_dir(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(Repair::None)
    }
}

/// Runs the same checks on files expected inside the data directory. A missing file is normal (a
/// token that was never stored) and is skipped.
pub fn verify_private_files<P: AsRef<Path>>(paths: &[P]) -> Result<Repair, Refusal> {
    #[cfg(windows)]
    {
        windows::verify_private_files(paths)
    }
    #[cfg(not(windows))]
    {
        let _ = paths;
        Ok(Repair::None)
    }
}

/// Creates `path` (and parents) as owner-only, and tightens it if it already exists.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::ensure_private_dir(path)
    }
    #[cfg(not(windows))]
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(DIR_MODE);
        builder.create(path)?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE))?;
        Ok(())
    }
}

/// Writes `bytes` to a fresh 0600 file next to `path`, syncs it and renames it over `path`, so
/// readers see either the old or the new content and the secret is never world-readable.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut temp_name = name.to_os_string();
    temp_name.push(format!(".{:016x}.tmp", rand::random::<u64>()));
    let temp = dir.join(temp_name);

    let result = write_new(&temp, bytes).and_then(|()| rename_atomic(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    // Persist the rename itself; a failure here leaves a complete file, so it is not fatal.
    if let Err(err) = fs::File::open(dir).and_then(|dir| dir.sync_all()) {
        tracing::debug!(error = %err, "could not sync directory after atomic write");
    }
    Ok(())
}

/// Exchanges `a` and `b` in one step (`renamex_np` with `RENAME_SWAP`): each path always names a
/// complete tree. Both must exist on the same volume.
#[cfg(target_os = "macos")]
pub fn swap(a: &Path, b: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt as _};

    let c_path = |path: &Path| {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
    };
    let (a, b) = (c_path(a)?, c_path(b)?);
    // SAFETY: both are NUL-terminated paths that outlive the call.
    if unsafe { libc::renamex_np(a.as_ptr(), b.as_ptr(), libc::RENAME_SWAP) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn swap(_: &Path, _: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic swap is macOS only",
    ))
}

/// Whether this user may create and rename entries in `dir`.
#[cfg(unix)]
#[must_use]
pub fn is_writable_dir(dir: &Path) -> bool {
    use std::{ffi::CString, os::unix::ffi::OsStrExt as _};

    CString::new(dir.as_os_str().as_bytes()).is_ok_and(|path| {
        // SAFETY: a NUL-terminated path that outlives the call.
        unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
    })
}

/// Whether this user may create and rename entries in `dir`.
#[cfg(windows)]
#[must_use]
pub fn is_writable_dir(dir: &Path) -> bool {
    windows::is_writable_dir(dir)
}

/// Whether `path` lies on a volume mounted read-only (a disk image, a translocated app).
#[cfg(unix)]
pub fn is_on_read_only_volume(path: &Path) -> io::Result<bool> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt as _};

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: a NUL-terminated path and a writable out pointer, both live for the call.
    if unsafe { libc::statvfs(c_path.as_ptr(), info.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statvfs succeeded, so it initialised the struct.
    let info = unsafe { info.assume_init() };
    Ok(info.f_flag & libc::ST_RDONLY != 0)
}

/// Whether `path` lies on a volume mounted read-only (a disk image, a translocated app).
#[cfg(windows)]
pub fn is_on_read_only_volume(path: &Path) -> io::Result<bool> {
    windows::is_on_read_only_volume(path)
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(FILE_MODE);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn rename_atomic(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::rename_with_retry(from, to)
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn atomic_write_creates_and_replaces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.bin");
        write_private_atomic(&path, b"first").expect("first write");
        write_private_atomic(&path, b"second").expect("second write");
        assert_eq!(fs::read(&path).expect("read"), b"second");
        let leftovers = fs::read_dir(dir.path()).expect("read_dir").count();
        assert_eq!(leftovers, 1, "temp files must not linger");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_is_owner_only_even_when_replacing_a_public_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.bin");
        fs::write(&path, b"old").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        write_private_atomic(&path, b"new").expect("write");
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn atomic_write_into_a_missing_dir_fails_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing").join("state.bin");
        let err = write_private_atomic(&path, b"x").expect_err("missing dir");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn swap_exchanges_two_trees() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        fs::create_dir(&a).expect("a");
        fs::create_dir(&b).expect("b");
        fs::write(a.join("which"), b"a").expect("write");
        fs::write(b.join("which"), b"b").expect("write");
        swap(&a, &b).expect("swap");
        assert_eq!(fs::read(a.join("which")).expect("read"), b"b");
        assert_eq!(fs::read(b.join("which")).expect("read"), b"a");
        let missing = dir.path().join("missing");
        assert!(swap(&a, &missing).is_err(), "both sides must exist");
    }

    #[cfg(unix)]
    #[test]
    fn writable_and_read_only_checks() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(is_writable_dir(dir.path()));
        assert!(!is_writable_dir(&dir.path().join("missing")));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).expect("chmod");
        assert!(!is_writable_dir(dir.path()));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(!is_on_read_only_volume(dir.path()).expect("statvfs"));
    }

    #[cfg(unix)]
    #[test]
    fn private_dir_is_created_and_tightened() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a").join("b");
        ensure_private_dir(&nested).expect("create");
        assert_eq!(mode(&nested), 0o700);
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).expect("chmod");
        ensure_private_dir(&nested).expect("tighten");
        assert_eq!(mode(&nested), 0o700);
    }

    #[cfg(not(windows))]
    #[test]
    fn startup_checks_are_a_noop_off_windows() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(verify_private_dir(dir.path()).expect("dir"), Repair::None);
        let missing = dir.path().join("missing");
        assert_eq!(
            verify_private_files(&[missing]).expect("files"),
            Repair::None
        );
    }
}
