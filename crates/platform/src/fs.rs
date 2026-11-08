//! Private on-disk state: owner-only directories and atomically replaced files.

// Atomic writes serve Touch ID enrollment, which exists on macOS only for now.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// Creates `path` (and parents) as owner-only, and tightens it if it already exists.
pub(crate) fn ensure_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(DIR_MODE);
    builder.create(path)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE))?;
    Ok(())
}

/// Writes `bytes` to a fresh 0600 file next to `path`, syncs it and renames it over `path`, so
/// readers see either the old or the new content and the secret is never world-readable.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
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

    let result = write_new(&temp, bytes).and_then(|()| fs::rename(&temp, path));
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

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(FILE_MODE);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
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
}
