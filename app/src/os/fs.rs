//! Owner-only files replaced atomically (settings, device id).

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const FILE_MODE: u32 = 0o600;

/// Writes `bytes` to a fresh 0600 file next to `path`, syncs it and renames it over `path`, so a
/// reader sees the old or the new content, never a torn write.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut temp_name = name.to_os_string();
    temp_name.push(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let temp = dir.join(temp_name);
    let written = write_new(&temp, bytes).and_then(|()| fs::rename(&temp, path));
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn replaces_atomically_with_owner_only_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settings.json");
        fs::write(&path, b"old").expect("seed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        write_private(&path, b"new").expect("write");
        assert_eq!(fs::read(&path).expect("read"), b"new");
        let mode = fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            fs::read_dir(dir.path()).expect("list").count(),
            1,
            "no temp file left"
        );
    }

    #[test]
    fn a_missing_directory_fails_without_leftovers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error =
            write_private(&dir.path().join("gone/settings.json"), b"x").expect_err("no dir");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
