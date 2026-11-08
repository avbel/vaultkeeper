use std::{
    fs::{self, DirBuilder},
    io::ErrorKind,
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt},
        net::UnixStream,
    },
    path::Path,
};

use tracing::warn;

use crate::AgentError;

/// Checks the path before the vendored listener binds it. The listener unlinks whatever sits at
/// the path, so this refuses to hijack a live agent or delete something that is not a socket.
pub(crate) fn prepare(path: &Path) -> Result<(), AgentError> {
    create_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                return Err(AgentError::AlreadyRunning(path.to_path_buf()));
            }
            Ok(())
        }
        Ok(_) => Err(AgentError::NotASocket(path.to_path_buf())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

// The socket file is unlinked synchronously so a restart on the same path cannot race the old
// listener task, which only closes its descriptor once the runtime schedules it.
pub(crate) fn remove(path: &Path) {
    if let Err(error) = fs::remove_file(path)
        && error.kind() != ErrorKind::NotFound
    {
        warn!(path = %path.display(), %error, "cannot remove the SSH agent socket");
    }
}

fn create_parent(path: &Path) -> Result<(), AgentError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|source| io_error(parent, source))
}

fn io_error(path: &Path, source: std::io::Error) -> AgentError {
    AgentError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};

    use tempfile::TempDir;

    use super::*;

    fn temp() -> TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn missing_path_is_fine_and_parent_is_created_private() {
        let dir = temp();
        let path = dir.path().join("nested/agent.sock");

        prepare(&path).expect("prepared");

        let mode = fs::metadata(path.parent().expect("parent"))
            .expect("parent exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn existing_parent_keeps_its_mode() {
        let dir = temp();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod");

        prepare(&dir.path().join("agent.sock")).expect("prepared");

        let mode = fs::metadata(dir.path()).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn stale_socket_is_accepted() {
        let dir = temp();
        let path = dir.path().join("agent.sock");
        drop(UnixListener::bind(&path).expect("bind"));
        assert!(path.exists(), "the dead listener leaves its file behind");

        prepare(&path).expect("stale sockets are replaced by the listener");
    }

    #[test]
    fn live_socket_is_refused() {
        let dir = temp();
        let path = dir.path().join("agent.sock");
        let _live = UnixListener::bind(&path).expect("bind");

        let error = prepare(&path).expect_err("must not hijack");

        assert!(matches!(error, AgentError::AlreadyRunning(p) if p == path));
    }

    #[test]
    fn regular_file_is_never_deleted() {
        let dir = temp();
        let path = dir.path().join("precious");
        fs::write(&path, "data").expect("write");

        let error = prepare(&path).expect_err("not a socket");

        assert!(matches!(error, AgentError::NotASocket(_)));
        assert_eq!(fs::read_to_string(&path).expect("still there"), "data");
    }

    #[test]
    fn symlink_is_refused() {
        let dir = temp();
        let target = dir.path().join("target");
        fs::write(&target, "data").expect("write");
        let link = dir.path().join("agent.sock");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let error = prepare(&link).expect_err("symlink");

        assert!(matches!(error, AgentError::NotASocket(_)));
    }

    #[test]
    fn unusable_parent_is_an_io_error() {
        let dir = temp();
        let file = dir.path().join("file");
        fs::write(&file, "").expect("write");

        let error = prepare(&file.join("agent.sock")).expect_err("parent is a file");

        assert!(matches!(error, AgentError::Io { .. }));
    }

    #[test]
    fn remove_ignores_missing_file() {
        let dir = temp();
        let path = dir.path().join("gone.sock");

        remove(&path);

        assert!(!path.exists());
    }
}
