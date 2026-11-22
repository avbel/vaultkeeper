//! Landlock grants a unix socket by its inode, so a socket recreated after the sandbox was applied
//! (a restarted `systemd-creds.socket` or session bus) stays out of reach. The inodes are
//! recorded when the rules are made, so the daemon can tell and restart into a fresh sandbox.

use std::{
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::sandbox::CREDS_SOCKET;

/// Which file a path names: device and inode.
pub type FileIdentity = (u64, u64);

pub type Pinned = Vec<(PathBuf, Option<FileIdentity>)>;

#[must_use]
pub fn identity(path: &Path) -> Option<FileIdentity> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

/// A missing file (a service restarting right now) is not a replacement.
#[must_use]
pub fn replaced(was: FileIdentity, now: Option<FileIdentity>) -> bool {
    now.is_some_and(|now| now != was)
}

/// The first pinned path that now names another file than when it was pinned.
#[must_use]
pub fn replaced_path(pinned: &[(PathBuf, Option<FileIdentity>)]) -> Option<&Path> {
    pinned
        .iter()
        .find(|(path, was)| was.is_some_and(|was| replaced(was, identity(path))))
        .map(|(path, _)| path.as_path())
}

fn socket_identity(path: &Path) -> Option<FileIdentity> {
    let meta = std::fs::metadata(path).ok()?;
    meta.file_type()
        .is_socket()
        .then(|| (meta.dev(), meta.ino()))
}

/// What of the granted socket paths named a socket when the sandbox was applied. A directory
/// grant (at-spi) is not pinned: its sockets come and go inside it without losing the rule. A
/// socket missing now is not pinned either: Landlock skips a rule for a path that does not
/// exist, so one that appears later was never granted and no restart would help.
#[must_use]
pub fn socket_pins(paths: &[PathBuf]) -> Pinned {
    paths
        .iter()
        .filter_map(|path| socket_identity(path).map(|id| (path.clone(), Some(id))))
        .collect()
}

static SOCKETS: OnceLock<Pinned> = OnceLock::new();

/// Called once, right after the sandbox is applied.
pub fn pin_sockets(paths: &[PathBuf]) {
    if SOCKETS.set(socket_pins(paths)).is_err() {
        tracing::warn!("the sandbox's sockets were pinned twice; keeping the first set");
    }
}

#[must_use]
pub fn replaced_socket() -> Option<&'static Path> {
    replaced_path(SOCKETS.get()?)
}

/// Whether `target` is pinned and now names another file than when it was pinned.
#[must_use]
pub fn is_replaced(pinned: &[(PathBuf, Option<FileIdentity>)], target: &Path) -> bool {
    let own: Vec<_> = pinned
        .iter()
        .filter(|(path, _)| path == target)
        .cloned()
        .collect();
    replaced_path(&own).is_some()
}

/// Whether the service `systemd-creds` talks to was recreated behind the sandbox's back.
#[must_use]
pub fn creds_socket_replaced() -> bool {
    SOCKETS
        .get()
        .is_some_and(|pinned| is_replaced(pinned, Path::new(CREDS_SOCKET)))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn a_recreated_socket_is_replaced_and_a_missing_one_is_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("svc.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        let pinned = socket_pins(&[path.clone(), dir.path().to_owned()]);
        assert_eq!(pinned.len(), 1, "the directory is not a socket");
        assert_eq!(replaced_path(&pinned), None);
        std::fs::remove_file(&path).expect("remove");
        assert_eq!(replaced_path(&pinned), None, "a restart in progress");
        let _again = UnixListener::bind(&path).expect("rebind");
        assert_eq!(replaced_path(&pinned), Some(path.as_path()));
        drop(listener);
    }

    #[test]
    fn only_the_named_sockets_own_pin_counts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bus = dir.path().join("bus");
        let creds = dir.path().join("creds");
        let _bus = UnixListener::bind(&bus).expect("bind bus");
        let _creds = UnixListener::bind(&creds).expect("bind creds");
        let pinned = socket_pins(&[bus.clone(), creds.clone()]);
        assert!(!is_replaced(&pinned, &creds));
        std::fs::remove_file(&bus).expect("remove bus");
        let _bus_again = UnixListener::bind(&bus).expect("rebind bus");
        assert_eq!(replaced_path(&pinned), Some(bus.as_path()));
        assert!(is_replaced(&pinned, &bus));
        assert!(
            !is_replaced(&pinned, &creds),
            "the bus pin must not stand in for the credentials socket"
        );
    }
}
