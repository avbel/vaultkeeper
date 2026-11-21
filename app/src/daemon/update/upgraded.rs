//! Restart after a package manager replaced the binary under the running daemon (linux-plan.md
//! 2e). `brew upgrade` puts a new file behind the stable install path and deletes the old Cellar
//! directory; the daemon keeps running the deleted inode. Once the vault is quiet it restarts
//! from the install path, the same gate the macOS self-update uses.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use crate::daemon::Daemon;

/// How often the install path is compared with the running binary; an upgrade is rare and a
/// restart waits for quiet anyway.
const CHECK_EVERY: Duration = Duration::from_secs(60);

/// Which file a path names: device and inode.
pub type FileIdentity = (u64, u64);

#[must_use]
pub fn identity(path: &Path) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

/// The install path now names another file than the one this process was started from. A
/// missing install path (an uninstall in progress) is not an upgrade.
#[must_use]
pub fn replaced(running: FileIdentity, installed: Option<FileIdentity>) -> bool {
    installed.is_some_and(|installed| installed != running)
}

/// The install path to restart from, once it names another file than the running binary.
#[must_use]
pub fn updated_install(
    running: FileIdentity,
    installed: Option<FileIdentity>,
    install: &Path,
) -> Option<PathBuf> {
    replaced(running, installed).then(|| install.to_path_buf())
}

/// Stores the install path; false when it was already the state, so watchers are not woken again.
#[must_use]
pub fn record(current: &mut Option<PathBuf>, install: PathBuf) -> bool {
    let changed = current.as_ref() != Some(&install);
    *current = Some(install);
    changed
}

pub async fn watch(daemon: Arc<Daemon>) {
    // `/proc/self/exe` names the image the kernel loaded, even once its file is deleted.
    let Some(running) = identity(Path::new("/proc/self/exe")) else {
        tracing::warn!("cannot identify the running binary; upgrades need a manual restart");
        return;
    };
    let Some(install) = vk_platform::install_kind::current_install_path() else {
        return;
    };
    loop {
        tokio::time::sleep(CHECK_EVERY).await;
        let Some(updated) = updated_install(running, identity(&install), &install) else {
            continue;
        };
        if daemon.upgraded().is_none() {
            tracing::info!(path = %install.display(), "Vaultkeeper was updated; restarting once the vault is locked");
        }
        daemon.mark_upgraded(updated.clone());
        if daemon.quiet_for_update() {
            daemon.restart_for_update(updated);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_file_behind_the_install_path_is_an_upgrade() {
        assert!(replaced((1, 10), Some((1, 11))));
        assert!(!replaced((1, 10), Some((1, 10))));
        assert!(
            !replaced((1, 10), None),
            "no install path is not an upgrade"
        );
    }

    #[test]
    fn updated_names_the_install_path_only_for_a_replaced_binary() {
        let install = Path::new("/opt/vaultkeeper/bin/vaultkeeper");
        assert_eq!(
            updated_install((1, 10), Some((1, 11)), install),
            Some(install.to_path_buf())
        );
        assert_eq!(updated_install((1, 10), Some((1, 10)), install), None);
        assert_eq!(updated_install((1, 10), None, install), None);
    }

    #[test]
    fn recording_the_same_install_path_twice_wakes_watchers_once() {
        let mut state = None;
        let install = PathBuf::from("/opt/vaultkeeper/bin/vaultkeeper");
        assert!(record(&mut state, install.clone()));
        assert!(!record(&mut state, install.clone()));
        assert_eq!(state, Some(install));
    }

    #[test]
    fn identity_follows_a_symlink_to_the_file_it_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (old, new, link) = (
            dir.path().join("old"),
            dir.path().join("new"),
            dir.path().join("opt"),
        );
        std::fs::write(&old, b"v1").expect("old");
        std::fs::write(&new, b"v2").expect("new");
        std::os::unix::fs::symlink(&old, &link).expect("link");
        let running = identity(&link).expect("running");
        assert!(!replaced(running, identity(&link)));
        std::fs::remove_file(&link).expect("unlink");
        std::os::unix::fs::symlink(&new, &link).expect("relink");
        assert!(replaced(running, identity(&link)), "brew repointed opt");
    }
}
