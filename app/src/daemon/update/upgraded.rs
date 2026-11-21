//! Restart after a package manager replaced the binary under the running daemon (linux-plan.md
//! 2e). `brew upgrade` puts a new file behind the stable install path and deletes the old Cellar
//! directory; the daemon keeps running the deleted inode. Once the vault is quiet it restarts
//! from the install path, the same gate the macOS self-update uses.

use std::{path::Path, sync::Arc, time::Duration};

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

pub async fn watch(daemon: Arc<Daemon>) {
    // `/proc/self/exe` names the image the kernel loaded, even once its file is deleted.
    let Some(running) = identity(Path::new("/proc/self/exe")) else {
        tracing::warn!("cannot identify the running binary; upgrades need a manual restart");
        return;
    };
    let Some(install) = vk_platform::install_kind::current_install_path() else {
        return;
    };
    let mut announced = false;
    loop {
        tokio::time::sleep(CHECK_EVERY).await;
        if !replaced(running, identity(&install)) {
            continue;
        }
        if !announced {
            tracing::info!(path = %install.display(), "Vaultkeeper was updated; restarting once the vault is locked");
            announced = true;
        }
        if daemon.quiet_for_update() {
            daemon.restart_for_update(install);
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
