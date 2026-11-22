//! Restart after a package manager replaced the binary under the running daemon (linux-plan.md
//! 2e). `brew upgrade` puts a new file behind the stable install path and deletes the old Cellar
//! directory; the daemon keeps running the deleted inode. Once the vault is quiet it restarts
//! from the install path, the same gate the macOS self-update uses.
//!
//! Under the Landlock sandbox the same restart answers a replaced loader or `systemd-creds`
//! (a glibc or systemd upgrade): the sandbox allows execution per file, so the new file behind
//! the path is refused until a fresh sandbox names it. Until then a window that is not open
//! yet cannot be started and the token store's `systemd-creds` calls fail; with the vault
//! unlocked that lasts until it locks, since the restart waits for quiet.
//!
//! A socket the sandbox granted (the `systemd-creds` service, the buses) is held by inode too: one
//! recreated by a service restart is unreachable until the same quiet restart.
//!
//! A sandboxed daemon cannot start its replacement itself (`daemon::relaunch`). With no systemd
//! user manager to do it, it keeps running and the tray asks for a restart by hand.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use crate::daemon::Daemon;

/// How often the install path is compared with the running binary; an upgrade is rare and a
/// restart waits for quiet anyway.
const CHECK_EVERY: Duration = Duration::from_secs(60);

pub use vk_platform::pins::{FileIdentity, identity, replaced};

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

/// The files the sandbox lets this process execute, with what each path named when the rule
/// was made.
static PINNED: OnceLock<Vec<(PathBuf, Option<FileIdentity>)>> = OnceLock::new();

/// Called once, right after the sandbox is applied.
pub fn pin(executables: &[PathBuf]) {
    let pinned = executables
        .iter()
        .map(|path| (path.clone(), identity(path)))
        .collect();
    if PINNED.set(pinned).is_err() {
        tracing::warn!("the sandbox's executables were pinned twice; keeping the first set");
    }
}

/// Whether a restart is for a new Vaultkeeper or only to reach what the sandbox pinned again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Updated,
    Reconnect,
}

/// The install path to restart from and why: the binary was replaced, or a program or socket the
/// sandbox pinned.
fn stale(running: FileIdentity, install: &Path) -> Option<(PathBuf, Cause)> {
    if let Some(updated) = updated_install(running, identity(install), install) {
        return Some((updated, Cause::Updated));
    }
    if let Some(path) = vk_platform::pins::replaced_socket() {
        tracing::debug!(path = %path.display(), "a socket the sandbox allows was recreated");
        return Some((install.to_path_buf(), Cause::Reconnect));
    }
    let pinned = PINNED.get()?;
    let path = vk_platform::pins::replaced_path(pinned)?;
    tracing::debug!(path = %path.display(), "a program the sandbox allows was replaced");
    Some((install.to_path_buf(), Cause::Reconnect))
}

/// What the Settings report needs to word the fix: no systemd user manager to restart the daemon.
static BY_HAND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[must_use]
pub fn restart_by_hand() -> bool {
    BY_HAND.load(std::sync::atomic::Ordering::SeqCst)
}

/// Whether this daemon must not quit for the upgrade because nothing would start the new one.
#[cfg(target_os = "linux")]
async fn restart_is_manual() -> bool {
    use crate::daemon::relaunch;
    relaunch::sandboxed()
        && relaunch::route(true, relaunch::manager_reachable().await) == relaunch::Route::Manual
}

#[cfg(not(target_os = "linux"))]
async fn restart_is_manual() -> bool {
    std::future::ready(false).await
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
        let Some((updated, cause)) = stale(running, &install) else {
            continue;
        };
        let manual = restart_is_manual().await;
        BY_HAND.store(manual, std::sync::atomic::Ordering::SeqCst);
        if daemon.upgraded().is_none() {
            if manual {
                tracing::warn!(path = %install.display(), "Vaultkeeper, a program it runs or a service it talks to was updated or restarted, and no systemd user manager can start the new one outside this sandbox; quit and start Vaultkeeper again");
            } else {
                tracing::info!(path = %install.display(), "Vaultkeeper, a program it runs or a service it talks to was updated or restarted; restarting once the vault is locked");
            }
        }
        daemon.set_manual_restart(manual);
        daemon.set_restart_reconnects(cause == Cause::Reconnect);
        daemon.mark_upgraded(updated.clone());
        if manual {
            continue;
        }
        if daemon.quiet_for_update() {
            daemon.restart_for_update(updated);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_platform::pins::replaced_path;

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
    fn a_pinned_program_is_stale_once_its_path_names_another_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (loader, tool, absent) = (
            dir.path().join("ld.so"),
            dir.path().join("tool"),
            dir.path().join("absent"),
        );
        std::fs::write(&loader, b"v1").expect("loader");
        std::fs::write(&tool, b"v1").expect("tool");
        let pinned: Vec<_> = [&loader, &tool, &absent]
            .into_iter()
            .map(|path| (path.clone(), identity(path)))
            .collect();
        assert_eq!(replaced_path(&pinned), None);
        std::fs::write(&absent, b"appeared").expect("absent");
        assert_eq!(replaced_path(&pinned), None, "nothing was pinned there");
        // What a package manager does: a new file renamed over the path.
        let staged = dir.path().join("staged");
        std::fs::write(&staged, b"v2").expect("staged");
        std::fs::rename(&staged, &tool).expect("replace");
        assert_eq!(replaced_path(&pinned), Some(tool.as_path()));
        std::fs::remove_file(&tool).expect("remove");
        assert_eq!(
            replaced_path(&pinned),
            None,
            "a missing file is not an upgrade"
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
