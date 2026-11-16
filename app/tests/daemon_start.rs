//! The daemon core starts on every platform with a fresh data dir, the way `daemon::run` builds
//! it. The rest of the daemon tests bind Unix sockets and are Unix-only, which let a Windows-only
//! start-up failure (the SSH endpoint is a named pipe there) reach a release unnoticed.

use std::sync::Arc;

use vaultkeeper::daemon::{Daemon, DaemonConfig, Peers};
use vk_vault::MemorySecretStore;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_install_starts_with_the_ssh_agent_off() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = DaemonConfig::new(dir.path().to_owned(), Arc::new(MemorySecretStore::new()));
    config.peers = Peers::AnyOfThisUser;
    let daemon = Daemon::start(config).await.expect("the daemon starts");
    assert!(!daemon.ssh_agent_running());
    daemon.shutdown().await;
}
