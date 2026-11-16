#![cfg(windows)]
#![allow(dead_code)]

use std::{path::Path, process::Command};

use serial_test::serial;

mod common;
use common::{always_approving_agent, unique_pipe_name};

const SSH_ADD: &str = r"C:\Windows\System32\OpenSSH\ssh-add.exe";

/// The real OpenSSH client must be able to open the pipe with the final DACL; this is what decides
/// whether the DACL's rights are enough for `ssh.exe`.
#[serial]
#[tokio::test(flavor = "multi_thread")]
async fn test_openssh_ssh_add_lists_an_agent_with_no_keys() {
    if !Path::new(SSH_ADD).exists() {
        // A runner without the OpenSSH client has nothing to prove here.
        return;
    }
    let name = unique_pipe_name();
    let mut agent = always_approving_agent();
    agent.start_on(&name).unwrap();

    let output = tokio::task::spawn_blocking(move || {
        Command::new(SSH_ADD)
            .arg("-l")
            .env("SSH_AUTH_SOCK", name)
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    agent.stop();

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "ssh-add -l against an empty agent must exit 1; output: {text}"
    );
    assert!(
        text.contains("The agent has no identities"),
        "ssh-add did not reach the agent; output: {text}"
    );
}
