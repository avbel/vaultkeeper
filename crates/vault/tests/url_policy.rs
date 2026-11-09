//! The server URL policy is enforced by the vault itself (login, probe, stored accounts), not
//! only by the login form.

#![allow(clippy::unwrap_used)]

use std::{path::Path, sync::Arc};

use bwl_vault::{
    DeviceInfo, Error, MemorySecretStore, Vault, VaultConfig, VaultService, model::LoginRequest,
};
use serde_json::json;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const USER_ID: &str = "3bef05d6-9070-48b4-b320-a5d425eec9fd";

fn open(dir: &Path) -> bwl_vault::Result<Vault> {
    let device = DeviceInfo {
        identifier: Uuid::new_v4(),
        name: "test".into(),
        device_type: 7,
    };
    let config = VaultConfig::new(dir.to_owned(), device, tokio::runtime::Handle::current());
    Vault::open(config, Arc::new(MemorySecretStore::new()))
}

fn temp_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("bwl-url-policy-{}", Uuid::new_v4().simple()))
}

fn rejected(error: &Error) -> bool {
    matches!(error, Error::Api(bwl_api::Error::InvalidServerUrl(_)))
}

const BAD_SERVERS: [&str; 5] = [
    "http://vault.example.com",
    "https://user:secret@vault.example.com",
    "ftp://vault.example.com",
    "https://vault.example.com/?x=1",
    "https://vault.example.com/#frag",
];

#[tokio::test]
async fn login_refuses_servers_outside_the_policy_before_any_request() {
    let dir = temp_dir();
    let vault = open(&dir).unwrap();
    for server in BAD_SERVERS {
        let request = LoginRequest {
            server: Url::parse(server).unwrap(),
            email: "user@example.com".into(),
            password: Zeroizing::new("pw".into()),
        };
        let error = vault.login(request, None, None).await.unwrap_err();
        assert!(rejected(&error), "{server}: {error:?}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn probe_refuses_servers_outside_the_policy() {
    let dir = temp_dir();
    let vault = open(&dir).unwrap();
    for server in BAD_SERVERS {
        let error = vault
            .probe_server(&Url::parse(server).unwrap())
            .await
            .unwrap_err();
        assert!(rejected(&error), "{server}: {error:?}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_stored_account_with_a_forbidden_server_is_refused_not_dropped() {
    let dir = temp_dir();
    let account_dir = dir.join("accounts").join(USER_ID);
    std::fs::create_dir_all(&account_dir).unwrap();
    let server = "http://vault.example.com";
    std::fs::write(
        dir.join("accounts.json"),
        json!({ "accounts": [{ "id": USER_ID, "server": server, "email": "a@example.com" }] })
            .to_string(),
    )
    .unwrap();
    std::fs::write(
        account_dir.join("account.json"),
        json!({
            "id": USER_ID,
            "server": server,
            "email": "a@example.com",
            "kdf": { "kind": 0, "iterations": 600_000 },
            "key": "2.a|b|c",
        })
        .to_string(),
    )
    .unwrap();

    let error = open(&dir).err().expect("open must refuse the account");
    assert!(rejected(&error), "{error:?}");
    assert!(account_dir.join("account.json").exists(), "data kept");
    let _ = std::fs::remove_dir_all(dir);
}
