//! Stand-in for the `--ui` process and the vault owner in the browser end-to-end run
//! (`scripts/e2e-browser.sh`, driver in `browsers/e2e/`).
//!
//! Talks to a real `vaultkeeper --daemon` over `ui.sock`. Commands arrive as JSON lines on stdin,
//! events (prompts the daemon shows, replies to commands) leave as JSON lines on stdout. Browser
//! prompts are answered by the policy last set with `{"cmd":"policy", ...}`.

#![cfg(feature = "vw-it")]
#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::too_many_lines)]

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use url::Url;
use vk_crypto::{EncString, Kdf, MasterKey, SymmetricKey};
use vk_ipc::{BrowserPrompt, BrowserReply, RemoteVault, UiEvent};
use vk_vault::{
    VaultService,
    model::{CopyField, Filter, ItemData, ItemDraft, ItemKind, LoginRequest, LoginStep},
};
use zeroize::Zeroizing;

const RSA_PRIVATE_DER: &[u8] = include_bytes!("../../crates/vault/tests/fixtures/rsa_private.der");
const RSA_PUBLIC_B64: &str = include_str!("../../crates/vault/tests/fixtures/rsa_public.b64");

#[derive(Clone)]
struct Policy {
    pair: String,
    fill: String,
    save: String,
}

fn emit(value: &Value) {
    println!("{value}");
}

async fn register(server: &Url) -> (String, String) {
    let email = format!("browser-e2e-{}@example.com", uuid::Uuid::new_v4().simple());
    let password = format!("pw-{}", uuid::Uuid::new_v4().simple());
    let kdf = Kdf::from_wire(0, 100_000, None, None).unwrap();
    let master = MasterKey::derive(password.as_bytes(), &email, &kdf).unwrap();
    let hash = master.server_hash(password.as_bytes());
    let user_key = SymmetricKey::generate();
    let protected = EncString::encrypt(&user_key.to_bytes(), &master.stretch()).unwrap();
    let private_key = EncString::encrypt(RSA_PRIVATE_DER, &user_key).unwrap();
    let http = reqwest::Client::new();
    let token = http
        .post(
            server
                .join("identity/accounts/register/send-verification-email")
                .unwrap(),
        )
        .json(&json!({ "email": email, "name": "Browser E2E" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    let response = http
        .post(server.join("identity/accounts/register/finish").unwrap())
        .json(&json!({
            "email": email,
            "masterPasswordHash": hash,
            "key": protected.to_string(),
            "keys": { "encryptedPrivateKey": private_key.to_string(), "publicKey": RSA_PUBLIC_B64.trim() },
            "emailVerificationToken": token.trim().trim_matches('"'),
            "kdf": 0,
            "kdfIterations": 100_000,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "register: {}",
        response.status()
    );
    (email, password)
}

fn login_draft(name: &str, username: &str, password: &str, uris: Vec<String>) -> ItemDraft {
    ItemDraft {
        name: name.to_owned(),
        notes: Zeroizing::new(String::new()),
        folder_id: None,
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: false,
        reprompt: false,
        fields: Vec::new(),
        data: ItemData::Login {
            username: username.to_owned(),
            password: Zeroizing::new(password.to_owned()),
            totp: Zeroizing::new(String::new()),
            uris,
        },
        revision_date: None,
    }
}

fn answer(event: UiEvent, policy: &Policy) {
    match event {
        UiEvent::Command { command, .. } => {
            emit(&json!({ "event": "command", "command": format!("{command:?}") }));
        }
        UiEvent::BrowserPrompt(prompt) => {
            let reply = match &prompt.prompt {
                BrowserPrompt::Pair {
                    browser,
                    fingerprint,
                } => {
                    emit(
                        &json!({ "event": "prompt", "kind": "pair", "browser": browser, "fingerprint": fingerprint }),
                    );
                    if policy.pair == "slow" {
                        let reply = prompt.reply;
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(4)).await;
                            let _ = reply.send(BrowserReply::PairApproved);
                        });
                        return;
                    }
                    if policy.pair == "approve" {
                        BrowserReply::PairApproved
                    } else {
                        BrowserReply::Dismissed
                    }
                }
                BrowserPrompt::Fill {
                    browser,
                    host,
                    insecure,
                    matches,
                    touch_id,
                    ..
                } => {
                    let names: Vec<_> = matches
                        .iter()
                        .map(|m| json!({ "name": &*m.name, "subtitle": &*m.subtitle }))
                        .collect();
                    emit(
                        &json!({ "event": "prompt", "kind": "fill", "browser": browser, "host": host,
                        "insecure": insecure, "matches": names, "touch_id": touch_id }),
                    );
                    let wanted = policy.fill.strip_prefix("name:");
                    let pick = match wanted {
                        Some(name) => matches.iter().find(|m| &*m.name == name),
                        None if policy.fill == "first" => matches.first(),
                        None => None,
                    };
                    pick.map_or(BrowserReply::Dismissed, |item| BrowserReply::Fill {
                        item_id: Arc::clone(&item.id),
                        confirmed_other_site: false,
                    })
                }
                BrowserPrompt::Save {
                    browser,
                    host,
                    username,
                    update_of,
                    choices,
                    ..
                } => {
                    emit(
                        &json!({ "event": "prompt", "kind": "save", "browser": browser, "host": host,
                        "username": username, "update_of": update_of.as_ref().map(|i| json!({ "id": &*i.id, "name": &*i.name })),
                        "choices": choices.len() }),
                    );
                    match policy.save.as_str() {
                        "save" => BrowserReply::Save {
                            target: update_of.as_ref().map(|item| Arc::clone(&item.id)),
                        },
                        "never" => BrowserReply::NeverForSite,
                        _ => BrowserReply::Dismissed,
                    }
                }
                BrowserPrompt::AddAddress {
                    browser,
                    host,
                    item,
                } => {
                    emit(
                        &json!({ "event": "prompt", "kind": "add_address", "browser": browser,
                        "host": host, "item": &*item.name }),
                    );
                    BrowserReply::Dismissed
                }
            };
            let _ = prompt.reply.send(reply);
        }
        UiEvent::Skipped(seq) => emit(&json!({ "event": "skipped", "seq": seq })),
        UiEvent::Shutdown => emit(&json!({ "event": "shutdown" })),
        UiEvent::OfflineChanged(_) | UiEvent::SshApproval(_) => {}
    }
}

fn describe(vault: &RemoteVault) -> Value {
    let items = vault
        .search(
            "",
            &Filter {
                kind: Some(ItemKind::Login),
                ..Filter::default()
            },
        )
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let password = vault
                        .reveal(&item.id, CopyField::Password)
                        .map(|p| (*p).clone())
                        .ok();
                    let uris = vault
                        .draft(&item.id)
                        .ok()
                        .and_then(|draft| match draft.data {
                            ItemData::Login { uris, .. } => Some(uris),
                            _ => None,
                        });
                    json!({ "id": &*item.id.0, "name": &*item.name, "username": &*item.subtitle,
                        "password": password, "uris": uris })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!(items)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let socket =
        PathBuf::from(std::env::args().nth(1).expect("usage: bot <data-dir>")).join("ui.sock");
    let policy = Arc::new(Mutex::new(Policy {
        pair: "approve".into(),
        fill: "first".into(),
        save: "save".into(),
    }));
    let mut vault: Option<Arc<RemoteVault>> = None;
    let mut account: Option<(String, String)> = None;
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await.unwrap() {
        let cmd: Value = serde_json::from_str(&line).unwrap();
        let name = cmd["cmd"].as_str().unwrap_or_default().to_owned();
        let result: Result<Value, String> = async {
            match name.as_str() {
                "register" => {
                    let server = Url::parse(cmd["server"].as_str().unwrap()).unwrap();
                    let (email, password) = register(&server).await;
                    account = Some((email.clone(), password.clone()));
                    Ok(json!({ "email": email, "password": password }))
                }
                "account" => {
                    account = Some((
                        cmd["email"].as_str().unwrap().to_owned(),
                        cmd["password"].as_str().unwrap().to_owned(),
                    ));
                    Ok(json!({}))
                }
                "connect" => {
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                    let (remote, mut events) = loop {
                        match RemoteVault::connect(&socket).await {
                            Ok(connected) => break connected,
                            Err(error) if tokio::time::Instant::now() >= deadline => {
                                return Err(format!("daemon not reachable: {error}"));
                            }
                            Err(_) => tokio::time::sleep(Duration::from_millis(150)).await,
                        }
                    };
                    let current = Arc::clone(&policy);
                    tokio::spawn(async move {
                        while let Some(event) = events.next().await {
                            let snapshot = current.lock().unwrap().clone();
                            answer(event, &snapshot);
                        }
                        emit(&json!({ "event": "disconnected" }));
                    });
                    vault = Some(Arc::new(remote));
                    Ok(json!({ "state": format!("{:?}", vault.as_ref().unwrap().state()) }))
                }
                "login" => {
                    let (email, password) = account.clone().ok_or("no account")?;
                    let server = Url::parse(cmd["server"].as_str().unwrap()).unwrap();
                    let step = vault
                        .as_ref()
                        .ok_or("not connected")?
                        .login(
                            LoginRequest {
                                server,
                                email,
                                password: Zeroizing::new(password),
                            },
                            None,
                            None,
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(json!({ "step": format!("{step:?}"), "done": step == LoginStep::Done }))
                }
                "add" => {
                    let uris = cmd["uris"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|u| u.as_str().unwrap().to_owned())
                        .collect();
                    let draft = login_draft(
                        cmd["name"].as_str().unwrap(),
                        cmd["username"].as_str().unwrap(),
                        cmd["password"].as_str().unwrap(),
                        uris,
                    );
                    let id = vault
                        .as_ref()
                        .ok_or("not connected")?
                        .save(None, draft)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(json!({ "id": &*id.0 }))
                }
                "items" => Ok(describe(vault.as_ref().ok_or("not connected")?)),
                "state" => Ok(json!(format!(
                    "{:?}",
                    vault.as_ref().ok_or("not connected")?.state()
                ))),
                "lock" => {
                    vault.as_ref().ok_or("not connected")?.lock();
                    Ok(json!({}))
                }
                "unlock" => {
                    let (_, password) = account.clone().ok_or("no account")?;
                    vault
                        .as_ref()
                        .ok_or("not connected")?
                        .unlock_with_password(Zeroizing::new(password))
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(json!({}))
                }
                "sync" => {
                    vault
                        .as_ref()
                        .ok_or("not connected")?
                        .sync()
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(json!({}))
                }
                "notify_settings" => {
                    vault
                        .as_ref()
                        .ok_or("not connected")?
                        .notify(vk_ipc::UiNotice::SettingsChanged)
                        .map_err(|e| e.to_string())?;
                    Ok(json!({}))
                }
                "policy" => {
                    let mut guard = policy.lock().unwrap();
                    let Policy { pair, fill, save } = &mut *guard;
                    for (key, slot) in [("pair", pair), ("fill", fill), ("save", save)] {
                        if let Some(value) = cmd[key].as_str() {
                            value.clone_into(slot);
                        }
                    }
                    Ok(json!({}))
                }
                "quit" => std::process::exit(0),
                other => Err(format!("unknown command {other}")),
            }
        }
        .await;
        match result {
            Ok(value) => {
                emit(&json!({ "event": "reply", "cmd": name, "ok": true, "value": value }));
            }
            Err(error) => {
                emit(&json!({ "event": "reply", "cmd": name, "ok": false, "error": error }));
            }
        }
    }
}
