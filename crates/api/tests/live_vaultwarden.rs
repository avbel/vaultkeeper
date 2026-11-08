//! Runs against a real Vaultwarden when `VW_URL` is set (and is skipped otherwise):
//!
//! ```text
//! docker run -d --rm --name vw -p 8099:80 -e SIGNUPS_ALLOWED=true \
//!     -e I_REALLY_WANT_VOLATILE_STORAGE=true vaultwarden/server:latest
//! VW_URL=http://localhost:8099 cargo test -p bwl-api --test live_vaultwarden
//! ```
//!
//! The server only checks that encrypted fields look like EncStrings, so random-looking
//! `2.iv|ct|mac` values stand in for real ciphertext.

#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use bwl_api::{
    Client, Error, LoginOutcome,
    models::{CipherRequest, Login, SshKey, TokenResponse},
    notifications::{ListenOptions, Notification, listen_with},
};
use serde_json::{Value, json};
use tokio::{sync::mpsc, time::timeout};
use url::Url;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(10);

fn server_url() -> Option<Url> {
    let raw = std::env::var("VW_URL")
        .ok()
        .filter(|value| !value.is_empty())?;
    Some(Url::parse(&raw).expect("VW_URL must be a valid URL"))
}

#[allow(clippy::print_stderr)]
fn skip_notice(test: &str) {
    eprintln!("skipping {test}: VW_URL is not set");
}

fn random_b64(len: usize) -> String {
    let bytes: Vec<u8> = (0..len.div_ceil(16))
        .flat_map(|_| *Uuid::new_v4().as_bytes())
        .take(len)
        .collect();
    STANDARD.encode(bytes)
}

fn enc() -> String {
    format!("2.{}|{}|{}", random_b64(16), random_b64(24), random_b64(32))
}

struct Account {
    email: String,
    hash: String,
}

async fn register(base: &Url) -> Account {
    let account = Account {
        email: format!("it-{}@example.com", Uuid::new_v4().simple()),
        hash: random_b64(32),
    };
    let http = reqwest::Client::new();
    let url = |path: &str| base.join(path).unwrap();

    let token: String = http
        .post(url("identity/accounts/register/send-verification-email"))
        .header("accept", "application/json")
        .json(&json!({ "email": account.email, "name": "Integration" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("signups must be allowed on the test server")
        .json()
        .await
        .unwrap();
    http.post(url("identity/accounts/register/finish"))
        .json(&json!({
            "email": account.email,
            "masterPasswordHash": account.hash,
            "kdf": 0,
            "kdfIterations": 600_000,
            "key": enc(),
            "keys": { "encryptedPrivateKey": enc(), "publicKey": random_b64(64) },
            "emailVerificationToken": token,
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    account
}

async fn login(client: &Client, account: &Account) -> Box<TokenResponse> {
    match client
        .login(&account.email, &account.hash, None, None)
        .await
        .unwrap()
    {
        LoginOutcome::Success(token) => token,
        other => panic!("login did not succeed: {other:?}"),
    }
}

fn login_request(name: &str) -> CipherRequest {
    CipherRequest {
        r#type: 1,
        name: name.into(),
        login: Some(Login {
            username: Some(enc()),
            password: Some(enc()),
            ..Login::default()
        }),
        ..CipherRequest::default()
    }
}

async fn next_event(rx: &mut mpsc::Receiver<Notification>) -> Notification {
    timeout(WAIT, rx.recv())
        .await
        .expect("no notification in time")
        .expect("listener stopped")
}

#[tokio::test]
async fn prelogin_reaches_a_real_server() {
    let Some(base) = server_url() else {
        return skip_notice("prelogin_reaches_a_real_server");
    };
    let client = Client::new(base, common::device()).unwrap();

    let response = client
        .prelogin("nobody-registered@example.com")
        .await
        .unwrap();

    assert!(
        matches!(response.kdf, 0 | 1),
        "unexpected kdf {}",
        response.kdf
    );
    assert!(response.kdf_iterations > 0);
}

// One linear scenario against a stateful server; splitting it would only add shared plumbing.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn full_account_lifecycle_against_a_real_server() {
    let Some(base) = server_url() else {
        return skip_notice("full_account_lifecycle_against_a_real_server");
    };
    let client = Client::new(base.clone(), common::device()).unwrap();
    let account = register(&base).await;

    let prelogin = client.prelogin(&account.email).await.unwrap();
    assert_eq!((prelogin.kdf, prelogin.kdf_iterations), (0, 600_000));

    let wrong = client
        .login(&account.email, "d3Jvbmc=", None, None)
        .await
        .unwrap_err();
    match wrong {
        Error::Server {
            status: 400,
            message,
        } => {
            assert_eq!(message, "Username or password is incorrect. Try again");
        }
        other => panic!("unexpected: {other:?}"),
    }

    let token = login(&client, &account).await;
    let access = token.access_token.clone();
    assert!(
        token
            .key
            .as_deref()
            .is_some_and(|key| key.starts_with("2."))
    );
    let sync = client.sync(&access).await.unwrap();
    assert_eq!(sync.profile.email, account.email);
    assert!(sync.ciphers.is_empty() && sync.folders.is_empty());

    let refreshed = client
        .refresh(token.refresh_token.as_deref().unwrap())
        .await
        .unwrap();
    assert!(client.sync(&refreshed.access_token).await.is_ok());
    let bogus = client.refresh("not-a-refresh-token").await.unwrap_err();
    assert!(matches!(bogus, Error::Unauthorized), "{bogus:?}");
    let denied = client.sync("not-a-token").await.unwrap_err();
    assert!(matches!(denied, Error::Unauthorized), "{denied:?}");

    let (tx, mut rx) = mpsc::channel(32);
    let (hub_base, hub_token) = (base.clone(), access.clone());
    let listener = tokio::spawn(async move {
        listen_with(&hub_base, &hub_token, &tx, &ListenOptions::default()).await
    });
    assert_eq!(next_event(&mut rx).await, Notification::Connected);

    let folder = client.create_folder(&access, &enc()).await.unwrap();
    assert_eq!(
        next_event(&mut rx).await,
        Notification::FolderChanged {
            id: folder.id.clone()
        }
    );
    client
        .update_folder(&access, &folder.id, &enc())
        .await
        .unwrap();
    assert_eq!(
        next_event(&mut rx).await,
        Notification::FolderChanged {
            id: folder.id.clone()
        }
    );

    let mut request = login_request(&enc());
    request.folder_id = Some(folder.id.clone());
    request.key = Some(enc());
    let cipher = client.create_cipher(&access, &request, &[]).await.unwrap();
    assert_eq!(
        next_event(&mut rx).await,
        Notification::CipherChanged {
            id: cipher.id.clone()
        }
    );
    assert_eq!(cipher.folder_id.as_deref(), Some(folder.id.as_str()));

    let mut edit = request.clone();
    edit.name = enc();
    edit.last_known_revision_date = Some(cipher.revision_date.clone());
    let updated = client
        .update_cipher(&access, &cipher.id, &edit)
        .await
        .unwrap();
    assert_eq!(
        next_event(&mut rx).await,
        Notification::CipherChanged {
            id: cipher.id.clone()
        }
    );

    let stale = CipherRequest {
        last_known_revision_date: Some("2020-01-01T00:00:00.000000Z".into()),
        ..edit.clone()
    };
    let conflict = client
        .update_cipher(&access, &cipher.id, &stale)
        .await
        .unwrap_err();
    assert!(
        matches!(conflict, Error::Server { status: 400, .. }),
        "{conflict:?}"
    );

    let ssh = CipherRequest {
        r#type: 5,
        name: enc(),
        ssh_key: Some(SshKey {
            private_key: Some(enc()),
            public_key: Some(enc()),
            key_fingerprint: Some(enc()),
            ..SshKey::default()
        }),
        ..CipherRequest::default()
    };
    let ssh_cipher = client.create_cipher(&access, &ssh, &[]).await.unwrap();
    assert_eq!(
        next_event(&mut rx).await,
        Notification::CipherChanged {
            id: ssh_cipher.id.clone()
        }
    );
    let synced = client.sync(&access).await.unwrap();
    assert!(
        synced
            .ciphers
            .iter()
            .any(|c| c.id == ssh_cipher.id && c.ssh_key.is_some()),
        "SSH key cipher must survive sync: the client version header must allow it"
    );

    exercise_attachment(&client, &access, &cipher.id, &mut rx).await;

    client.trash_cipher(&access, &cipher.id).await.unwrap();
    assert_eq!(
        next_event(&mut rx).await,
        Notification::CipherChanged {
            id: cipher.id.clone()
        }
    );
    let restored = client.restore_cipher(&access, &cipher.id).await.unwrap();
    assert!(restored.deleted_date.is_none());
    assert_eq!(
        next_event(&mut rx).await,
        Notification::CipherChanged {
            id: cipher.id.clone()
        }
    );
    client.delete_cipher(&access, &cipher.id).await.unwrap();
    assert_eq!(
        next_event(&mut rx).await,
        Notification::CipherDeleted {
            id: cipher.id.clone()
        }
    );
    client.delete_folder(&access, &folder.id).await.unwrap();
    assert_eq!(
        next_event(&mut rx).await,
        Notification::FolderDeleted {
            id: folder.id.clone()
        }
    );
    assert_ne!(updated.revision_date, cipher.revision_date);

    listener.abort();
    assert_own_changes_are_filtered(&base, &client, &access).await;
}

async fn exercise_attachment(
    client: &Client,
    access: &str,
    cipher_id: &str,
    rx: &mut mpsc::Receiver<Notification>,
) {
    let file: Vec<u8> = (0..1_500_000_u32)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect();
    let upload = client
        .create_attachment(access, cipher_id, &enc(), &enc(), file.len() as u64)
        .await
        .unwrap();
    assert_eq!(upload.file_upload_type, 0);
    assert_eq!(
        next_event(rx).await,
        Notification::CipherChanged {
            id: cipher_id.to_owned()
        }
    );

    let chunks: Vec<Result<Vec<u8>, std::io::Error>> = file
        .chunks(64 * 1024)
        .map(|chunk| Ok(chunk.to_vec()))
        .collect();
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter(chunks));
    client
        .upload_attachment_data(
            access,
            cipher_id,
            &upload.attachment_id,
            body,
            file.len() as u64,
        )
        .await
        .unwrap();

    let info = client
        .attachment_info(access, cipher_id, &upload.attachment_id)
        .await
        .unwrap();
    assert_eq!(info.size.as_deref(), Some(file.len().to_string().as_str()));
    let mut downloaded = Vec::new();
    let written = client
        .download_attachment(info.url.as_deref().unwrap(), &mut downloaded)
        .await
        .unwrap();
    assert_eq!(written, file.len() as u64);
    assert!(
        downloaded == file,
        "downloaded attachment differs from the upload"
    );

    client
        .delete_attachment(access, cipher_id, &upload.attachment_id)
        .await
        .unwrap();
    assert_eq!(
        next_event(rx).await,
        Notification::CipherChanged {
            id: cipher_id.to_owned()
        }
    );
    let gone = client
        .attachment_info(access, cipher_id, &upload.attachment_id)
        .await
        .unwrap_err();
    assert!(
        matches!(gone, Error::Server { status: 400, .. }),
        "{gone:?}"
    );
}

/// Vaultwarden stamps notifications with the acting device (`ContextId`), which is the device
/// identifier we log in with; filtering on it must hide our own writes but not other devices'.
async fn assert_own_changes_are_filtered(base: &Url, client: &Client, access: &str) {
    let options = ListenOptions {
        own_device_id: Some(common::DEVICE_ID.into()),
        ..ListenOptions::default()
    };
    let (tx, mut rx) = mpsc::channel(8);
    let (hub_base, hub_token) = (base.clone(), access.to_owned());
    let listener =
        tokio::spawn(async move { listen_with(&hub_base, &hub_token, &tx, &options).await });
    assert_eq!(next_event(&mut rx).await, Notification::Connected);

    let folder: Value =
        serde_json::to_value(client.create_folder(access, &enc()).await.unwrap()).unwrap();

    let silence = timeout(Duration::from_millis(700), rx.recv()).await;
    assert!(
        silence.is_err(),
        "own change was not filtered: {silence:?} for {folder}"
    );
    listener.abort();
}
