#![allow(clippy::unwrap_used)]

mod common;

use bwl_api::{
    Error,
    models::{CipherRequest, Extra, Login, LoginUri, cipher_type},
};
use common::{
    USER_ID, access_token, client, client_version_shows_ssh_keys, fixture_json, html_response,
    json_response,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, body_partial_json, header, method, path, query_param},
};

const LOGIN_ID: &str = "1b2151b1-7bbd-4057-bb11-f5ae84ef21cd";
const FOLDER_ID: &str = "20a84907-69e2-4395-94b7-398e34353e65";

fn bearer() -> String {
    format!("Bearer {}", access_token())
}

fn request(kind: u8) -> CipherRequest {
    CipherRequest {
        r#type: kind,
        name: "2.bmFtZQ==|Y3Q=|bWFj".into(),
        reprompt: 0,
        ..Default::default()
    }
}

/// Mounts the sync fixture only for clients that report an SSH-key-capable version, like the
/// real server, and the key-less variant otherwise.
async fn mount_sync(server: &MockServer, fixture: &str) {
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .and(query_param("excludeDomains", "true"))
        .and(header("authorization", bearer().as_str()))
        .and(client_version_shows_ssh_keys)
        .respond_with(json_response(200, fixture))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(json_response(200, "sync_without_client_version.json"))
        .mount(server)
        .await;
}

#[tokio::test]
async fn sync_returns_every_cipher_type_with_its_type_data() {
    let server = MockServer::start().await;
    mount_sync(&server, "sync_full.json").await;

    let sync = client(&server).sync(&access_token()).await.unwrap();

    assert_eq!(sync.profile.id, USER_ID);
    assert_eq!(sync.profile.email, "vault@example.com");
    assert!(sync.profile.key.as_deref().unwrap().starts_with("2."));
    assert!(sync.profile.private_key.is_some());
    assert!(sync.profile.organizations.is_empty());
    assert_eq!(sync.folders.len(), 1);
    assert_eq!(sync.folders[0].id, FOLDER_ID);
    assert!(sync.folders[0].name.starts_with("2."));
    assert!(sync.folders[0].revision_date.starts_with("2026-11-08T"));

    let mut kinds: Vec<u8> = sync.ciphers.iter().map(|cipher| cipher.r#type).collect();
    kinds.sort_unstable();
    assert_eq!(
        kinds,
        [
            cipher_type::LOGIN,
            cipher_type::SECURE_NOTE,
            cipher_type::CARD,
            cipher_type::IDENTITY,
            cipher_type::SSH_KEY
        ]
    );
    let by_type = |kind: u8| {
        sync.ciphers
            .iter()
            .find(|cipher| cipher.r#type == kind)
            .unwrap()
    };

    let login = by_type(cipher_type::LOGIN);
    assert_eq!(login.id, LOGIN_ID);
    assert_eq!(login.folder_id.as_deref(), Some(FOLDER_ID));
    assert!(login.key.is_some());
    assert!(login.edit && login.view_password && !login.favorite);
    let data = login.login.as_ref().unwrap();
    assert!(data.password.is_some() && data.totp.is_some());
    let uris = data.uris.as_ref().unwrap();
    assert_eq!(uris.len(), 2);
    assert_eq!(uris[0].r#match, None);
    assert_eq!(uris[1].r#match, Some(3));
    assert_eq!(login.fields.as_ref().unwrap().len(), 1);
    assert_eq!(login.fields.as_ref().unwrap()[0].r#type, 0);

    assert!(by_type(cipher_type::SECURE_NOTE).secure_note.is_some());
    let card = by_type(cipher_type::CARD).card.as_ref().unwrap();
    assert!(card.number.is_some() && card.exp_month.is_some() && card.code.is_some());
    let identity = by_type(cipher_type::IDENTITY).identity.as_ref().unwrap();
    assert!(identity.first_name.is_some() && identity.passport_number.is_some());
    let ssh = by_type(cipher_type::SSH_KEY);
    let ssh_key = ssh.ssh_key.as_ref().unwrap();
    assert!(ssh_key.private_key.is_some());
    assert!(ssh_key.public_key.is_some());
    assert!(ssh_key.key_fingerprint.is_some());
    assert!(
        ssh.deleted_date.is_some(),
        "the fixture trashed the SSH key"
    );
    assert!(by_type(cipher_type::LOGIN).deleted_date.is_none());
}

#[tokio::test]
async fn sync_parses_attachments_with_string_sizes() {
    let server = MockServer::start().await;
    mount_sync(&server, "sync_full.json").await;

    let sync = client(&server).sync(&access_token()).await.unwrap();

    let login = sync
        .ciphers
        .iter()
        .find(|cipher| cipher.id == LOGIN_ID)
        .unwrap();
    let attachments = login.attachments.as_ref().unwrap();
    assert_eq!(attachments.len(), 1);
    let attachment = &attachments[0];
    assert_eq!(attachment.size.as_deref(), Some("2048"));
    assert_eq!(attachment.size_name.as_deref(), Some("2.00 KB"));
    assert!(attachment.url.as_deref().unwrap().contains("/attachments/"));
    assert!(attachment.file_name.as_deref().unwrap().starts_with("2."));
    assert!(attachment.key.as_deref().unwrap().starts_with("2."));
    let others = sync.ciphers.iter().filter(|cipher| cipher.id != LOGIN_ID);
    assert!(
        others
            .into_iter()
            .all(|cipher| cipher.attachments.is_none())
    );
}

/// Hand-built variations of the captured sync: organizations, collections, unsupported cipher
/// types and the PascalCase spelling some Bitwarden servers use.
fn sync_with_extras() -> Value {
    let mut sync = fixture_json("sync_full.json");
    sync["profile"]["organizations"] = json!([{
        "id": "0a1b2c3d-0000-4000-8000-000000000001",
        "name": "Acme",
        "key": "4.cmVhbGx5LWFuLW9yZy1rZXk=",
        "enabled": true,
        "object": "profileOrganization"
    }]);
    sync["collections"] = json!([{
        "id": "0a1b2c3d-0000-4000-8000-000000000002",
        "organizationId": "0a1b2c3d-0000-4000-8000-000000000001",
        "name": "2.bmFtZQ==|Y3Q=|bWFj",
        "readOnly": true,
        "hidePasswords": true,
        "object": "collectionDetails"
    }]);
    let mut bank = sync["ciphers"][0].clone();
    bank["id"] = json!("0a1b2c3d-0000-4000-8000-000000000003");
    bank["type"] = json!(6);
    bank["organizationId"] = json!("0a1b2c3d-0000-4000-8000-000000000001");
    bank["collectionIds"] = json!(["0a1b2c3d-0000-4000-8000-000000000002"]);
    bank["sshKey"] = Value::Null;
    bank["bankAccount"] = json!({ "bankName": "2.eA==|eQ==|eg==" });
    bank["edit"] = json!(false);
    bank["viewPassword"] = json!(false);
    sync["ciphers"].as_array_mut().unwrap().push(bank);
    sync
}

fn pascal_case(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, child)| {
                    let mut chars = key.chars();
                    let key = chars
                        .next()
                        .map(|first| first.to_uppercase().chain(chars).collect())
                        .unwrap_or_default();
                    (key, pascal_case(child))
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(pascal_case).collect()),
        other => other,
    }
}

async fn sync_of(body: Value) -> bwl_api::models::SyncResponse {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    client(&server).sync(&access_token()).await.unwrap()
}

#[tokio::test]
async fn sync_keeps_organization_ciphers_collections_and_unsupported_types() {
    let sync = sync_of(sync_with_extras()).await;

    assert_eq!(sync.profile.organizations.len(), 1);
    assert_eq!(sync.profile.organizations[0].name, "Acme");
    assert_eq!(
        sync.profile.organizations[0].key.as_deref(),
        Some("4.cmVhbGx5LWFuLW9yZy1rZXk=")
    );
    assert_eq!(sync.collections.len(), 1);
    assert!(sync.collections[0].read_only && sync.collections[0].hide_passwords);
    let bank = sync
        .ciphers
        .iter()
        .find(|cipher| cipher.r#type == 6)
        .unwrap();
    assert_eq!(
        bank.organization_id.as_deref(),
        Some("0a1b2c3d-0000-4000-8000-000000000001")
    );
    assert_eq!(
        bank.collection_ids,
        ["0a1b2c3d-0000-4000-8000-000000000002"]
    );
    assert!(!bank.edit && !bank.view_password);
    assert_eq!(sync.ciphers.len(), 6);
}

#[tokio::test]
async fn sync_accepts_pascal_case_responses() {
    let sync = sync_of(pascal_case(sync_with_extras())).await;

    assert_eq!(sync.profile.email, "vault@example.com");
    assert_eq!(sync.ciphers.len(), 6);
    assert_eq!(sync.folders.len(), 1);
    assert!(sync.ciphers.iter().any(|cipher| cipher.ssh_key.is_some()));
}

#[tokio::test]
async fn sync_with_an_expired_token_is_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(html_response(401, "sync_unauthorized.txt"))
        .mount(&server)
        .await;

    let error = client(&server).sync("expired").await.unwrap_err();

    assert!(matches!(error, Error::Unauthorized), "{error:?}");
}

#[tokio::test]
async fn create_cipher_posts_the_cipher_with_encrypted_for_taken_from_the_token() {
    for kind in 1..=5_u8 {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/ciphers"))
            .and(header("authorization", bearer().as_str()))
            .and(body_partial_json(json!({
                "type": kind,
                "name": "2.bmFtZQ==|Y3Q=|bWFj",
                "encryptedFor": USER_ID,
            })))
            .respond_with(json_response(
                200,
                &format!("cipher_create_type{kind}.json"),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let created = client(&server)
            .create_cipher(&access_token(), &request(kind), &[])
            .await
            .unwrap();

        assert_eq!(created.r#type, kind);
        let expected = fixture_json(&format!("cipher_create_type{kind}.json"));
        assert_eq!(created.id, expected["id"].as_str().unwrap());
        assert!(created.key.is_some());
    }
}

#[tokio::test]
async fn create_cipher_for_an_organization_wraps_the_cipher_with_its_collections() {
    let server = MockServer::start().await;
    let org = "0a1b2c3d-0000-4000-8000-000000000001";
    Mock::given(method("POST"))
        .and(path("/api/ciphers/create"))
        .and(body_partial_json(json!({
            "cipher": { "type": 1, "organizationId": org, "encryptedFor": USER_ID },
            "collectionIds": ["c1", "c2"],
        })))
        .respond_with(json_response(200, "cipher_create_type1.json"))
        .expect(1)
        .mount(&server)
        .await;
    let cipher = CipherRequest {
        organization_id: Some(org.into()),
        ..request(1)
    };

    client(&server)
        .create_cipher(&access_token(), &cipher, &["c1".into(), "c2".into()])
        .await
        .unwrap();
}

#[tokio::test]
async fn write_with_an_opaque_token_fails_before_any_request_is_sent() {
    let server = MockServer::start().await;

    let error = client(&server)
        .create_cipher("opaque", &request(2), &[])
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Decode(_)), "{error:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

const ENC: &str = "2.rJFLaQWX2PGFdsSxCzykOw==|UGfhV0b1hjQ4+5lKEy/aVU7cLrrBW6DR|JuVejUpq98hEXS/hpQg3L0y3+tUjJK9LpywQJ9DoMgk=";

fn passkey() -> Value {
    json!({
        "credentialId": ENC, "keyType": ENC, "keyAlgorithm": ENC, "keyCurve": ENC,
        "keyValue": ENC, "rpId": ENC, "userHandle": ENC, "userName": ENC, "counter": ENC,
        "rpName": ENC, "userDisplayName": ENC, "discoverable": ENC,
        "creationDate": "2026-11-08T17:00:59.321Z"
    })
}

/// The captured sync plus what this client doesn't model: a passkey, an archive date and
/// properties a newer server might add, at every level of each cipher.
fn sync_with_passthrough() -> Value {
    let mut sync = fixture_json("sync_full.json");
    for cipher in sync["ciphers"].as_array_mut().unwrap() {
        cipher["archivedDate"] = json!("2026-11-08T18:00:00.000000Z");
        cipher["futureTopLevel"] = json!({ "nested": [1, "two", null] });
        if let Some(field) = cipher["fields"].get_mut(0) {
            field["futureField"] = json!(7);
        }
        if let Some(entry) = cipher["passwordHistory"].get_mut(0) {
            entry["futureHistory"] = json!(true);
        }
        for part in ["login", "card", "identity", "secureNote", "sshKey"] {
            if cipher[part].is_object() {
                cipher[part]["futurePart"] = json!("kept");
            }
        }
        if cipher["type"] == 1 {
            cipher["login"]["fido2Credentials"] = json!([passkey()]);
            cipher["login"]["uris"][0]["futureUri"] = json!("x");
        }
    }
    sync
}

#[tokio::test]
async fn synced_ciphers_re_serialize_to_the_server_json() {
    let raw = sync_with_passthrough();
    let sync = sync_of(raw.clone()).await;
    let expected = raw["ciphers"].as_array().unwrap();
    assert_eq!(sync.ciphers.len(), expected.len());
    for (cipher, expected) in sync.ciphers.iter().zip(expected) {
        let mut back = serde_json::to_value(cipher).unwrap();
        let mut expected = expected.clone();
        // Response-only, never sent back; modelled without its `object` tag.
        back["attachments"] = Value::Null;
        expected["attachments"] = Value::Null;
        assert_eq!(back, expected, "{}", cipher.id);
    }
    let login = sync
        .ciphers
        .iter()
        .find(|cipher| cipher.r#type == 1)
        .unwrap();
    assert_eq!(
        login.login.as_ref().unwrap().extra["fido2Credentials"],
        json!([passkey()])
    );
}

#[tokio::test]
async fn update_sends_carried_properties_beside_encrypted_for_and_the_revision_date() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/ciphers/{LOGIN_ID}")))
        .and(body_partial_json(json!({
            "encryptedFor": USER_ID,
            "lastKnownRevisionDate": "2026-11-08T17:00:59.323234Z",
            "archivedDate": "2026-11-08T18:00:00.000000Z",
            "login": {
                "autofillOnPageLoad": false,
                "fido2Credentials": [passkey()],
                "uris": [{ "uri": ENC, "uriChecksum": ENC, "futureUri": "x" }],
            },
        })))
        .respond_with(json_response(200, "cipher_update.json"))
        .expect(1)
        .mount(&server)
        .await;
    let extra = |pairs: &[(&str, Value)]| -> Extra {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect()
    };
    let cipher = CipherRequest {
        last_known_revision_date: Some("2026-11-08T17:00:59.323234Z".into()),
        login: Some(Login {
            uris: Some(vec![LoginUri {
                uri: Some(ENC.into()),
                uri_checksum: Some(ENC.into()),
                extra: extra(&[("futureUri", json!("x"))]),
                ..LoginUri::default()
            }]),
            extra: extra(&[
                ("autofillOnPageLoad", json!(false)),
                ("fido2Credentials", json!([passkey()])),
            ]),
            ..Login::default()
        }),
        extra: extra(&[("archivedDate", json!("2026-11-08T18:00:00.000000Z"))]),
        ..request(1)
    };

    client(&server)
        .update_cipher(&access_token(), LOGIN_ID, &cipher)
        .await
        .unwrap();
}

#[tokio::test]
async fn update_cipher_puts_the_revision_date_for_optimistic_concurrency() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/ciphers/{LOGIN_ID}")))
        .and(body_partial_json(json!({
            "encryptedFor": USER_ID,
            "lastKnownRevisionDate": "2026-11-08T17:00:59.323234Z",
        })))
        .respond_with(json_response(200, "cipher_update.json"))
        .expect(1)
        .mount(&server)
        .await;
    let cipher = CipherRequest {
        last_known_revision_date: Some("2026-11-08T17:00:59.323234Z".into()),
        ..request(1)
    };

    let updated = client(&server)
        .update_cipher(&access_token(), LOGIN_ID, &cipher)
        .await
        .unwrap();

    assert_eq!(updated.id, LOGIN_ID);
    assert_eq!(
        updated.revision_date,
        fixture_json("cipher_update.json")["revisionDate"]
    );
}

#[tokio::test]
async fn stale_update_is_a_server_error_with_the_resync_message() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/ciphers/{LOGIN_ID}")))
        .respond_with(json_response(400, "cipher_update_stale.json"))
        .mount(&server)
        .await;

    let error = client(&server)
        .update_cipher(&access_token(), LOGIN_ID, &request(1))
        .await
        .unwrap_err();

    match error {
        Error::Server {
            status: 400,
            message,
        } => assert_eq!(
            message,
            "The client copy of this cipher is out of date. Resync the client and try again."
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn trash_restore_and_delete_use_the_documented_routes() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/ciphers/{LOGIN_ID}/delete")))
        .and(header("authorization", bearer().as_str()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/ciphers/{LOGIN_ID}/restore")))
        .respond_with(json_response(200, "cipher_restore.json"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("/api/ciphers/{LOGIN_ID}")))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server);

    client
        .trash_cipher(&access_token(), LOGIN_ID)
        .await
        .unwrap();
    let restored = client
        .restore_cipher(&access_token(), LOGIN_ID)
        .await
        .unwrap();
    client
        .delete_cipher(&access_token(), LOGIN_ID)
        .await
        .unwrap();

    assert_eq!(
        restored.id,
        fixture_json("cipher_restore.json")["id"].as_str().unwrap()
    );
    assert!(restored.deleted_date.is_none());
}

#[tokio::test]
async fn cipher_writes_surface_unauthorized_and_server_errors() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/ciphers/gone"))
        .respond_with(json_response(400, "folder_not_found.json"))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/ciphers/x/delete"))
        .respond_with(html_response(401, "sync_unauthorized.txt"))
        .mount(&server)
        .await;
    let client = client(&server);

    let error = client
        .delete_cipher(&access_token(), "gone")
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::Server { status: 400, .. }),
        "{error:?}"
    );
    let error = client.trash_cipher(&access_token(), "x").await.unwrap_err();
    assert!(matches!(error, Error::Unauthorized), "{error:?}");
}

#[tokio::test]
async fn folder_crud_uses_the_documented_routes_and_bodies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/folders"))
        .and(body_json(json!({ "name": "2.ZW5j|Y3Q=|bWFj" })))
        .respond_with(json_response(200, "folder_create.json"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/folders/{FOLDER_ID}")))
        .and(body_json(json!({ "name": "2.bmV3|Y3Q=|bWFj" })))
        .respond_with(json_response(200, "folder_update.json"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("/api/folders/{FOLDER_ID}")))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server);

    let created = client
        .create_folder(&access_token(), "2.ZW5j|Y3Q=|bWFj")
        .await
        .unwrap();
    let updated = client
        .update_folder(&access_token(), FOLDER_ID, "2.bmV3|Y3Q=|bWFj")
        .await
        .unwrap();
    client
        .delete_folder(&access_token(), FOLDER_ID)
        .await
        .unwrap();

    assert_eq!(
        created.id,
        fixture_json("folder_create.json")["id"].as_str().unwrap()
    );
    assert!(created.name.starts_with("2."));
    assert_eq!(
        updated.id,
        fixture_json("folder_update.json")["id"].as_str().unwrap()
    );
    assert!(updated.revision_date.starts_with("20"));
}

#[tokio::test]
async fn unknown_folder_is_a_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/folders/missing"))
        .respond_with(json_response(400, "folder_not_found.json"))
        .mount(&server)
        .await;

    let error = client(&server)
        .update_folder(&access_token(), "missing", "x")
        .await
        .unwrap_err();

    match error {
        Error::Server {
            status: 400,
            message,
        } => assert_eq!(message, "Invalid folder"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn debug_output_of_a_sync_never_contains_attachment_download_tokens() {
    let server = MockServer::start().await;
    mount_sync(&server, "sync_full.json").await;

    let sync = client(&server).sync(&access_token()).await.unwrap();

    let rendered = format!("{sync:?}");
    assert!(
        !rendered.contains("token="),
        "attachment URL leaked: {rendered}"
    );
    assert!(
        !rendered.contains("/attachments/"),
        "attachment URL leaked: {rendered}"
    );
}

#[tokio::test]
async fn only_the_sync_may_answer_with_more_than_8_mib() {
    let padding = "x".repeat(9 << 20);
    let mut big_sync = sync_with_extras();
    big_sync["profile"]["name"] = Value::String(padding.clone());
    let sync = sync_of(big_sync).await;
    assert_eq!(sync.ciphers.len(), 6);

    let server = MockServer::start().await;
    let mut big_cipher = fixture_json("cipher_create_type1.json");
    big_cipher["notes"] = Value::String(padding);
    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(big_cipher))
        .mount(&server)
        .await;
    let error = client(&server)
        .create_cipher(&access_token(), &request(1), &[])
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Server { status: 200, message } if message == "response body too large"),
        "{error:?}"
    );
}
