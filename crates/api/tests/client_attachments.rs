#![allow(clippy::unwrap_used)]

mod common;

use bwl_api::{Error, models::Attachment};
use common::{access_token, client, fixture_json, json_response};
use serde_json::json;
use tokio::io::AsyncWrite;
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

const CIPHER_ID: &str = "1b2151b1-7bbd-4057-bb11-f5ae84ef21cd";
const ATTACHMENT_ID: &str = "f00a0657e2416d73b7fd";

fn bearer() -> String {
    format!("Bearer {}", access_token())
}

fn attachment_path() -> String {
    format!("/api/ciphers/{CIPHER_ID}/attachment/{ATTACHMENT_ID}")
}

fn big_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + i / 251) % 256).unwrap())
        .collect()
}

#[tokio::test]
async fn attachment_info_returns_metadata_with_a_download_url() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(attachment_path()))
        .and(header("authorization", bearer().as_str()))
        .respond_with(json_response(200, "attachment_info.json"))
        .expect(1)
        .mount(&server)
        .await;

    let info = client(&server)
        .attachment_info(&access_token(), CIPHER_ID, ATTACHMENT_ID)
        .await
        .unwrap();

    let expected = fixture_json("attachment_info.json");
    assert_eq!(info.id, ATTACHMENT_ID);
    assert_eq!(info.url.as_deref(), expected["url"].as_str());
    assert_eq!(info.size.as_deref(), Some("2048"));
    assert_eq!(info.size_name.as_deref(), Some("2.00 KB"));
    assert_eq!(info.file_name.as_deref(), expected["fileName"].as_str());
    assert_eq!(info.key.as_deref(), expected["key"].as_str());
}

#[tokio::test]
async fn unknown_attachment_is_a_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/ciphers/{CIPHER_ID}/attachment/nope")))
        .respond_with(json_response(400, "attachment_not_found.json"))
        .mount(&server)
        .await;

    let error = client(&server)
        .attachment_info(&access_token(), CIPHER_ID, "nope")
        .await
        .unwrap_err();

    match error {
        Error::Server {
            status: 400,
            message,
        } => assert_eq!(message, "Attachment doesn't exist"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn attachment_size_accepts_strings_numbers_and_null() {
    let parse = |size: serde_json::Value| -> Attachment {
        serde_json::from_value(json!({ "id": "a", "size": size })).unwrap()
    };
    assert_eq!(parse(json!("2048")).size.as_deref(), Some("2048"));
    assert_eq!(parse(json!(2048)).size.as_deref(), Some("2048"));
    assert_eq!(parse(json!(null)).size, None);
    let missing: Attachment = serde_json::from_value(json!({ "id": "a" })).unwrap();
    assert_eq!(missing.size, None);
    let invalid = serde_json::from_value::<Attachment>(json!({ "id": "a", "size": [1] }));
    assert!(invalid.is_err());
}

#[tokio::test]
async fn create_attachment_registers_name_key_and_numeric_size() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/ciphers/{CIPHER_ID}/attachment/v2")))
        .and(header("authorization", bearer().as_str()))
        .and(body_json(json!({
            "key": "2.a2V5|Y3Q=|bWFj",
            "fileName": "2.bmFtZQ==|Y3Q=|bWFj",
            "fileSize": 2048,
        })))
        .respond_with(json_response(200, "attachment_create_v2.json"))
        .expect(1)
        .mount(&server)
        .await;

    let upload = client(&server)
        .create_attachment(
            &access_token(),
            CIPHER_ID,
            "2.bmFtZQ==|Y3Q=|bWFj",
            "2.a2V5|Y3Q=|bWFj",
            2048,
        )
        .await
        .unwrap();

    assert_eq!(upload.attachment_id, ATTACHMENT_ID);
    assert_eq!(
        upload.url,
        format!("/ciphers/{CIPHER_ID}/attachment/{ATTACHMENT_ID}")
    );
    assert_eq!(upload.file_upload_type, 0);
}

fn is_multipart_with_data(payload: Vec<u8>) -> impl Fn(&Request) -> bool {
    move |request: &Request| {
        let Some(content_type) = request
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };
        let Some(boundary) = content_type.strip_prefix("multipart/form-data; boundary=") else {
            return false;
        };
        let body = &request.body;
        let opening = format!("--{boundary}\r\n");
        let has_field = body
            .windows(b"name=\"data\"".len())
            .any(|window| window == b"name=\"data\"");
        let has_payload = body
            .windows(payload.len())
            .any(|window| window == payload.as_slice());
        let closing = format!("\r\n--{boundary}--\r\n");
        has_field
            && has_payload
            && body.starts_with(opening.as_bytes())
            && body.ends_with(closing.as_bytes())
    }
}

#[tokio::test]
async fn upload_streams_the_body_as_the_multipart_field_data() {
    let payload = big_payload(1_500_000);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(attachment_path()))
        .and(header("authorization", bearer().as_str()))
        .and(is_multipart_with_data(payload.clone()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> = payload
        .chunks(64 * 1024)
        .map(|chunk| Ok(chunk.to_vec()))
        .collect();
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter(chunks));

    client(&server)
        .upload_attachment_data(
            &access_token(),
            CIPHER_ID,
            ATTACHMENT_ID,
            body,
            payload.len() as u64,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn upload_rejection_carries_the_server_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(attachment_path()))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": "Attachment size mismatch (expected within [0, 1048586], got 2097152)",
            "error": "",
        })))
        .mount(&server)
        .await;

    let error = client(&server)
        .upload_attachment_data(
            &access_token(),
            CIPHER_ID,
            ATTACHMENT_ID,
            reqwest::Body::from(vec![1_u8; 8]),
            8,
        )
        .await
        .unwrap_err();

    match error {
        Error::Server {
            status: 400,
            message,
        } => assert!(message.contains("size mismatch")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn delete_attachment_accepts_the_cipher_returned_by_the_server() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path(attachment_path()))
        .and(header("authorization", bearer().as_str()))
        .respond_with(json_response(200, "attachment_delete.json"))
        .expect(1)
        .mount(&server)
        .await;

    client(&server)
        .delete_attachment(&access_token(), CIPHER_ID, ATTACHMENT_ID)
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_attachment_reports_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path(attachment_path()))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let error = client(&server)
        .delete_attachment("expired", CIPHER_ID, ATTACHMENT_ID)
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Unauthorized), "{error:?}");
}

fn no_authorization_header(request: &Request) -> bool {
    !request.headers.contains_key("authorization")
}

#[tokio::test]
async fn download_streams_a_multi_megabyte_body_without_the_bearer_token() {
    let payload = big_payload(3 * 1024 * 1024 + 17);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/attachments/{CIPHER_ID}/{ATTACHMENT_ID}")))
        .and(query_param("token", "short-lived"))
        .and(no_authorization_header)
        .respond_with(ResponseTemplate::new(200).set_body_bytes(payload.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let url = format!(
        "{}/attachments/{CIPHER_ID}/{ATTACHMENT_ID}?token=short-lived",
        server.uri()
    );
    let mut sink = Vec::new();

    let written = client(&server)
        .download_attachment(&url, &mut sink)
        .await
        .unwrap();

    assert_eq!(written, payload.len() as u64);
    assert_eq!(sink.len(), payload.len());
    assert!(
        sink == payload,
        "downloaded bytes differ from the served body"
    );
}

#[tokio::test]
async fn download_resolves_server_relative_urls() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/attachments/{CIPHER_ID}/{ATTACHMENT_ID}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"cipher text".to_vec()))
        .expect(1)
        .mount(&server)
        .await;
    let mut sink = Vec::new();

    let written = client(&server)
        .download_attachment(
            &format!("/attachments/{CIPHER_ID}/{ATTACHMENT_ID}?token=t"),
            &mut sink,
        )
        .await
        .unwrap();

    assert_eq!(written, 11);
    assert_eq!(sink, b"cipher text");
}

#[tokio::test]
async fn download_refuses_a_foreign_host_and_sends_nothing() {
    let server = MockServer::start().await;

    let error = client(&server)
        .download_attachment(
            "http://attacker.example/attachments/c/a?token=SECRET",
            Vec::new(),
        )
        .await
        .unwrap_err();

    match &error {
        Error::UntrustedUrl(host) => assert_eq!(host, "attacker.example"),
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(!error.to_string().contains("SECRET"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn download_failures_map_to_typed_errors_without_leaking_the_url_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/attachments/c/expired"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/attachments/c/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;
    let client = client(&server);

    let error = client
        .download_attachment(
            &format!("{}/attachments/c/expired?token=SECRET", server.uri()),
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Unauthorized), "{error:?}");

    let error = client
        .download_attachment(
            &format!("{}/attachments/c/missing?token=SECRET", server.uri()),
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::Server { status: 404, .. }),
        "{error:?}"
    );
    assert!(!format!("{error:?}").contains("SECRET"));
}

#[tokio::test]
async fn download_network_error_hides_the_url_token() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let client = common::client_for(&format!("http://{address}"));

    let error = client
        .download_attachment(
            &format!("http://{address}/attachments/c/a?token=SECRET"),
            Vec::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Http(_)), "{error:?}");
    assert!(error.is_offline());
    assert!(!error.to_string().contains("SECRET"), "{error}");
}

struct FailingWriter;

impl AsyncWrite for FailingWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::Error::other("disk full")))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn download_stops_with_an_io_error_when_the_writer_fails() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/attachments/c/a"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0_u8; 4096]))
        .mount(&server)
        .await;

    let error = client(&server)
        .download_attachment("/attachments/c/a", FailingWriter)
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Io(_)), "{error:?}");
}

#[tokio::test]
async fn crafted_relative_urls_never_reach_another_host() {
    let victim = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"leak".to_vec()))
        .expect(0)
        .mount(&victim)
        .await;
    let home = MockServer::start().await;
    let victim_authority = victim.uri().replace("http://", "");
    let client = client(&home);
    for raw in [
        format!("\\\\{victim_authority}/x"),
        format!(" //{victim_authority}/x"),
        format!("\t//{victim_authority}/x"),
        format!("/\\{victim_authority}/x"),
        format!("{}/x", victim.uri()),
        victim.uri().replace("http://", "https://"),
    ] {
        let mut sink = Vec::new();
        let outcome = client.download_attachment(&raw, &mut sink).await;
        assert!(sink.is_empty(), "{raw:?}");
        // Resolving to the home server (404 there) is fine; only the victim must stay untouched.
        assert!(outcome.is_err(), "{raw:?}");
    }
    assert!(victim.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn download_stops_once_the_body_exceeds_the_cap() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/attachments/big"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7_u8; 100_000]))
        .mount(&server)
        .await;
    let client = client(&server);

    let mut sink = Vec::new();
    let error = client
        .download_attachment_capped("/attachments/big", &mut sink, 1000)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Server { .. }), "{error:?}");
    assert!(sink.len() <= 100_000);

    let mut exact = Vec::new();
    let written = client
        .download_attachment_capped("/attachments/big", &mut exact, 100_000)
        .await
        .unwrap();
    assert_eq!(written, 100_000);
}
