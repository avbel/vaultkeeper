#![allow(clippy::unwrap_used)]

mod common;

use common::{
    EMAIL, PASSWORD_HASH, client, client_for, client_version_shows_ssh_keys, fixture_json,
    html_response, json_response, login_form_with,
};
use serde_json::json;
use vk_api::{Client, Error, LoginOutcome, TwoFactorProvider, TwoFactorToken};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

fn totp(code: &str, remember: bool) -> TwoFactorToken {
    TwoFactorToken {
        provider: TwoFactorProvider::Authenticator,
        token: code.into(),
        remember,
    }
}

#[tokio::test]
async fn prelogin_reads_pbkdf2_settings_and_posts_the_email() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .and(body_json(json!({ "email": EMAIL })))
        .respond_with(json_response(200, "prelogin_registered.json"))
        .expect(1)
        .mount(&server)
        .await;

    let response = client(&server).prelogin(EMAIL).await.unwrap();

    assert_eq!(response.kdf, 0);
    assert_eq!(response.kdf_iterations, 600_000);
    assert_eq!(response.kdf_memory, None);
    assert_eq!(response.kdf_parallelism, None);
}

#[tokio::test]
async fn prelogin_reads_argon2id_memory_and_parallelism() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(json_response(200, "prelogin_argon2id.json"))
        .mount(&server)
        .await;

    let response = client(&server)
        .prelogin("argon2@example.com")
        .await
        .unwrap();

    assert_eq!(response.kdf, 1);
    assert_eq!(response.kdf_iterations, 3);
    assert_eq!(response.kdf_memory, Some(64));
    assert_eq!(response.kdf_parallelism, Some(4));
}

#[tokio::test]
async fn every_request_identifies_the_desktop_client_and_claims_a_ssh_key_capable_version() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .and(header("device-type", "7"))
        .and(header("bitwarden-client-name", "desktop"))
        .and(client_version_shows_ssh_keys)
        .respond_with(json_response(200, "prelogin_pbkdf2.json"))
        .expect(1)
        .mount(&server)
        .await;

    client(&server).prelogin(EMAIL).await.unwrap();
}

#[tokio::test]
async fn server_url_with_a_path_prefix_keeps_the_prefix() {
    for suffix in ["/vw", "/vw/"] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/vw/identity/accounts/prelogin"))
            .respond_with(json_response(200, "prelogin_pbkdf2.json"))
            .expect(1)
            .mount(&server)
            .await;

        let client = client_for(&format!("{}{suffix}", server.uri()));
        client.prelogin(EMAIL).await.unwrap();
    }
}

#[tokio::test]
async fn password_login_sends_the_documented_form_and_parses_the_pascal_case_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(login_form_with(&[]))
        .respond_with(json_response(200, "token_success.json"))
        .expect(1)
        .mount(&server)
        .await;

    let outcome = client(&server)
        .login(EMAIL, PASSWORD_HASH, None, None)
        .await
        .unwrap();

    let LoginOutcome::Success(token) = outcome else {
        panic!("expected success, got {outcome:?}");
    };
    let fixture = fixture_json("token_success.json");
    assert_eq!(
        token.access_token,
        fixture["access_token"].as_str().unwrap()
    );
    assert_eq!(
        token.refresh_token.as_deref(),
        fixture["refresh_token"].as_str()
    );
    assert_eq!(token.expires_in, 7200);
    assert_eq!(token.key.as_deref(), fixture["Key"].as_str());
    assert!(token.key.as_deref().unwrap().starts_with("2."));
    assert_eq!(token.private_key.as_deref(), fixture["PrivateKey"].as_str());
    assert_eq!(token.two_factor_token, None);
}

#[tokio::test]
async fn debug_output_of_login_results_never_contains_secrets() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(json_response(200, "token_success.json"))
        .mount(&server)
        .await;

    let outcome = client(&server)
        .login(EMAIL, PASSWORD_HASH, None, None)
        .await
        .unwrap();

    let rendered = format!("{outcome:?}");
    let fixture = fixture_json("token_success.json");
    for secret in [
        fixture["access_token"].as_str().unwrap(),
        fixture["refresh_token"].as_str().unwrap(),
        fixture["Key"].as_str().unwrap(),
        fixture["PrivateKey"].as_str().unwrap(),
    ] {
        assert!(
            !rendered.contains(secret),
            "Debug leaked a secret: {rendered}"
        );
    }
}

#[test]
fn debug_output_of_a_two_factor_token_hides_the_code() {
    let rendered = format!("{:?}", totp("123456", true));
    assert!(!rendered.contains("123456"), "{rendered}");
}

#[tokio::test]
async fn login_reports_the_available_two_factor_providers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(login_form_with(&[]))
        .respond_with(json_response(400, "token_two_factor_required.json"))
        .mount(&server)
        .await;

    let outcome = client(&server)
        .login(EMAIL, PASSWORD_HASH, None, None)
        .await
        .unwrap();

    let LoginOutcome::TwoFactorRequired { providers, .. } = outcome else {
        panic!("expected a 2FA challenge, got {outcome:?}");
    };
    assert_eq!(providers, vec![TwoFactorProvider::Authenticator]);
}

#[tokio::test]
async fn two_factor_retry_sends_provider_token_and_remember_flag() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(login_form_with(&[
            ("twoFactorToken", "123456"),
            ("twoFactorProvider", "0"),
            ("twoFactorRemember", "1"),
        ]))
        .respond_with(json_response(200, "token_two_factor_success_remember.json"))
        .expect(1)
        .mount(&server)
        .await;

    let outcome = client(&server)
        .login(EMAIL, PASSWORD_HASH, Some(&totp("123456", true)), None)
        .await
        .unwrap();

    let LoginOutcome::Success(token) = outcome else {
        panic!("expected success, got {outcome:?}");
    };
    let remember = fixture_json("token_two_factor_success_remember.json");
    assert_eq!(
        token.two_factor_token.as_deref(),
        remember["TwoFactorToken"].as_str()
    );
    assert!(token.two_factor_token.is_some());
}

#[tokio::test]
async fn two_factor_without_remember_sends_zero_and_uses_the_provider_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(login_form_with(&[
            ("twoFactorToken", "abcd-efgh"),
            ("twoFactorProvider", "8"),
            ("twoFactorRemember", "0"),
        ]))
        .respond_with(json_response(200, "token_success.json"))
        .expect(1)
        .mount(&server)
        .await;
    let recovery = TwoFactorToken {
        provider: TwoFactorProvider::RecoveryCode,
        token: "abcd-efgh".into(),
        remember: false,
    };

    client(&server)
        .login(EMAIL, PASSWORD_HASH, Some(&recovery), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn rejected_two_factor_code_carries_the_server_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(json_response(400, "token_two_factor_invalid.json"))
        .mount(&server)
        .await;

    let error = client(&server)
        .login(EMAIL, PASSWORD_HASH, Some(&totp("000000", false)), None)
        .await
        .unwrap_err();

    match error {
        Error::Server {
            status: 400,
            message,
        } => {
            assert!(message.starts_with("Invalid TOTP code!"), "{message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn wrong_password_is_a_server_error_with_the_server_message_not_a_network_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(json_response(400, "token_invalid_password.json"))
        .mount(&server)
        .await;

    let error = client(&server)
        .login(EMAIL, PASSWORD_HASH, None, None)
        .await
        .unwrap_err();

    assert!(!error.is_offline());
    match error {
        Error::Server {
            status: 400,
            message,
        } => {
            assert_eq!(message, "Username or password is incorrect. Try again");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn login_rate_limit_is_reported_with_its_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(json_response(429, "token_rate_limited.json"))
        .mount(&server)
        .await;

    let error = client(&server)
        .login(EMAIL, PASSWORD_HASH, None, None)
        .await
        .unwrap_err();

    match error {
        Error::Server {
            status: 429,
            message,
        } => assert_eq!(message, "Too many login requests"),
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Bitwarden-shaped (the official server's wording), not captured: Vaultwarden has no new-device OTP.
#[tokio::test]
async fn new_device_challenge_is_recognised_and_the_otp_is_sent_on_retry() {
    let challenge = json!({
        "error": "invalid_grant",
        "error_description": "Invalid grant",
        "ErrorModel": { "Message": "New device verification required", "Object": "error" }
    });
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(login_form_with(&[("newDeviceOtp", "654321")]))
        .respond_with(json_response(200, "token_success.json"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(login_form_with(&[]))
        .respond_with(ResponseTemplate::new(400).set_body_json(challenge))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server);

    let first = client
        .login(EMAIL, PASSWORD_HASH, None, None)
        .await
        .unwrap();
    assert!(
        matches!(first, LoginOutcome::NewDeviceOtpRequired),
        "{first:?}"
    );
    let second = client
        .login(EMAIL, PASSWORD_HASH, None, Some("654321"))
        .await
        .unwrap();
    assert!(matches!(second, LoginOutcome::Success(_)), "{second:?}");
}

#[tokio::test]
async fn unauthorized_login_maps_to_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(html_response(401, "sync_unauthorized.txt"))
        .mount(&server)
        .await;

    let error = client(&server)
        .login(EMAIL, PASSWORD_HASH, None, None)
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Unauthorized), "{error:?}");
}

#[tokio::test]
async fn refresh_sends_the_refresh_grant_and_parses_a_response_without_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(common::ExactForm::new(&[
            ("grant_type", "refresh_token"),
            ("client_id", "desktop"),
            ("refresh_token", "old-refresh"),
        ]))
        .respond_with(json_response(200, "token_refresh.json"))
        .expect(1)
        .mount(&server)
        .await;

    let token = client(&server).refresh("old-refresh").await.unwrap();

    let fixture = fixture_json("token_refresh.json");
    assert_eq!(
        token.access_token,
        fixture["access_token"].as_str().unwrap()
    );
    assert_eq!(
        token.refresh_token.as_deref(),
        fixture["refresh_token"].as_str()
    );
    assert_eq!(token.key, None);
}

#[tokio::test]
async fn refresh_token_the_server_rejects_means_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(json_response(400, "token_refresh_invalid.json"))
        .mount(&server)
        .await;

    let error = client(&server).refresh("bogus").await.unwrap_err();

    assert!(matches!(error, Error::Unauthorized), "{error:?}");
}

#[tokio::test]
async fn other_refresh_failures_stay_server_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(json_response(400, "token_rate_limited.json"))
        .mount(&server)
        .await;

    let error = client(&server).refresh("t").await.unwrap_err();

    assert!(
        matches!(error, Error::Server { status: 400, .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_401_from_a_proxy_on_refresh_is_not_a_rejected_refresh_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(html_response(401, "sync_unauthorized.txt"))
        .mount(&server)
        .await;

    let error = client(&server).refresh("t").await.unwrap_err();

    assert!(
        matches!(error, Error::Server { status: 401, .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn send_email_login_posts_credentials_and_accepts_an_empty_200() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/two-factor/send-email-login"))
        .and(body_json(json!({
            "email": EMAIL,
            "masterPasswordHash": PASSWORD_HASH,
            "deviceIdentifier": common::DEVICE_ID,
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    client(&server)
        .send_email_login(EMAIL, PASSWORD_HASH)
        .await
        .unwrap();
}

#[tokio::test]
async fn send_email_login_reports_a_disabled_feature() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/two-factor/send-email-login"))
        .respond_with(json_response(400, "send_email_login_disabled.json"))
        .mount(&server)
        .await;

    let error = client(&server)
        .send_email_login(EMAIL, PASSWORD_HASH)
        .await
        .unwrap_err();

    match error {
        Error::Server {
            status: 400,
            message,
        } => assert_eq!(message, "Email 2FA is disabled"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn gateway_errors_count_as_offline_but_other_server_errors_do_not() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(502).set_body_string("<html>Bad Gateway</html>"))
        .mount(&server)
        .await;
    let error = client(&server).prelogin(EMAIL).await.unwrap_err();
    assert!(
        matches!(error, Error::Server { status: 502, .. }),
        "{error:?}"
    );
    assert!(error.is_offline());

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let error = client(&server).prelogin(EMAIL).await.unwrap_err();
    assert!(
        matches!(error, Error::Server { status: 500, .. }),
        "{error:?}"
    );
    assert!(!error.is_offline());
}

#[tokio::test]
async fn unreachable_server_is_a_network_error_that_means_offline() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);

    let error = client_for(&format!("http://{address}"))
        .prelogin(EMAIL)
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Http(_)), "{error:?}");
    assert!(error.is_offline());
}

#[tokio::test]
async fn a_failed_tls_handshake_is_a_tls_error_not_offline() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Plain HTTP on the port an https:// URL points at: the client's handshake fails in rustls,
    // the same path an expired or untrusted certificate takes.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut hello = [0; 512];
        let _ = socket.read(&mut hello).await;
        let _ = socket
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await;
    });

    let error = client_for(&format!("https://{address}"))
        .prelogin(EMAIL)
        .await
        .unwrap_err();

    assert!(matches!(error, Error::Tls(_)), "{error:?}");
    assert!(!error.is_offline());
}

#[tokio::test]
async fn undecodable_success_body_is_a_decode_error_not_an_offline_signal() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>captive portal</html>"))
        .mount(&server)
        .await;

    let error = client(&server).prelogin(EMAIL).await.unwrap_err();

    assert!(matches!(error, Error::Decode(_)), "{error:?}");
    assert!(!error.is_offline());
}

#[tokio::test]
async fn redirects_are_not_followed_and_explain_themselves() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(
            ResponseTemplate::new(301).insert_header("location", "https://elsewhere.example/"),
        )
        .mount(&server)
        .await;

    let error = client(&server).prelogin(EMAIL).await.unwrap_err();

    match error {
        Error::Server {
            status: 301,
            message,
        } => assert!(message.contains("redirected"), "{message}"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn non_json_error_bodies_fall_back_to_the_status_reason() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/accounts/prelogin"))
        .respond_with(html_response(
            422,
            "cipher_update_missing_encrypted_for.txt",
        ))
        .mount(&server)
        .await;

    let error = client(&server).prelogin(EMAIL).await.unwrap_err();

    match error {
        Error::Server {
            status: 422,
            message,
        } => assert_eq!(message, "Unprocessable Entity"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn client_new_rejects_a_url_that_cannot_be_a_base() {
    let url = url::Url::parse("mailto:someone@example.com").unwrap();
    let result = Client::new(url, common::device());
    assert!(matches!(result, Err(Error::Url(_))));
}
