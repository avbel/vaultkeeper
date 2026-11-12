use std::fmt;

use reqwest::{
    RequestBuilder, StatusCode,
    multipart::{Form, Part},
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use url::Url;
use uuid::Uuid;

use crate::{
    Error, Result,
    http::{HttpTimeouts, MAX_SYNC_BODY_BYTES, Reply, Transport},
    login::{classify_bad_request, is_invalid_grant},
    models::{
        Attachment, AttachmentUpload, Cipher, CipherRequest, Folder, OptionalCipher,
        PreloginResponse, SendFileUpload, SendItem, SendRequest, SyncResponse, TokenResponse,
    },
    server_url::validate_server_url,
    token,
};

const CLIENT_ID: &str = "desktop";
const SCOPE: &str = "api offline_access";

/// Identifies this installation to the server. `identifier` must be persisted across runs.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub identifier: Uuid,
    /// e.g. "macos".
    pub name: String,
    /// 6 Windows desktop, 7 macOS desktop, 8 Linux desktop.
    pub device_type: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TwoFactorProvider {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
    RecoveryCode = 8,
}

impl TwoFactorProvider {
    /// Wire id used in `twoFactorProvider` and as a key of `TwoFactorProviders2`.
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// `None` for ids this client does not know, such as the retired U2F provider (4).
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Authenticator),
            1 => Some(Self::Email),
            2 => Some(Self::Duo),
            3 => Some(Self::YubiKey),
            5 => Some(Self::Remember),
            6 => Some(Self::OrganizationDuo),
            7 => Some(Self::WebAuthn),
            8 => Some(Self::RecoveryCode),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct TwoFactorToken {
    pub provider: TwoFactorProvider,
    pub token: String,
    /// Ask the server for a remember-device token (`twoFactorRemember=1`).
    pub remember: bool,
}

impl fmt::Debug for TwoFactorToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TwoFactorToken")
            .field("provider", &self.provider)
            .field("remember", &self.remember)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum LoginOutcome {
    Success(Box<TokenResponse>),
    /// HTTP 400 with `TwoFactorProviders2`; unknown provider ids are dropped. `webauthn` is the
    /// security-key challenge (the JSON value of provider 7), present when that provider is.
    TwoFactorRequired {
        providers: Vec<TwoFactorProvider>,
        webauthn: Option<String>,
    },
    /// HTTP 400 "new device verification required": resend with an emailed OTP.
    NewDeviceOtpRequired,
}

/// Self-hosted layout: `{base}/identity/...` and `{base}/api/...`.
///
/// Transport failures surface as [`Error::Http`]; wrong passwords, rejected 2FA codes and other
/// server-side refusals are [`Error::Server`] with the server's own message, so
/// [`Error::is_offline`] cleanly separates "server unreachable" from "request refused".
pub struct Client {
    transport: Transport,
    device: DeviceInfo,
    device_type: String,
    device_identifier: String,
}

impl Client {
    pub fn new(base: Url, device: DeviceInfo) -> Result<Self> {
        Self::with_timeouts(base, device, HttpTimeouts::default())
    }

    pub fn with_timeouts(base: Url, device: DeviceInfo, timeouts: HttpTimeouts) -> Result<Self> {
        if base.cannot_be_a_base() {
            return Err(url::ParseError::RelativeUrlWithCannotBeABaseBase.into());
        }
        validate_server_url(&base)?;
        let transport = Transport::new(base, device.device_type, timeouts)?;
        Ok(Self {
            transport,
            device_type: device.device_type.to_string(),
            device_identifier: device.identifier.to_string(),
            device,
        })
    }

    /// `POST {base}/identity/accounts/prelogin` with `{"email"}`.
    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse> {
        let url = self
            .transport
            .endpoint(&["identity", "accounts", "prelogin"])?;
        self.call(self.transport.post(url).json(&json!({ "email": email })))
            .await
    }

    /// `POST {base}/identity/connect/token`, form-encoded password grant: `grant_type=password`,
    /// `username`, `password` (= server hash), `scope=api offline_access`, `client_id=desktop`,
    /// `deviceType`, `deviceIdentifier`, `deviceName`, plus `twoFactor*` / `newDeviceOtp` when given.
    pub async fn login(
        &self,
        email: &str,
        password_hash: &str,
        two_factor: Option<&TwoFactorToken>,
        new_device_otp: Option<&str>,
    ) -> Result<LoginOutcome> {
        let provider = two_factor.map(|factor| factor.provider.id().to_string());
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "password"),
            ("username", email),
            ("password", password_hash),
            ("scope", SCOPE),
            ("client_id", CLIENT_ID),
            ("deviceType", &self.device_type),
            ("deviceIdentifier", &self.device_identifier),
            ("deviceName", &self.device.name),
        ];
        if let (Some(factor), Some(provider)) = (two_factor, provider.as_deref()) {
            form.push(("twoFactorToken", &factor.token));
            form.push(("twoFactorProvider", provider));
            form.push(("twoFactorRemember", if factor.remember { "1" } else { "0" }));
        }
        if let Some(otp) = new_device_otp {
            form.push(("newDeviceOtp", otp));
        }

        let reply = self.token_request(&form).await?;
        if reply.status.is_success() {
            return Ok(LoginOutcome::Success(Box::new(reply.json()?)));
        }
        if reply.status == StatusCode::BAD_REQUEST {
            return classify_bad_request(&reply);
        }
        Err(reply.failure())
    }

    /// `POST {base}/api/two-factor/send-email-login` so the server emails a 2FA code.
    pub async fn send_email_login(&self, email: &str, password_hash: &str) -> Result<()> {
        let url = self
            .transport
            .endpoint(&["api", "two-factor", "send-email-login"])?;
        let body = json!({
            "email": email,
            "masterPasswordHash": password_hash,
            "deviceIdentifier": self.device_identifier,
        });
        self.call_empty(self.transport.post(url).json(&body)).await
    }

    /// `grant_type=refresh_token`, `client_id=desktop`. Only the identity server's rejection of
    /// the refresh token (HTTP 400 `invalid_grant`) is reported as [`Error::Unauthorized`]: the
    /// caller must log in again. Any other failure, including a 401 from an auth proxy in front
    /// of the server, is an [`Error::Server`] and leaves the refresh token usable.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse> {
        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT_ID),
            ("refresh_token", refresh_token),
        ];
        let reply = self.token_request(&form).await?;
        if reply.status.is_success() {
            return reply.json();
        }
        if reply.status == StatusCode::BAD_REQUEST && is_invalid_grant(&reply.body) {
            return Err(Error::Unauthorized);
        }
        Err(reply.error())
    }

    /// `GET {base}/api/sync?excludeDomains=true`.
    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse> {
        let mut url = self.transport.endpoint(&["api", "sync"])?;
        url.set_query(Some("excludeDomains=true"));
        let request = self
            .transport
            .get_transfer(url)
            .bearer_auth(access_token)
            .timeout(self.transport.timeouts.sync);
        self.transport
            .execute_capped(request, MAX_SYNC_BODY_BYTES)
            .await?
            .into_success()?
            .json()
    }

    /// `POST /api/ciphers` (personal) or `POST /api/ciphers/create` with `collectionIds` (org).
    ///
    /// The server rejects writes without `encryptedFor`, the acting user's id; it is taken from
    /// the access token so callers cannot forget it.
    pub async fn create_cipher(
        &self,
        access_token: &str,
        cipher: &CipherRequest,
        collection_ids: &[String],
    ) -> Result<Cipher> {
        let body = cipher_body(cipher, access_token)?;
        let request = if cipher.organization_id.is_some() || !collection_ids.is_empty() {
            let url = self.transport.endpoint(&["api", "ciphers", "create"])?;
            let wrapped = json!({ "cipher": body, "collectionIds": collection_ids });
            self.transport.post(url).json(&wrapped)
        } else {
            let url = self.transport.endpoint(&["api", "ciphers"])?;
            self.transport.post(url).json(&body)
        };
        self.call(request.bearer_auth(access_token)).await
    }

    /// `PUT /api/ciphers/{id}`.
    pub async fn update_cipher(
        &self,
        access_token: &str,
        id: &str,
        cipher: &CipherRequest,
    ) -> Result<Cipher> {
        let body = cipher_body(cipher, access_token)?;
        let url = self.transport.endpoint(&["api", "ciphers", id])?;
        self.call(
            self.transport
                .put(url)
                .bearer_auth(access_token)
                .json(&body),
        )
        .await
    }

    /// `PUT /api/ciphers/{id}/share` with `{cipher, collectionIds}`: moves a personal item into
    /// an organization. `cipher` must be re-encrypted for the organization's key.
    pub async fn share_cipher(
        &self,
        access_token: &str,
        id: &str,
        cipher: &CipherRequest,
        collection_ids: &[String],
    ) -> Result<Cipher> {
        let body = cipher_body(cipher, access_token)?;
        let url = self.transport.endpoint(&["api", "ciphers", id, "share"])?;
        let wrapped = json!({ "cipher": body, "collectionIds": collection_ids });
        self.call(
            self.transport
                .put(url)
                .bearer_auth(access_token)
                .json(&wrapped),
        )
        .await
    }

    /// `PUT /api/ciphers/{id}/collections_v2` with `{collectionIds}`: the full new set of an
    /// organization item's collections.
    pub async fn update_cipher_collections(
        &self,
        access_token: &str,
        id: &str,
        collection_ids: &[String],
    ) -> Result<OptionalCipher> {
        let url = self
            .transport
            .endpoint(&["api", "ciphers", id, "collections_v2"])?;
        self.call(
            self.transport
                .put(url)
                .bearer_auth(access_token)
                .json(&json!({ "collectionIds": collection_ids })),
        )
        .await
    }

    /// Soft delete (`PUT /api/ciphers/{id}/delete`, moves to trash).
    pub async fn trash_cipher(&self, access_token: &str, id: &str) -> Result<()> {
        let url = self.transport.endpoint(&["api", "ciphers", id, "delete"])?;
        self.call_empty(self.transport.put(url).bearer_auth(access_token))
            .await
    }

    /// `PUT /api/ciphers/{id}/restore`.
    pub async fn restore_cipher(&self, access_token: &str, id: &str) -> Result<Cipher> {
        let url = self
            .transport
            .endpoint(&["api", "ciphers", id, "restore"])?;
        self.call(self.transport.put(url).bearer_auth(access_token))
            .await
    }

    /// Permanent delete (`DELETE /api/ciphers/{id}`).
    pub async fn delete_cipher(&self, access_token: &str, id: &str) -> Result<()> {
        let url = self.transport.endpoint(&["api", "ciphers", id])?;
        self.call_empty(self.transport.delete(url).bearer_auth(access_token))
            .await
    }

    /// `POST /api/folders` with `{"name": <EncString>}`.
    pub async fn create_folder(&self, access_token: &str, enc_name: &str) -> Result<Folder> {
        let url = self.transport.endpoint(&["api", "folders"])?;
        let request = self.transport.post(url).bearer_auth(access_token);
        self.call(request.json(&json!({ "name": enc_name }))).await
    }

    /// `PUT /api/folders/{id}`.
    pub async fn update_folder(
        &self,
        access_token: &str,
        id: &str,
        enc_name: &str,
    ) -> Result<Folder> {
        let url = self.transport.endpoint(&["api", "folders", id])?;
        let request = self.transport.put(url).bearer_auth(access_token);
        self.call(request.json(&json!({ "name": enc_name }))).await
    }

    /// `DELETE /api/folders/{id}`.
    pub async fn delete_folder(&self, access_token: &str, id: &str) -> Result<()> {
        let url = self.transport.endpoint(&["api", "folders", id])?;
        self.call_empty(self.transport.delete(url).bearer_auth(access_token))
            .await
    }

    /// `POST /api/sends`: a new text Send.
    pub async fn create_send(&self, access_token: &str, send: &SendRequest) -> Result<SendItem> {
        let url = self.transport.endpoint(&["api", "sends"])?;
        self.call(
            self.transport
                .post(url)
                .bearer_auth(access_token)
                .json(send),
        )
        .await
    }

    /// Reserves a File Send and returns the metadata needed for the direct upload.
    pub async fn create_file_send(
        &self,
        access_token: &str,
        send: &SendRequest,
    ) -> Result<SendFileUpload> {
        let url = self.transport.endpoint(&["api", "sends", "file", "v2"])?;
        self.call(
            self.transport
                .post(url)
                .bearer_auth(access_token)
                .json(send),
        )
        .await
    }

    /// Streams the encrypted file to Vaultwarden. Its multipart filename must match the
    /// encrypted filename in the reservation.
    pub async fn upload_send_file(
        &self,
        access_token: &str,
        upload: &SendFileUpload,
        encrypted_name: &str,
        body: reqwest::Body,
        len: u64,
    ) -> Result<()> {
        if upload.file_upload_type != 0 {
            return Err(Error::Decode(serde::de::Error::custom(
                "expected a direct Send file upload",
            )));
        }
        let send = &upload.send_response;
        let file_id = send
            .file
            .as_ref()
            .and_then(|file| file.id.as_deref())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                Error::Decode(serde::de::Error::custom("missing direct Send file id"))
            })?;
        let url = self
            .transport
            .endpoint(&["api", "sends", &send.id, "file", file_id])?;
        let part = Part::stream_with_length(body, len)
            .file_name(encrypted_name.to_owned())
            .mime_str("application/octet-stream")?;
        let request = self
            .transport
            .post_transfer(url)
            .bearer_auth(access_token)
            .multipart(Form::new().part("data", part))
            .timeout(self.transport.timeouts.transfer);
        self.call_empty(request).await
    }

    /// `PUT /api/sends/{id}`.
    pub async fn update_send(
        &self,
        access_token: &str,
        id: &str,
        send: &SendRequest,
    ) -> Result<SendItem> {
        let url = self.transport.endpoint(&["api", "sends", id])?;
        self.call(self.transport.put(url).bearer_auth(access_token).json(send))
            .await
    }

    /// `DELETE /api/sends/{id}`: gone at once, there is no trash for Sends.
    pub async fn delete_send(&self, access_token: &str, id: &str) -> Result<()> {
        let url = self.transport.endpoint(&["api", "sends", id])?;
        self.call_empty(self.transport.delete(url).bearer_auth(access_token))
            .await
    }

    /// `PUT /api/sends/{id}/remove-password`.
    pub async fn remove_send_password(&self, access_token: &str, id: &str) -> Result<SendItem> {
        let url = self
            .transport
            .endpoint(&["api", "sends", id, "remove-password"])?;
        self.call(self.transport.put(url).bearer_auth(access_token))
            .await
    }

    /// `GET /api/ciphers/{id}/attachment/{attachment_id}`: metadata plus a fresh download URL.
    pub async fn attachment_info(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<Attachment> {
        let url = self.attachment_url(cipher_id, attachment_id)?;
        self.call(self.transport.get(url).bearer_auth(access_token))
            .await
    }

    /// Streams an attachment into `writer` without buffering it and returns the byte count.
    ///
    /// `url` is the value of [`Attachment::url`]: relative to the server, or absolute on the
    /// configured server's origin. Any other host is refused with [`Error::UntrustedUrl`] because
    /// the URL's own token, not an Authorization header, authorizes the download.
    pub async fn download_attachment(
        &self,
        url: &str,
        writer: impl AsyncWrite + Unpin,
    ) -> Result<u64> {
        self.download_attachment_capped(url, writer, u64::MAX).await
    }

    /// [`Self::download_attachment`] that fails with a server error once the body exceeds
    /// `max_bytes`, so a hostile server cannot stream unbounded data to disk.
    pub async fn download_attachment_capped(
        &self,
        url: &str,
        mut writer: impl AsyncWrite + Unpin,
        max_bytes: u64,
    ) -> Result<u64> {
        let url = self.transport.resolve_same_origin(url)?;
        let request = self
            .transport
            .get_transfer(url)
            .timeout(self.transport.timeouts.transfer);
        let mut response = self.transport.open_sensitive(request).await?;

        let mut written = 0_u64;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(reqwest::Error::without_url)?
        {
            written += chunk.len() as u64;
            if written > max_bytes {
                return Err(Error::Server {
                    status: 200,
                    message: "attachment is larger than the server announced".into(),
                });
            }
            writer.write_all(&chunk).await?;
        }
        writer.flush().await?;
        Ok(written)
    }

    /// `POST /api/ciphers/{id}/attachment/v2`: registers the encrypted file name, key and size
    /// and returns the id to upload the data to.
    pub async fn create_attachment(
        &self,
        access_token: &str,
        cipher_id: &str,
        enc_file_name: &str,
        enc_key: &str,
        file_size: u64,
    ) -> Result<AttachmentUpload> {
        let url = self
            .transport
            .endpoint(&["api", "ciphers", cipher_id, "attachment", "v2"])?;
        let body = json!({ "key": enc_key, "fileName": enc_file_name, "fileSize": file_size });
        self.call(
            self.transport
                .post(url)
                .bearer_auth(access_token)
                .json(&body),
        )
        .await
    }

    /// Uploads the encrypted file as the multipart field `data`, streaming `body` (`len` bytes).
    pub async fn upload_attachment_data(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
        body: reqwest::Body,
        len: u64,
    ) -> Result<()> {
        let url = self.attachment_url(cipher_id, attachment_id)?;
        let part = Part::stream_with_length(body, len)
            .file_name("data")
            .mime_str("application/octet-stream")?;
        let request = self
            .transport
            .post_transfer(url)
            .bearer_auth(access_token)
            .multipart(Form::new().part("data", part))
            .timeout(self.transport.timeouts.transfer);
        self.call_empty(request).await
    }

    /// `DELETE /api/ciphers/{id}/attachment/{attachment_id}`.
    pub async fn delete_attachment(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<()> {
        let url = self.attachment_url(cipher_id, attachment_id)?;
        self.call_empty(self.transport.delete(url).bearer_auth(access_token))
            .await
    }

    fn attachment_url(&self, cipher_id: &str, attachment_id: &str) -> Result<Url> {
        self.transport
            .endpoint(&["api", "ciphers", cipher_id, "attachment", attachment_id])
    }

    async fn token_request(&self, form: &[(&str, &str)]) -> Result<Reply> {
        let url = self.transport.endpoint(&["identity", "connect", "token"])?;
        self.transport
            .execute(self.transport.post(url).form(form))
            .await
    }

    async fn call<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        self.transport
            .execute(request)
            .await?
            .into_success()?
            .json()
    }

    async fn call_empty(&self, request: RequestBuilder) -> Result<()> {
        self.transport.execute(request).await?.into_success()?;
        Ok(())
    }
}

fn cipher_body(cipher: &CipherRequest, access_token: &str) -> Result<Value> {
    let mut body = serde_json::to_value(cipher)?;
    if let Value::Object(map) = &mut body {
        map.insert(
            "encryptedFor".into(),
            Value::String(token::subject(access_token)?),
        );
    }
    Ok(body)
}
