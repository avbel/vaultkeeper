use url::Url;
use uuid::Uuid;

use crate::{
    Result,
    models::{Cipher, CipherRequest, Folder, PreloginResponse, SyncResponse, TokenResponse},
};

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

#[derive(Debug, Clone)]
pub struct TwoFactorToken {
    pub provider: TwoFactorProvider,
    pub token: String,
    /// Ask the server for a remember-device token (`twoFactorRemember=1`).
    pub remember: bool,
}

#[derive(Debug)]
pub enum LoginOutcome {
    Success(Box<TokenResponse>),
    /// HTTP 400 with `TwoFactorProviders2`; unknown provider ids are dropped.
    TwoFactorRequired(Vec<TwoFactorProvider>),
    /// HTTP 400 "new device verification required": resend with an emailed OTP.
    NewDeviceOtpRequired,
}

/// Self-hosted layout: `{base}/identity/...` and `{base}/api/...`.
pub struct Client {
    base: Url,
    http: reqwest::Client,
    device: DeviceInfo,
}

impl Client {
    pub fn new(base: Url, device: DeviceInfo) -> Result<Self> {
        let _ = (base, device);
        todo!("step 4")
    }

    /// `POST {base}/identity/accounts/prelogin` with `{"email"}`.
    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse> {
        let _ = (email, &self.base, &self.http, &self.device);
        todo!("step 4")
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
        let _ = (email, password_hash, two_factor, new_device_otp);
        todo!("step 4")
    }

    /// `POST {base}/api/two-factor/send-email-login` so the server emails a 2FA code.
    pub async fn send_email_login(&self, email: &str, password_hash: &str) -> Result<()> {
        let _ = (email, password_hash);
        todo!("step 4")
    }

    /// `grant_type=refresh_token`, `client_id=desktop`.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse> {
        let _ = refresh_token;
        todo!("step 4")
    }

    /// `GET {base}/api/sync?excludeDomains=true`.
    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse> {
        let _ = access_token;
        todo!("step 4")
    }

    /// `POST /api/ciphers` (personal) or `POST /api/ciphers/create` with `collectionIds` (org).
    pub async fn create_cipher(
        &self,
        access_token: &str,
        cipher: &CipherRequest,
        collection_ids: &[String],
    ) -> Result<Cipher> {
        let _ = (access_token, cipher, collection_ids);
        todo!("step 4")
    }

    /// `PUT /api/ciphers/{id}`.
    pub async fn update_cipher(
        &self,
        access_token: &str,
        id: &str,
        cipher: &CipherRequest,
    ) -> Result<Cipher> {
        let _ = (access_token, id, cipher);
        todo!("step 4")
    }

    /// Soft delete (`PUT /api/ciphers/{id}/delete`, moves to trash).
    pub async fn trash_cipher(&self, access_token: &str, id: &str) -> Result<()> {
        let _ = (access_token, id);
        todo!("step 4")
    }

    /// `PUT /api/ciphers/{id}/restore`.
    pub async fn restore_cipher(&self, access_token: &str, id: &str) -> Result<Cipher> {
        let _ = (access_token, id);
        todo!("step 4")
    }

    /// Permanent delete (`DELETE /api/ciphers/{id}`).
    pub async fn delete_cipher(&self, access_token: &str, id: &str) -> Result<()> {
        let _ = (access_token, id);
        todo!("step 4")
    }

    /// `POST /api/folders` with `{"name": <EncString>}`.
    pub async fn create_folder(&self, access_token: &str, enc_name: &str) -> Result<Folder> {
        let _ = (access_token, enc_name);
        todo!("step 4")
    }

    /// `PUT /api/folders/{id}`.
    pub async fn update_folder(
        &self,
        access_token: &str,
        id: &str,
        enc_name: &str,
    ) -> Result<Folder> {
        let _ = (access_token, id, enc_name);
        todo!("step 4")
    }

    /// `DELETE /api/folders/{id}`.
    pub async fn delete_folder(&self, access_token: &str, id: &str) -> Result<()> {
        let _ = (access_token, id);
        todo!("step 4")
    }
}
