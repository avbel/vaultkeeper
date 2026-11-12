//! Vault passkeys for a page's `navigator.credentials` calls. The extension relays the options;
//! everything else happens here: the relying party check, the native prompt, Touch ID, the key
//! and its signature, and the write to the vault. A request the vault cannot or should not
//! answer is handed back as [`ErrorCode::Fallback`] for the browser's own WebAuthn.

use std::{future::Future, time::Duration};

use serde_json::{Value, json};
use vk_ipc::{
    BrowserPrompt, BrowserReply, TypingTarget, browser::protocol::ErrorCode, dto::ItemSummaryDto,
};
use vk_vault::{
    Error, NewPasskey, PasskeyMatch, PasskeyTarget, Vault,
    model::ItemId,
    uri_match::{DefaultMatch, PageUrl, valid_rp_id},
};
use vk_webauthn::{
    Assertion, Ceremony, ClientDataJson, CreationOptions, FLAG_USER_VERIFIED, PASSKEY_FLAGS,
    PasskeyKey, Registration, RequestOptions, b64,
};

use super::validation;

const PROMPT_TIMEOUT: Duration = Duration::from_secs(90);
/// What a vault passkey answers `getTransports()` with, as the Bitwarden clients do.
const TRANSPORTS: [&str; 2] = ["internal", "hybrid"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyCeremony {
    Create,
    Get,
}

pub struct PasskeyRequest {
    pub browser: String,
    pub ceremony: PasskeyCeremony,
    pub origin: String,
    pub options: Value,
    pub default_match: DefaultMatch,
    pub return_to: Option<TypingTarget>,
}

/// The caller must cancel this future when the page gives up, on disconnect or disable;
/// `authorized` rechecks the pairing and integration right before the vault is read.
pub async fn passkey<P, PFut, T, TFut, A, AFut>(
    vault: &Vault,
    request: PasskeyRequest,
    prompt: P,
    presence: T,
    authorized: A,
) -> Result<Value, ErrorCode>
where
    P: FnOnce(BrowserPrompt) -> PFut,
    PFut: Future<Output = BrowserReply>,
    T: FnOnce() -> TFut,
    TFut: Future<Output = bool>,
    A: FnOnce() -> AFut,
    AFut: Future<Output = bool>,
{
    let page = validation::page(&request.origin, "/").map_err(|_| ErrorCode::Fallback)?;
    // WebAuthn allows plain http for localhost only.
    if !page.is_https() && page.host_ascii() != "localhost" {
        return Err(ErrorCode::Fallback);
    }
    match request.ceremony {
        PasskeyCeremony::Get => get(vault, &request, &page, prompt, presence, authorized).await,
        PasskeyCeremony::Create => {
            create(vault, &request, &page, prompt, presence, authorized).await
        }
    }
}

fn relying_party(page: &PageUrl, requested: Option<&str>) -> Result<String, ErrorCode> {
    let host = page.host_ascii().trim_end_matches('.').to_ascii_lowercase();
    let rp_id = requested.map_or_else(|| host.clone(), str::to_ascii_lowercase);
    // An id the page may not use is the browser's to refuse with its own SecurityError.
    if valid_rp_id(&rp_id, &host) {
        Ok(rp_id.trim_end_matches('.').to_owned())
    } else {
        Err(ErrorCode::Fallback)
    }
}

async fn get<P, PFut, T, TFut, A, AFut>(
    vault: &Vault,
    request: &PasskeyRequest,
    page: &PageUrl,
    prompt: P,
    presence: T,
    authorized: A,
) -> Result<Value, ErrorCode>
where
    P: FnOnce(BrowserPrompt) -> PFut,
    PFut: Future<Output = BrowserReply>,
    T: FnOnce() -> TFut,
    TFut: Future<Output = bool>,
    A: FnOnce() -> AFut,
    AFut: Future<Output = bool>,
{
    let options = RequestOptions::from_json(&request.options).map_err(|_| ErrorCode::Fallback)?;
    let rp_id = relying_party(page, options.rp_id.as_deref())?;
    let found = vault
        .passkeys_for(&rp_id)
        .map_err(|error| vault_error(&error))?;
    let usable = usable_passkeys(found, &options);
    if usable.is_empty() {
        // Sites ask for a security key this way too: the browser must answer at once.
        return Err(ErrorCode::Fallback);
    }
    let snapshot = vault
        .browser_snapshot()
        .map_err(|error| vault_error(&error))?;
    let reply = tokio::time::timeout(
        PROMPT_TIMEOUT,
        prompt(BrowserPrompt::Passkey {
            browser: request.browser.clone(),
            host: page.host_ascii().to_owned(),
            save: false,
            user_name: String::new(),
            choices: usable.iter().map(choice).collect(),
            return_to: request.return_to.clone(),
        }),
    )
    .await
    .map_err(|_| ErrorCode::Fallback)?;
    let BrowserReply::Save { target: Some(id) } = reply else {
        return Err(ErrorCode::Fallback);
    };
    let chosen = usable
        .iter()
        .find(|found| found.summary.id.0 == id)
        .ok_or(ErrorCode::NotAllowed)?;
    if !presence().await || !authorized().await {
        return Err(ErrorCode::Fallback);
    }
    let secret = vault
        .passkey_secret(snapshot, &chosen.summary.id, &chosen.credential_id, &rp_id)
        .or_else(|error| match error {
            // A sync while the prompt was open moved the index on; the choice still stands.
            Error::Conflict => vault.browser_snapshot().and_then(|fresh| {
                if snapshot.same_session(fresh) {
                    vault.passkey_secret(fresh, &chosen.summary.id, &chosen.credential_id, &rp_id)
                } else {
                    Err(Error::Conflict)
                }
            }),
            other => Err(other),
        })
        .map_err(|error| vault_error(&error))?;
    let key = PasskeyKey::from_pkcs8_der(&secret.key_pkcs8).map_err(|_| ErrorCode::Internal)?;
    let counter = next_counter(secret.counter);
    if counter > 0 {
        vault
            .set_passkey_counter(&chosen.summary.id, &chosen.credential_id, counter)
            .await
            .map_err(|error| vault_error(&error))?;
    }
    let client_data = ClientDataJson::new(Ceremony::Get, &options.challenge.0, &page.origin());
    let mut assertion = vk_webauthn::get_assertion(
        &key,
        &chosen.credential_id,
        &rp_id,
        PASSKEY_FLAGS | FLAG_USER_VERIFIED,
        counter,
        &client_data,
    );
    assertion.user_handle = secret.user_handle;
    Ok(assertion_json(&assertion))
}

/// The allow list names the keys the site knows of; without one, only discoverable passkeys
/// may be offered. Logins that need the master password are left to the browser: the prompt
/// has no password field.
fn usable_passkeys(found: Vec<PasskeyMatch>, options: &RequestOptions) -> Vec<PasskeyMatch> {
    found
        .into_iter()
        .filter(|found| !found.summary.reprompt)
        .filter(|found| {
            if options.allow_credentials.is_empty() {
                found.discoverable
            } else {
                options
                    .allow_credentials
                    .iter()
                    .any(|allowed| allowed.id.0 == found.credential_id)
            }
        })
        .collect()
}

/// Passkeys made here keep the counter at 0, as the Bitwarden clients do (they sync between
/// devices, so a count would go backwards). An imported one that counts goes on counting.
const fn next_counter(stored: u32) -> u32 {
    if stored == 0 {
        0
    } else {
        stored.saturating_add(1)
    }
}

fn choice(found: &PasskeyMatch) -> ItemSummaryDto {
    let mut summary = ItemSummaryDto::from(&found.summary);
    if !found.user_name.is_empty() {
        summary.subtitle = found.user_name.as_str().into();
    }
    summary
}

async fn create<P, PFut, T, TFut, A, AFut>(
    vault: &Vault,
    request: &PasskeyRequest,
    page: &PageUrl,
    prompt: P,
    presence: T,
    authorized: A,
) -> Result<Value, ErrorCode>
where
    P: FnOnce(BrowserPrompt) -> PFut,
    PFut: Future<Output = BrowserReply>,
    T: FnOnce() -> TFut,
    TFut: Future<Output = bool>,
    A: FnOnce() -> AFut,
    AFut: Future<Output = bool>,
{
    let options = CreationOptions::from_json(&request.options).map_err(|_| ErrorCode::Fallback)?;
    let rp_id = relying_party(page, options.rp.id.as_deref())?;
    if !options.accepts_es256()
        || options
            .authenticator_selection
            .authenticator_attachment
            .as_deref()
            == Some("cross-platform")
    {
        return Err(ErrorCode::Fallback);
    }
    let existing = vault
        .passkeys_for(&rp_id)
        .map_err(|error| vault_error(&error))?;
    if existing.iter().any(|found| {
        options
            .exclude_credentials
            .iter()
            .any(|excluded| excluded.id.0 == found.credential_id)
    }) {
        return Err(ErrorCode::InvalidState);
    }
    let logins = vault
        .logins_for(page, request.default_match)
        .map_err(|error| vault_error(&error))?;
    let choices = save_choices(&logins, &existing);
    let reply = tokio::time::timeout(
        PROMPT_TIMEOUT,
        prompt(BrowserPrompt::Passkey {
            browser: request.browser.clone(),
            host: page.host_ascii().to_owned(),
            save: true,
            user_name: options.user.name.clone(),
            choices: choices.clone(),
            return_to: request.return_to.clone(),
        }),
    )
    .await
    .map_err(|_| ErrorCode::Fallback)?;
    let BrowserReply::Save { target } = reply else {
        return Err(ErrorCode::Fallback);
    };
    if let Some(id) = &target
        && !choices.iter().any(|choice| choice.id == *id)
    {
        return Err(ErrorCode::NotAllowed);
    }
    if !presence().await || !authorized().await {
        return Err(ErrorCode::Fallback);
    }
    let key = PasskeyKey::generate().map_err(|_| ErrorCode::Internal)?;
    let credential_id = uuid::Uuid::new_v4().as_bytes().to_vec();
    let client_data = ClientDataJson::new(Ceremony::Create, &options.challenge.0, &page.origin());
    let registration = vk_webauthn::make_credential(
        &key,
        &credential_id,
        &rp_id,
        PASSKEY_FLAGS | FLAG_USER_VERIFIED,
        &client_data,
    )
    .map_err(|_| ErrorCode::Internal)?;
    let discoverable = options.wants_discoverable();
    let target = match target {
        Some(id) => PasskeyTarget::Existing(ItemId(id)),
        None => PasskeyTarget::New {
            name: match options.rp.name.trim() {
                "" => rp_id.clone(),
                name => name.to_owned(),
            },
            username: options.user.name.clone(),
            uri: page.origin(),
        },
    };
    vault
        .save_passkey(
            target,
            NewPasskey {
                credential_id,
                key_pkcs8: key.to_pkcs8_der().map_err(|_| ErrorCode::Internal)?,
                rp_id,
                rp_name: options.rp.name.clone(),
                user_handle: options.user.id.0.clone(),
                user_name: options.user.name.clone(),
                user_display_name: options.user.display_name.clone(),
                discoverable,
            },
        )
        .await
        .map_err(|error| vault_error(&error))?;
    Ok(registration_json(
        &registration,
        options.extensions.cred_props == Some(true),
        discoverable,
    ))
}

/// Logins the new passkey may go into: editable, no master-password re-prompt, and none that
/// holds a passkey for this site already, which saving would replace without a word.
fn save_choices(logins: &[vk_vault::LoginMatch], existing: &[PasskeyMatch]) -> Vec<ItemSummaryDto> {
    logins
        .iter()
        .map(|login| &login.summary)
        .filter(|summary| summary.editable && !summary.reprompt)
        .filter(|summary| !existing.iter().any(|found| found.summary.id == summary.id))
        .map(ItemSummaryDto::from)
        .collect()
}

fn assertion_json(assertion: &Assertion) -> Value {
    let id = b64::encode(&assertion.credential_id);
    json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": b64::encode(&assertion.client_data_json),
            "authenticatorData": b64::encode(&assertion.authenticator_data),
            "signature": b64::encode(&assertion.signature),
            "userHandle": assertion.user_handle.as_deref().map(b64::encode),
        },
        "clientExtensionResults": {},
    })
}

fn registration_json(registration: &Registration, cred_props: bool, discoverable: bool) -> Value {
    let id = b64::encode(&registration.credential_id);
    let extensions = if cred_props {
        json!({ "credProps": { "rk": discoverable } })
    } else {
        json!({})
    };
    json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": b64::encode(&registration.client_data_json),
            "attestationObject": b64::encode(&registration.attestation_object),
            "authenticatorData": b64::encode(&registration.authenticator_data),
            "publicKey": b64::encode(&registration.public_key_spki),
            "publicKeyAlgorithm": vk_webauthn::ES256,
            "transports": TRANSPORTS,
        },
        "clientExtensionResults": extensions,
    })
}

fn vault_error(error: &Error) -> ErrorCode {
    match error {
        Error::Locked => ErrorCode::Locked,
        Error::LoggedOut | Error::NotFound | Error::Offline | Error::Conflict => {
            ErrorCode::Fallback
        }
        Error::ReadOnly => ErrorCode::NotAllowed,
        _ => {
            tracing::warn!(%error, "passkey request failed");
            ErrorCode::Internal
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use vk_vault::{
        LoginMatch,
        model::{ItemKind, ItemSummary},
    };

    use super::*;

    fn summary(id: &str, reprompt: bool, editable: bool) -> ItemSummary {
        ItemSummary {
            id: ItemId(id.into()),
            kind: ItemKind::Login,
            name: id.into(),
            subtitle: "anne".into(),
            favorite: false,
            folder_id: None,
            organization_id: None,
            primary_uri: None,
            has_password: true,
            has_totp: false,
            reprompt,
            deleted: false,
            editable,
        }
    }

    fn passkey(id: &str, credential: u8, discoverable: bool, reprompt: bool) -> PasskeyMatch {
        PasskeyMatch {
            summary: summary(id, reprompt, true),
            credential_id: vec![credential],
            user_name: "anne".into(),
            discoverable,
        }
    }

    fn request(allow: &[u8]) -> RequestOptions {
        RequestOptions::from_json(&json!({
            "challenge": "AQ",
            "allowCredentials": allow
                .iter()
                .map(|id| json!({ "type": "public-key", "id": b64::encode(&[*id]) }))
                .collect::<Vec<_>>(),
        }))
        .expect("options")
    }

    fn ids(found: &[PasskeyMatch]) -> Vec<&str> {
        found.iter().map(|found| &*found.summary.id.0).collect()
    }

    #[test]
    fn offers_allowed_or_discoverable_passkeys_never_reprompt_items() {
        let found = || {
            vec![
                passkey("listed", 1, false, false),
                passkey("discoverable", 2, true, false),
                passkey("guarded", 3, true, true),
            ]
        };
        assert_eq!(
            ids(&usable_passkeys(found(), &request(&[1, 3]))),
            ["listed"]
        );
        assert_eq!(
            ids(&usable_passkeys(found(), &request(&[]))),
            ["discoverable"]
        );
        assert!(usable_passkeys(found(), &request(&[9])).is_empty());
    }

    #[test]
    fn a_new_passkey_never_lands_on_a_login_it_would_damage() {
        let login = |id: &str, reprompt: bool, editable: bool| LoginMatch {
            summary: summary(id, reprompt, editable),
            matched_uri: "https://example.com".into(),
        };
        let logins = [
            login("free", false, true),
            login("holds-one", false, true),
            login("guarded", true, true),
            login("read-only", false, false),
        ];
        let existing = [passkey("holds-one", 1, true, false)];
        let choices = save_choices(&logins, &existing);
        let offered: Vec<&str> = choices.iter().map(|choice| &*choice.id).collect();
        assert_eq!(offered, ["free"]);
    }

    #[test]
    fn the_relying_party_is_the_host_or_a_registrable_parent() {
        let page = PageUrl::new("https://login.example.com", "/").expect("page");
        let rp = |requested| relying_party(&page, requested).ok();
        assert_eq!(rp(None).as_deref(), Some("login.example.com"));
        assert_eq!(rp(Some("Example.com")).as_deref(), Some("example.com"));
        assert_eq!(rp(Some("com")), None);
        assert_eq!(rp(Some("other.com")), None);
    }

    #[test]
    fn only_a_counting_passkey_counts_on() {
        assert_eq!(next_counter(0), 0);
        assert_eq!(next_counter(41), 42);
        assert_eq!(next_counter(u32::MAX), u32::MAX);
    }
}
