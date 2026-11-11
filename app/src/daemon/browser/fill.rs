//! One explicitly approved browser fill. Session policy and response delivery are owned by the caller.

use std::{future::Future, time::Duration};

use vk_ipc::{
    BrowserPrompt, BrowserReply, TypingTarget,
    browser::protocol::{ErrorCode, FillFields, FillResult},
    dto::ItemSummaryDto,
};
use vk_vault::{
    BrowserCredentials, BrowserFields, BrowserSnapshot, Error, LoginMatch, Vault,
    model::ItemId,
    uri_match::{DefaultMatch, PageUrl},
};

use super::validation;

/// How the credential was released, for the activity log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Picker,
    Remembered,
    /// The only login matching the site, released without the picker.
    Single,
}

pub struct FillRequest {
    pub browser: String,
    pub choose: bool,
    pub fill_single: bool,
    /// The item approved earlier on this connection for this origin, if any.
    pub remembered: Option<ItemId>,
    pub origin: String,
    pub path: String,
    pub fields: FillFields,
    pub default_match: DefaultMatch,
    pub touch_id: bool,
    pub return_to: Option<TypingTarget>,
}

pub struct Filled {
    pub result: FillResult,
    pub item: ItemId,
    pub host: String,
    /// The caller may remember `origin -> item` for this connection.
    pub remember: bool,
    pub via: Via,
    pub has_totp: bool,
    /// Set when the user filled a login saved for another site: this site's address, which the
    /// daemon may offer to add to the login.
    pub unsaved_address: Option<String>,
}

impl Filled {
    #[cfg(test)]
    #[must_use]
    pub fn bare(result: FillResult) -> Self {
        Self {
            result,
            item: ItemId("item".into()),
            host: "example.com".into(),
            remember: false,
            via: Via::Picker,
            has_totp: false,
            unsaved_address: None,
        }
    }
}

/// The caller must cancel this future on disconnect, disable, or session shutdown. `authorized`
/// must recheck the current pairing and integration setting immediately before the vault read.
/// Password re-prompt and other-site confirmation are enforced by the native picker; the snapshot
/// invalidates that approval if the vault session or index changes while the picker is open.
pub async fn fill<P, PFut, T, TFut, A, AFut>(
    vault: &Vault,
    request: FillRequest,
    prompt: P,
    presence: T,
    authorized: A,
) -> Result<Filled, ErrorCode>
where
    P: FnOnce(BrowserPrompt) -> PFut,
    PFut: Future<Output = BrowserReply>,
    T: FnOnce() -> TFut,
    TFut: Future<Output = bool>,
    A: FnOnce() -> AFut,
    AFut: Future<Output = bool>,
{
    let page = validation::page(&request.origin, &request.path)?;
    let snapshot = vault
        .browser_snapshot()
        .map_err(|error| vault_error(&error))?;
    let matches = vault
        .logins_for(&page, request.default_match)
        .map_err(|error| vault_error(&error))?;
    let fields = BrowserFields {
        username: request.fields.username,
        password: request.fields.password,
    };
    if let Some((item, via)) = silent_item(&request, &page, &matches) {
        // Skipping the picker never skips Touch ID: the setting means every fill.
        if request.touch_id && !presence().await {
            return Err(ErrorCode::Denied);
        }
        if !authorized().await {
            return Err(ErrorCode::Denied);
        }
        let revealed = reveal_retrying(
            vault,
            snapshot,
            &item,
            &page,
            (request.default_match, false),
            fields,
        )?;
        return Ok(filled(revealed, item, &page, via));
    }
    let reply = tokio::time::timeout(
        Duration::from_secs(90),
        prompt(BrowserPrompt::Fill {
            browser: request.browser,
            host: page.host_ascii().to_owned(),
            insecure: !page.is_https(),
            matches: matches
                .iter()
                .map(|item| ItemSummaryDto::from(&item.summary))
                .collect(),
            touch_id: request.touch_id,
            return_to: request.return_to,
        }),
    )
    .await
    .map_err(|_| ErrorCode::Timeout)?;
    let BrowserReply::Fill {
        item_id,
        confirmed_other_site,
    } = reply
    else {
        return Err(ErrorCode::Cancelled);
    };
    if request.touch_id && !presence().await {
        return Err(ErrorCode::Denied);
    }
    if !authorized().await {
        return Err(ErrorCode::Denied);
    }
    let item = ItemId(item_id);
    if !confirmed_other_site
        && !vault
            .login_matches(&item, &page, request.default_match)
            .map_err(|error| vault_error(&error))?
    {
        return Err(ErrorCode::Denied);
    }
    let revealed = reveal_retrying(
        vault,
        snapshot,
        &item,
        &page,
        (request.default_match, confirmed_other_site),
        fields,
    )?;
    Ok(filled(revealed, item, &page, Via::Picker))
}

/// Reveals under the snapshot taken before the prompt or Touch ID sheet. A background sync can
/// move the index while the user is deciding; the user approved this item for this page and
/// `browser_reveal` rechecks both, so a fresh snapshot of the same session is enough. A different
/// session stays refused.
fn reveal_retrying(
    vault: &Vault,
    snapshot: BrowserSnapshot,
    item: &ItemId,
    page: &PageUrl,
    (default_match, confirmed_other_site): (DefaultMatch, bool),
    fields: BrowserFields,
) -> Result<BrowserCredentials, ErrorCode> {
    let reveal = |snapshot| {
        vault.browser_reveal(
            snapshot,
            item,
            page,
            default_match,
            confirmed_other_site,
            fields,
        )
    };
    match reveal(snapshot) {
        Err(Error::Conflict) => {
            let fresh = vault
                .browser_snapshot()
                .map_err(|error| vault_error(&error))?;
            if !snapshot.same_session(fresh) {
                return Err(ErrorCode::Denied);
            }
            reveal(fresh)
        }
        result => result,
    }
    .map_err(|error| vault_error(&error))
}

/// The login to release without the picker, if any. A remembered approval applies only to an
/// item that still matches the page and needs no master-password re-prompt; a single match is
/// released at once only on an encrypted page. `choose` always shows the picker.
fn silent_item(
    request: &FillRequest,
    page: &PageUrl,
    matches: &[LoginMatch],
) -> Option<(ItemId, Via)> {
    if request.choose {
        return None;
    }
    if let Some(item) = &request.remembered
        && matches
            .iter()
            .any(|found| found.summary.id == *item && !found.summary.reprompt)
    {
        return Some((item.clone(), Via::Remembered));
    }
    match matches {
        [only] if request.fill_single && page.is_https() && !only.summary.reprompt => {
            Some((only.summary.id.clone(), Via::Single))
        }
        _ => None,
    }
}

fn filled(revealed: BrowserCredentials, item: ItemId, page: &PageUrl, via: Via) -> Filled {
    Filled {
        unsaved_address: (!revealed.matched).then(|| page.origin()),
        remember: revealed.matched && !revealed.reprompt,
        has_totp: revealed.has_totp,
        result: FillResult {
            username: revealed.username,
            password: revealed.password,
        },
        item,
        host: page.host_ascii().to_owned(),
        via,
    }
}

fn vault_error(error: &Error) -> ErrorCode {
    match error {
        Error::Locked => ErrorCode::Locked,
        Error::LoggedOut => ErrorCode::LoggedOut,
        Error::NotFound => ErrorCode::NoLogin,
        Error::Conflict => ErrorCode::Denied,
        _ => ErrorCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vk_vault::{MemorySecretStore, VaultConfig};

    fn request(origin: &str) -> FillRequest {
        FillRequest {
            browser: "Firefox".into(),
            choose: false,
            fill_single: false,
            remembered: None,
            origin: origin.into(),
            path: "/".into(),
            fields: FillFields {
                username: true,
                password: true,
            },
            default_match: DefaultMatch::Domain,
            touch_id: false,
            return_to: None,
        }
    }

    #[tokio::test]
    async fn rejects_insecure_or_logged_out_without_prompting() {
        let dir = tempfile::tempdir().expect("directory");
        let config = VaultConfig::new(
            dir.path().to_owned(),
            vk_api::DeviceInfo {
                identifier: uuid::Uuid::new_v4(),
                name: "test".into(),
                device_type: 7,
            },
            tokio::runtime::Handle::current(),
        );
        let vault = Vault::open(config, Arc::new(MemorySecretStore::new())).expect("vault");
        for (origin, expected) in [
            ("http://example.com", "insecure_page"),
            ("https://example.com", "logged_out"),
        ] {
            let result = fill(
                &vault,
                request(origin),
                |_| async { panic!("unexpected prompt") },
                || async { panic!("unexpected presence check") },
                || async { panic!("unexpected authorization check") },
            )
            .await;
            let Err(error) = result else {
                panic!("fill unexpectedly succeeded");
            };
            assert_eq!(serde_json::to_value(error).expect("serialize"), expected);
        }
    }

    fn login(id: &str, reprompt: bool) -> LoginMatch {
        LoginMatch {
            summary: vk_vault::model::ItemSummary {
                id: ItemId(id.into()),
                kind: vk_vault::model::ItemKind::Login,
                name: id.into(),
                subtitle: String::new().into(),
                favorite: false,
                folder_id: None,
                organization_id: None,
                primary_uri: None,
                has_password: true,
                has_totp: false,
                reprompt,
                deleted: false,
                editable: true,
            },
            matched_uri: "https://example.com".into(),
        }
    }

    fn single_request(choose: bool, remembered: Option<&str>) -> FillRequest {
        FillRequest {
            choose,
            fill_single: true,
            remembered: remembered.map(|id| ItemId(id.into())),
            ..request("https://example.com")
        }
    }

    #[test]
    fn a_lone_match_skips_the_picker_only_when_it_is_safe_to() {
        let https = validation::page("https://example.com", "/").expect("page");
        let http = validation::page("http://localhost:3000", "/").expect("page");
        let one = [login("a", false)];
        let two = [login("a", false), login("b", false)];

        let picked = silent_item(&single_request(false, None), &https, &one);
        assert!(matches!(picked, Some((item, Via::Single)) if item.0.as_ref() == "a"));
        assert!(silent_item(&single_request(false, None), &https, &two).is_none());
        assert!(silent_item(&single_request(false, None), &http, &one).is_none());
        assert!(silent_item(&single_request(false, None), &https, &[login("a", true)]).is_none());
        assert!(silent_item(&single_request(true, None), &https, &one).is_none());
        let off = FillRequest {
            fill_single: false,
            ..single_request(false, None)
        };
        assert!(silent_item(&off, &https, &one).is_none());
    }

    #[test]
    fn a_remembered_item_wins_and_a_reprompt_item_is_never_remembered() {
        let https = validation::page("https://example.com", "/").expect("page");
        let two = [login("a", false), login("b", false)];
        let picked = silent_item(&single_request(false, Some("b")), &https, &two);
        assert!(matches!(picked, Some((item, Via::Remembered)) if item.0.as_ref() == "b"));
        let reprompt = [login("a", false), login("b", true)];
        assert!(silent_item(&single_request(false, Some("b")), &https, &reprompt).is_none());
    }
}
