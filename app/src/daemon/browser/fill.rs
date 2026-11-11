//! One explicitly approved browser fill. Session policy and response delivery are owned by the caller.

use std::{future::Future, time::Duration};

use vk_ipc::{
    BrowserPrompt, BrowserReply, TypingTarget,
    browser::protocol::{ErrorCode, FillFields, FillResult},
    dto::ItemSummaryDto,
};
use vk_vault::{
    BrowserCredentials, BrowserFields, Error, LoginMatch, Vault,
    model::ItemId,
    uri_match::{DefaultMatch, PageUrl},
};

use super::validation;

pub struct FillRequest {
    pub browser: String,
    pub choose: bool,
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
    pub from_memory: bool,
    pub has_totp: bool,
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
            from_memory: false,
            has_totp: false,
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
    if let Some(item) = remembered_item(&request, &matches) {
        let revealed = vault
            .browser_reveal(snapshot, &item, &page, request.default_match, false, fields)
            .map_err(|error| vault_error(&error))?;
        return Ok(filled(revealed, item, &page, true));
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
    let reveal = |snapshot| {
        vault.browser_reveal(
            snapshot,
            &item,
            &page,
            request.default_match,
            confirmed_other_site,
            fields,
        )
    };
    let revealed = match reveal(snapshot) {
        // A background sync moved the index while the picker was open. The user approved this
        // item for this page and `browser_reveal` rechecks both, so a fresh snapshot of the
        // same session is enough; a different session stays refused.
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
    .map_err(|error| vault_error(&error))?;
    Ok(filled(revealed, item, &page, false))
}

/// A remembered approval applies only to an item that still matches the page and needs no
/// master-password re-prompt; `choose` always shows the picker.
fn remembered_item(request: &FillRequest, matches: &[LoginMatch]) -> Option<ItemId> {
    if request.choose {
        return None;
    }
    let item = request.remembered.as_ref()?;
    matches
        .iter()
        .any(|found| found.summary.id == *item && !found.summary.reprompt)
        .then(|| item.clone())
}

fn filled(revealed: BrowserCredentials, item: ItemId, page: &PageUrl, from_memory: bool) -> Filled {
    Filled {
        remember: revealed.matched && !revealed.reprompt,
        has_totp: revealed.has_totp,
        result: FillResult {
            username: revealed.username,
            password: revealed.password,
        },
        item,
        host: page.host_ascii().to_owned(),
        from_memory,
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
}
