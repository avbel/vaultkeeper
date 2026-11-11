//! After the user confirms a fill with a login saved for another site, offer to add this site's
//! address to the login so it matches, and fills at once, next time.

use std::{collections::HashSet, future::Future, time::Duration};

use vk_ipc::{BrowserPrompt, BrowserReply, dto::ItemSummaryDto};
use vk_vault::{
    Vault, VaultService,
    model::{Filter, ItemData, ItemId, ItemKind, ItemSummary},
    uri_match::{DefaultMatch, PageUrl, saved_site_label},
};

use super::save::{SaveError, write_error};

const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounds the memory of what was already asked; the oldest answers are forgotten wholesale.
const MAX_ASKED: usize = 64;

pub struct AddressOffer {
    pub browser: String,
    pub item: ItemId,
    /// `scheme://host[:port]`, as `PageUrl::origin` gives it.
    pub origin: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not offered: the setting is off, nothing to add, or this pair was already asked.
    Skipped,
    Dismissed,
    Added,
}

/// Remembers which (login, site) pairs were already offered, so a "Not now" is not repeated
/// until the daemon restarts.
#[derive(Default)]
pub struct AddressOffers {
    asked: HashSet<(ItemId, String)>,
}

impl AddressOffers {
    /// `prompt` shows the question and returns the user's reply; nothing is written unless it
    /// is `Save { target: Some(item) }` for this very login and the same vault session.
    pub async fn offer<P, F>(
        &mut self,
        vault: &Vault,
        offer: AddressOffer,
        enabled: bool,
        prompt: P,
    ) -> Result<Outcome, SaveError>
    where
        P: FnOnce(BrowserPrompt) -> F,
        F: Future<Output = BrowserReply>,
    {
        if !enabled {
            return Ok(Outcome::Skipped);
        }
        let Some(page) = PageUrl::new(&offer.origin, "/") else {
            return Ok(Outcome::Skipped);
        };
        let Ok(snapshot) = vault.browser_snapshot() else {
            return Ok(Outcome::Skipped);
        };
        let Some(summary) = editable_login(vault, &offer.item) else {
            return Ok(Outcome::Skipped);
        };
        if !names_the_same_site(vault, &offer.item, &page) {
            return Ok(Outcome::Skipped);
        }
        let key = (offer.item.clone(), page.registrable_domain());
        if self.asked.contains(&key) {
            return Ok(Outcome::Skipped);
        }
        if self.asked.len() >= MAX_ASKED {
            self.asked.clear();
        }
        self.asked.insert(key);
        let reply = tokio::time::timeout(
            PROMPT_TIMEOUT,
            prompt(BrowserPrompt::AddAddress {
                browser: offer.browser,
                host: page.host_ascii().to_owned(),
                item: ItemSummaryDto::from(&summary),
            }),
        )
        .await
        .unwrap_or(BrowserReply::Dismissed);
        let BrowserReply::Save {
            target: Some(target),
        } = reply
        else {
            return Ok(Outcome::Dismissed);
        };
        let still_here = vault
            .browser_snapshot()
            .is_ok_and(|now| now.same_session(snapshot));
        if *target != *offer.item.0 || !still_here {
            return Ok(Outcome::Dismissed);
        }
        add_address(vault, &offer.item, &offer.origin, &page).await
    }
}

/// The login may take this site's address only when one of its saved addresses has exactly the
/// same site name under another public suffix (`site.com` and `site.io`). A subdomain of another
/// name (`site.another.com`), a lookalike with a different letter (`sitе.com`, Cyrillic е, which
/// reaches us as punycode) and tenants of shared hosts (`github.io`) never qualify: the user's
/// own click would otherwise tie their account to a phishing page.
fn names_the_same_site(vault: &Vault, id: &ItemId, page: &PageUrl) -> bool {
    let Some(label) = page.site_label() else {
        return false;
    };
    let Ok(draft) = vault.draft(id) else {
        return false;
    };
    let ItemData::Login { uris, .. } = &draft.data else {
        return false;
    };
    uris.iter()
        .any(|uri| saved_site_label(uri).as_deref() == Some(label.as_str()))
}

fn editable_login(vault: &Vault, id: &ItemId) -> Option<ItemSummary> {
    let filter = Filter {
        kind: Some(ItemKind::Login),
        ..Filter::default()
    };
    vault
        .search("", &filter)
        .ok()?
        .iter()
        .find(|item| item.id == *id && item.editable && !item.deleted)
        .cloned()
}

async fn add_address(
    vault: &Vault,
    id: &ItemId,
    origin: &str,
    page: &PageUrl,
) -> Result<Outcome, SaveError> {
    let Ok(mut draft) = vault.draft(id) else {
        return Ok(Outcome::Dismissed);
    };
    let ItemData::Login { uris, .. } = &mut draft.data else {
        return Ok(Outcome::Dismissed);
    };
    // The login may have gained an address that matches since the fill, for example on another
    // device; adding it again would only duplicate it.
    if uris
        .iter()
        .any(|uri| vk_vault::uri_match::matches(uri, None, DefaultMatch::Domain, page))
    {
        return Ok(Outcome::Dismissed);
    }
    uris.push(origin.to_owned());
    vault
        .save(Some(id.clone()), draft)
        .await
        .map(|_| Outcome::Added)
        .map_err(|error| write_error(&error))
}
