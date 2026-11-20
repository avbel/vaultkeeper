//! The browser save-candidate flow: decide whether a captured login is worth offering, ask the
//! user in a native prompt, and write the vault. The daemon owns the connection, the answer to
//! the extension (always `{}` at once) and the toast for a failed write.
//!
//! Run [`SaveManager`] from one worker task: candidates are handled one at a time, so at most one
//! save prompt is open and a duplicate cannot race its twin past the dedupe table.

use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use subtle::ConstantTimeEq as _;
use tokio::sync::Mutex;
use vk_ipc::{BrowserPrompt, BrowserReply, TypingTarget, dto::ItemSummaryDto};
use vk_vault::{
    BrowserFields, BrowserSnapshot, CONFLICT_MESSAGE, Error, OFFLINE_MESSAGE, Vault, VaultService,
    model::{ItemData, ItemDraft, ItemId, ItemSummary, SessionState},
    uri_match::{DefaultMatch, PageUrl},
};
use zeroize::Zeroizing;

use super::{
    dedupe::SaveDedupe,
    dispatch::{Candidate, canonical_origin},
    generated::{self, GeneratedStore},
    pairing::PairingStore,
    save_queue::SaveQueue,
    save_target::{self, SaveTarget},
    validation,
};

const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);
const SHOWN_USERNAME_CHARS: usize = 64;

/// The username comes from the page, so control and bidirectional-format characters are
/// dropped: they could reorder or hide parts of the text in the native prompt.
fn shown_username(username: &str) -> String {
    username
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .take(SHOWN_USERNAME_CHARS)
        .collect()
}

pub struct SaveSettings {
    pub prompts_enabled: bool,
    pub default_match: DefaultMatch,
    pub prompt_timeout: Duration,
    pub return_to: Option<TypingTarget>,
}

impl SaveSettings {
    #[must_use]
    pub fn new(prompts_enabled: bool, default_match: DefaultMatch) -> Self {
        Self {
            prompts_enabled,
            default_match,
            prompt_timeout: PROMPT_TIMEOUT,
            return_to: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    Disabled,
    InvalidPage,
    LoggedOut,
    Locked,
    NeverSave,
    Duplicate,
    /// Same password already stored, nothing eligible to update, or no username to save under.
    NothingToSave,
    /// The vault session or the target changed while the prompt was open; nothing was written.
    Stale,
    QueueFull,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Skipped(Skipped),
    Queued,
    Dismissed,
    NeverSave,
    Created(ItemId),
    Updated(ItemId),
}

#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    /// The reason is safe to show the user.
    #[error("Could not save the login: {0}")]
    Write(String),
    #[error("Could not remember this choice")]
    NeverSave,
}

/// The persistent per-site opt-out list, keyed by registrable domain.
pub trait NeverSaveStore: Send + Sync {
    fn contains(&self, domain: &str) -> impl Future<Output = anyhow::Result<bool>> + Send;
    fn add(&self, domain: &str) -> impl Future<Output = anyhow::Result<()>> + Send;
}

impl NeverSaveStore for Mutex<PairingStore> {
    async fn contains(&self, domain: &str) -> anyhow::Result<bool> {
        self.lock().await.is_never_save(domain)
    }

    async fn add(&self, domain: &str) -> anyhow::Result<()> {
        self.lock().await.never_save(domain)
    }
}

impl<T: NeverSaveStore> NeverSaveStore for Arc<T> {
    fn contains(&self, domain: &str) -> impl Future<Output = anyhow::Result<bool>> + Send {
        (**self).contains(domain)
    }

    fn add(&self, domain: &str) -> impl Future<Output = anyhow::Result<()>> + Send {
        (**self).add(domain)
    }
}

enum Plan {
    Create,
    Update(ItemSummary),
    Choose(Vec<ItemSummary>),
    /// One of these logins, or a new one.
    ChooseOrNew(Vec<ItemSummary>),
}

impl Plan {
    fn permits(&self, target: Option<&str>) -> bool {
        match (self, target) {
            (Self::Create | Self::ChooseOrNew(_), None) => true,
            (Self::Update(item), Some(id)) => &*item.id.0 == id,
            (Self::Choose(items) | Self::ChooseOrNew(items), Some(id)) => {
                items.iter().any(|item| &*item.id.0 == id)
            }
            _ => false,
        }
    }
}

struct Admitted {
    page: PageUrl,
    snapshot: BrowserSnapshot,
    /// The entry of the generated password this candidate carries.
    generated: Option<u64>,
}

/// Evaluates one candidate against the unlocked vault. Returns `Locked` as a skip rather than
/// queueing; [`SaveManager`] does the queueing. After a write was started this never retries: a
/// cancelled or failed request cannot prove the server did not commit, and the dedupe entry
/// already made the candidate a repeat.
///
/// A password Vaultkeeper generated for the page is offered even with save prompts off, and on
/// a sign-up form even without a username; once saved it leaves `generated`.
pub async fn handle<P, F>(
    vault: &Vault,
    candidate: Candidate,
    settings: &SaveSettings,
    never_save: &impl NeverSaveStore,
    generated: &std::sync::Mutex<GeneratedStore>,
    dedupe: &mut SaveDedupe,
    prompt: P,
) -> Result<Outcome, SaveError>
where
    P: FnOnce(BrowserPrompt) -> F + Send,
    F: Future<Output = BrowserReply> + Send,
{
    let entry = generated::find(vault, generated, &candidate.origin, &candidate.password);
    let admitted = match admit(vault, &candidate, settings, entry, never_save, dedupe).await {
        Ok(admitted) => admitted,
        Err(skipped) => return Ok(Outcome::Skipped(skipped)),
    };
    let plan = match plan(
        vault,
        &admitted.page,
        admitted.snapshot,
        settings,
        &candidate,
        entry.is_some(),
    ) {
        Ok(plan) => plan,
        Err(skipped) => return Ok(Outcome::Skipped(skipped)),
    };
    let reply = tokio::time::timeout(
        settings.prompt_timeout,
        prompt(prompt_for(&candidate, &admitted, &plan, settings)),
    )
    .await
    .unwrap_or(BrowserReply::Dismissed);
    match reply {
        BrowserReply::NeverForSite => {
            never_save
                .add(&admitted.page.registrable_domain())
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "could not persist never-save");
                    SaveError::NeverSave
                })?;
            Ok(Outcome::NeverSave)
        }
        BrowserReply::Save { target } => {
            let outcome = commit(vault, &admitted, settings, &candidate, &plan, target).await;
            if let (Ok(Outcome::Created(_) | Outcome::Updated(_)), Some(id)) = (&outcome, entry) {
                generated
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(id);
            }
            outcome
        }
        _ => Ok(Outcome::Dismissed),
    }
}

async fn admit(
    vault: &Vault,
    candidate: &Candidate,
    settings: &SaveSettings,
    generated: Option<u64>,
    never_save: &impl NeverSaveStore,
    dedupe: &mut SaveDedupe,
) -> Result<Admitted, Skipped> {
    if !settings.prompts_enabled && generated.is_none() {
        return Err(Skipped::Disabled);
    }
    let page =
        validation::page(&candidate.origin, &candidate.path).map_err(|_| Skipped::InvalidPage)?;
    let snapshot = vault.browser_snapshot().map_err(|error| match error {
        Error::LoggedOut => Skipped::LoggedOut,
        Error::Locked => Skipped::Locked,
        _ => Skipped::Stale,
    })?;
    // A store that cannot answer fails closed: no prompt for a site the user may have refused.
    if never_save
        .contains(&page.registrable_domain())
        .await
        .unwrap_or(true)
    {
        return Err(Skipped::NeverSave);
    }
    if !dedupe.admit(
        &candidate.origin,
        &candidate.username,
        &candidate.password,
        Instant::now(),
    ) {
        return Err(Skipped::Duplicate);
    }
    Ok(Admitted {
        page,
        snapshot,
        generated,
    })
}

fn plan(
    vault: &Vault,
    page: &PageUrl,
    snapshot: BrowserSnapshot,
    settings: &SaveSettings,
    candidate: &Candidate,
    generated: bool,
) -> Result<Plan, Skipped> {
    let matches: Vec<ItemSummary> = vault
        .logins_for(page, settings.default_match)
        .map_err(|_| Skipped::Stale)?
        .into_iter()
        .map(|found| found.summary)
        .collect();
    // A generated password on a form with neither a username nor a current password is a
    // sign-up or a reset by email link; only the user can tell which.
    if generated && !candidate.has_current && candidate.username.is_empty() {
        let editable: Vec<ItemSummary> = matches.into_iter().filter(|item| item.editable).collect();
        return Ok(if editable.is_empty() {
            Plan::Create
        } else {
            Plan::ChooseOrNew(editable)
        });
    }
    match save_target::select(&candidate.username, &candidate.kind, &matches) {
        SaveTarget::Ignore => Err(Skipped::NothingToSave),
        SaveTarget::Create => Ok(Plan::Create),
        SaveTarget::Choose(items) => Ok(Plan::Choose(items.into_iter().cloned().collect())),
        SaveTarget::Compare(item) => {
            if stored_password_equals(
                vault,
                page,
                snapshot,
                settings,
                &item.id,
                &candidate.password,
            )? {
                Err(Skipped::NothingToSave)
            } else {
                Ok(Plan::Update(item.clone()))
            }
        }
    }
}

fn stored_password_equals(
    vault: &Vault,
    page: &PageUrl,
    snapshot: BrowserSnapshot,
    settings: &SaveSettings,
    id: &ItemId,
    candidate: &str,
) -> Result<bool, Skipped> {
    let revealed = vault
        .browser_reveal(
            snapshot,
            id,
            page,
            settings.default_match,
            false,
            BrowserFields {
                username: false,
                password: true,
            },
        )
        .map_err(|_| Skipped::Stale)?;
    Ok(revealed
        .password
        .is_some_and(|stored| bool::from(stored.as_bytes().ct_eq(candidate.as_bytes()))))
}

fn prompt_for(
    candidate: &Candidate,
    admitted: &Admitted,
    plan: &Plan,
    settings: &SaveSettings,
) -> BrowserPrompt {
    let summaries = |items: &[ItemSummary]| items.iter().map(ItemSummaryDto::from).collect();
    let (update_of, choices) = match plan {
        Plan::Create => (None, Vec::new()),
        Plan::Update(item) => (Some(ItemSummaryDto::from(item)), Vec::new()),
        Plan::Choose(items) | Plan::ChooseOrNew(items) => (None, summaries(items)),
    };
    BrowserPrompt::Save {
        browser: candidate.browser.clone(),
        host: admitted.page.host_ascii().to_owned(),
        username: shown_username(&candidate.username),
        update_of,
        choices,
        generated: admitted.generated.is_some(),
        allow_new: matches!(plan, Plan::ChooseOrNew(_)),
        return_to: settings.return_to.clone(),
    }
}

/// The answer must be one the prompt offered and must still hold in the vault as it is now.
async fn commit(
    vault: &Vault,
    admitted: &Admitted,
    settings: &SaveSettings,
    candidate: &Candidate,
    offered: &Plan,
    target: Option<Arc<str>>,
) -> Result<Outcome, SaveError> {
    let target = target.as_deref();
    let Ok(now) = vault.browser_snapshot() else {
        return Ok(stale());
    };
    if !now.same_session(admitted.snapshot) || !offered.permits(target) {
        return Ok(stale());
    }
    let Ok(fresh) = plan(
        vault,
        &admitted.page,
        now,
        settings,
        candidate,
        admitted.generated.is_some(),
    ) else {
        return Ok(stale());
    };
    if !fresh.permits(target) {
        return Ok(stale());
    }
    match target {
        Some(id) => update(vault, ItemId(Arc::from(id)), candidate).await,
        None => create(vault, &admitted.page, candidate).await,
    }
}

fn stale() -> Outcome {
    Outcome::Skipped(Skipped::Stale)
}

async fn update(vault: &Vault, id: ItemId, candidate: &Candidate) -> Result<Outcome, SaveError> {
    let Ok(mut draft) = vault.draft(&id) else {
        return Ok(stale());
    };
    let ItemData::Login { password, .. } = &mut draft.data else {
        return Ok(stale());
    };
    password.clone_from(&candidate.password);
    vault
        .save(Some(id), draft)
        .await
        .map(Outcome::Updated)
        .map_err(|error| write_error(&error))
}

async fn create(
    vault: &Vault,
    page: &PageUrl,
    candidate: &Candidate,
) -> Result<Outcome, SaveError> {
    let draft = new_login(
        page.host_ascii(),
        &candidate.origin,
        &candidate.username,
        &candidate.password,
    );
    vault
        .save(None, draft)
        .await
        .map(Outcome::Created)
        .map_err(|error| write_error(&error))
}

/// A login named after `host`, without `www.`, that matches `origin`.
pub(super) fn new_login(host: &str, origin: &str, username: &str, password: &str) -> ItemDraft {
    ItemDraft {
        name: host.strip_prefix("www.").unwrap_or(host).to_owned(),
        notes: Zeroizing::default(),
        folder_id: None,
        organization_id: None,
        collection_ids: Vec::new(),
        favorite: false,
        reprompt: false,
        fields: Vec::new(),
        data: ItemData::Login {
            username: username.to_owned(),
            password: Zeroizing::new(password.to_owned()),
            totp: Zeroizing::default(),
            uris: vec![origin.to_owned()],
        },
        revision_date: None,
    }
}

pub(super) fn write_error(error: &Error) -> SaveError {
    let reason = match error {
        Error::Conflict => CONFLICT_MESSAGE,
        Error::Locked => "the vault is locked",
        Error::LoggedOut => "you are logged out",
        Error::ReadOnly => "the item is read-only",
        _ if error.is_offline() => OFFLINE_MESSAGE,
        _ => {
            tracing::warn!(%error, "browser save failed");
            "the server did not accept the change"
        }
    };
    SaveError::Write(reason.to_owned())
}

/// Locked-vault glue: holds up to three candidates for ten minutes, bound to one account.
#[derive(Default)]
pub struct SaveManager {
    queue: Option<(Arc<str>, SaveQueue)>,
    dedupe: SaveDedupe,
}

impl SaveManager {
    /// Handles `candidate` now when the vault is unlocked, queues it when locked.
    pub async fn submit<P, F>(
        &mut self,
        vault: &Vault,
        candidate: Candidate,
        settings: &SaveSettings,
        never_save: &impl NeverSaveStore,
        generated: &std::sync::Mutex<GeneratedStore>,
        prompt: P,
    ) -> Result<Outcome, SaveError>
    where
        P: FnOnce(BrowserPrompt) -> F + Send,
        F: Future<Output = BrowserReply> + Send,
    {
        match vault.state() {
            SessionState::LoggedOut => Ok(Outcome::Skipped(Skipped::LoggedOut)),
            SessionState::Locked { .. } => Ok(self.enqueue(vault, candidate, settings, generated)),
            SessionState::Unlocked { .. } => {
                handle(
                    vault,
                    candidate,
                    settings,
                    never_save,
                    generated,
                    &mut self.dedupe,
                    prompt,
                )
                .await
            }
        }
    }

    /// With prompts off, only a page Vaultkeeper generated a password for is worth holding:
    /// whether this candidate carries that password can only be told after the unlock.
    fn enqueue(
        &mut self,
        vault: &Vault,
        candidate: Candidate,
        settings: &SaveSettings,
        generated: &std::sync::Mutex<GeneratedStore>,
    ) -> Outcome {
        let Some(account) = vault.active_account_id() else {
            return Outcome::Skipped(Skipped::LoggedOut);
        };
        if !settings.prompts_enabled
            && !generated
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .has_origin(&account, &canonical_origin(&candidate.origin))
        {
            return Outcome::Skipped(Skipped::Disabled);
        }
        if validation::page(&candidate.origin, &candidate.path).is_err() {
            return Outcome::Skipped(Skipped::InvalidPage);
        }
        if self
            .queue
            .as_ref()
            .is_none_or(|(owner, _)| *owner != account)
        {
            self.queue = Some((Arc::clone(&account), SaveQueue::new(account.to_string())));
        }
        let Some((_, queue)) = self.queue.as_mut() else {
            return Outcome::Skipped(Skipped::QueueFull);
        };
        if queue.push(&account, candidate, Instant::now()) {
            Outcome::Queued
        } else {
            Outcome::Skipped(Skipped::QueueFull)
        }
    }

    /// Evaluates what was queued while locked, oldest first, one prompt at a time.
    pub async fn on_unlocked<P, F>(
        &mut self,
        vault: &Vault,
        settings: &SaveSettings,
        never_save: &impl NeverSaveStore,
        generated: &std::sync::Mutex<GeneratedStore>,
        mut prompt: P,
    ) -> Vec<Result<Outcome, SaveError>>
    where
        P: FnMut(BrowserPrompt) -> F + Send,
        F: Future<Output = BrowserReply> + Send,
    {
        let Some(account) = vault.active_account_id() else {
            self.clear();
            return Vec::new();
        };
        let Some((_, queue)) = self.queue.as_mut() else {
            return Vec::new();
        };
        let mut results = Vec::new();
        for candidate in queue.take(&account, Instant::now()) {
            results.push(
                handle(
                    vault,
                    candidate,
                    settings,
                    never_save,
                    generated,
                    &mut self.dedupe,
                    &mut prompt,
                )
                .await,
            );
        }
        results
    }

    /// Wipes everything held: logout, account switch, quit.
    pub fn clear(&mut self) {
        self.queue = None;
    }

    /// When the owner must call [`Self::expire`], even if no request arrives before then.
    #[must_use]
    pub fn next_expiry(&self) -> Option<Instant> {
        self.queue
            .as_ref()
            .and_then(|(_, queue)| queue.next_expiry())
    }

    pub fn expire(&mut self, now: Instant) {
        if let Some((_, queue)) = self.queue.as_mut() {
            queue.expire(now);
        }
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::*;

    #[test]
    fn page_text_in_the_prompt_loses_control_and_bidi_characters() {
        assert_eq!(shown_username("al\u{202E}ice\n\u{0}@x"), "alice@x");
        assert_eq!(shown_username(&"a".repeat(100)).chars().count(), 64);
    }
}
