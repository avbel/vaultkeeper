//! Passwords the daemon generated for web pages and still keeps, because they were not saved.

use std::{future::Future, pin::Pin, sync::Arc};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::dto::WireError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedDto {
    pub id: u64,
    /// The ASCII host of the page it was generated for.
    pub host: String,
    pub created_unix: u64,
}

pub type SaveFuture = Pin<Box<dyn Future<Output = Result<Arc<str>, WireError>> + Send>>;

pub trait GeneratedHost: Send + Sync + 'static {
    /// The active account's entries, newest first; empty unless the vault is unlocked.
    fn list(&self) -> Vec<GeneratedDto>;
    fn reveal(&self, id: u64) -> Result<Zeroizing<String>, WireError>;
    /// Creates a login for the entry's page and drops the entry; returns the new item id.
    fn save(&self, id: u64) -> SaveFuture;
    fn forget(&self, id: u64);
}
