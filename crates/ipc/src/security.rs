//! The daemon's protection chains, as Settings shows them. The daemon owns the
//! probes, so the UI process asks instead of probing from its own, different process.

use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};

/// Mirrors `vk_platform::security::ChainStatus`, weakest first so the derived order compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChainState {
    Off,
    Reduced,
    Standard,
    Full,
}

impl ChainState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Full => "Full",
            Self::Standard => "Standard",
            Self::Reduced => "Reduced",
            Self::Off => "Off",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainDto {
    pub id: String,
    pub name: String,
    pub state: ChainState,
    /// Mechanism of the exclusive link in use.
    pub active: Option<String>,
    pub stacked: Vec<String>,
    /// The next weaker link that would take over.
    pub fallback: Option<String>,
    pub note: Option<String>,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReportDto {
    pub chains: Vec<ChainDto>,
}

pub type SecurityFuture = Pin<Box<dyn Future<Output = SecurityReportDto> + Send>>;

pub trait SecurityHost: Send + Sync + 'static {
    /// Probes every chain again and returns the result.
    fn report(&self) -> SecurityFuture;
}
