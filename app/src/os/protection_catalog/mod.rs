//! What Settings and `vaultkeeper security status` say about each protection chain: one catalog
//! turns the daemon's report into finished rows (title, state, plain-language detail, technical
//! name, remedy), so the two surfaces cannot disagree. Linux chains only; macOS and Windows
//! register none.

mod remedies;
mod render;
mod rows;
mod summary;
#[cfg(test)]
mod tests;

use vk_ipc::{ChainDto, ChainRequired, ChainState};

use super::{security_gate::Distro, self_protection};

pub use render::{plain_text, status_text};
pub use summary::{Section, Segment, Summary, sections, summarize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Memory,
    StoredSecrets,
    Isolation,
    Session,
    Desktop,
}

impl Group {
    pub const ALL: [Self; 5] = [
        Self::Memory,
        Self::StoredSecrets,
        Self::Isolation,
        Self::Session,
        Self::Desktop,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Memory => "MEMORY",
            Self::StoredSecrets => "STORED SECRETS",
            Self::Isolation => "ISOLATION",
            Self::Session => "SESSION",
            Self::Desktop => "DESKTOP INTEGRATION · not counted above",
        }
    }

    #[must_use]
    pub const fn counted(self) -> bool {
        !matches!(self, Self::Desktop)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Active,
    Limited,
    Off,
    Missing,
}

impl Level {
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Limited => "Limited",
            Self::Off => "Off",
            Self::Missing => "Missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Green,
    Yellow,
    Red,
    Neutral,
}

impl Tone {
    /// The name the Slint side maps to a theme token.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Red => "red",
            Self::Neutral => "neutral",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionRow {
    pub id: String,
    pub group: Group,
    pub title: String,
    pub protects: String,
    pub level: Level,
    pub tone: Tone,
    pub detail: String,
    pub technical: String,
    pub steps_title: String,
    pub steps: Vec<String>,
    pub notes: Vec<String>,
    /// The command or file line the row's Copy button copies; empty for none.
    pub copy: String,
    /// The row's button text; empty for none.
    pub action: String,
}

impl ProtectionRow {
    #[must_use]
    pub const fn counted(&self) -> bool {
        self.group.counted()
    }

    #[must_use]
    pub fn accessible_label(&self) -> String {
        format!("{}, {}. {}", self.title, self.level.word(), self.detail)
    }
}

/// Links that mean "nothing protects here", whatever the chain's own status says.
const NOTHING: [&str; 3] = ["no-sandbox", "none", "window-and-log"];

/// Links that work with a stated weakness.
const WEAK: [&str; 5] = ["keyctl", "mlock", "peer-pidfd", "screensaver", "plain"];

const CREDS_LINK: &str = "systemd-creds";

fn level_of(chain: &ChainDto) -> Level {
    if chain.state == ChainState::Off {
        return if chain.required == ChainRequired::Refuse {
            Level::Missing
        } else {
            Level::Off
        };
    }
    let active = chain.active_id.as_deref();
    if active.is_some_and(|id| NOTHING.contains(&id)) {
        return Level::Off;
    }
    let creds_missing =
        chain.id == "secret-files" && !chain.stacked_ids.iter().any(|id| id == CREDS_LINK);
    if chain.state == ChainState::Reduced
        || chain.note.is_some()
        || active.is_some_and(|id| WEAK.contains(&id))
        || creds_missing
    {
        Level::Limited
    } else {
        Level::Active
    }
}

fn tone_of(chain: &ChainDto, group: Group, level: Level) -> Tone {
    match level {
        Level::Active => Tone::Green,
        Level::Missing => Tone::Red,
        Level::Off if group == Group::Desktop => Tone::Neutral,
        Level::Off if asked_for_and_failed(chain) => Tone::Red,
        Level::Limited | Level::Off => Tone::Yellow,
    }
}

/// An Off the user did not choose: the sandbox was requested and not enforced, or the process
/// is readable although it hardened itself.
fn asked_for_and_failed(chain: &ChainDto) -> bool {
    match chain.id.as_str() {
        "memory-read" => true,
        "sandbox" => rows::sandbox_kind(chain) != rows::SandboxKind::NotRequested,
        _ => false,
    }
}

const BPF_CHAIN: &str = "bpf";

/// The finished row for one chain. A chain the catalog does not know is described from its own
/// report, so a new chain shows before it has wording.
#[must_use]
pub fn describe(chain: &ChainDto, distro: Distro) -> ProtectionRow {
    let level = level_of(chain);
    let text = rows::text(chain, level);
    let remedy = remedies::remedy(chain, level, distro);
    let tone = tone_of(chain, text.group, level);
    let installable = chain.id == BPF_CHAIN && chain.state != ChainState::Full;
    ProtectionRow {
        id: chain.id.clone(),
        group: text.group,
        title: text.title,
        protects: text.protects,
        level,
        tone,
        detail: text.detail,
        technical: text.technical,
        steps_title: remedy.title,
        steps: remedy.steps,
        notes: remedy.notes,
        copy: remedy.copy,
        action: if installable && chain.fix.is_some() {
            "Install…".to_owned()
        } else {
            String::new()
        },
    }
}

/// Rows in the catalog's fixed order: by group, then by the order inside it.
#[must_use]
pub fn describe_all(chains: &[ChainDto], distro: Distro) -> Vec<ProtectionRow> {
    let mut rows: Vec<(usize, ProtectionRow)> = chains
        .iter()
        .map(|chain| (rows::position(&chain.id), describe(chain, distro)))
        .collect();
    rows.sort_by_key(|(position, row)| {
        (
            Group::ALL
                .iter()
                .position(|group| *group == row.group)
                .unwrap_or(usize::MAX),
            *position,
        )
    });
    rows.into_iter().map(|(_, row)| row).collect()
}

pub(super) fn landlock_abi_label(chain: &ChainDto) -> String {
    chain
        .note
        .as_deref()
        .and_then(self_protection::landlock_abi)
        .map_or_else(|| "?".to_owned(), |abi| abi.to_string())
}
