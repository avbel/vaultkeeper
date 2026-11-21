//! Protection chains (linux-ideas.md §11): every protection is a list of mechanisms, strongest
//! first, and the strongest one that probes as available is used. Startup refuses only when a
//! `Refuse` chain ends up with nothing; everything else is shown in `security status` and Settings.
//!
//! Probes and activations are closures, so the real ones can capture syscall shims and the tests
//! can inject fakes; evaluation itself is plain data in, plain data out.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What startup does when a chain has no working link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Required {
    Refuse,
    Warn,
    Status,
}

/// One probe result. `Degraded` works but with a stated caveat, so it never counts as Full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Probe {
    Available,
    Degraded(String),
    Unavailable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChainStatus {
    /// No link works.
    Off,
    /// A link below the chain's minimum.
    Reduced,
    /// The minimum or better, but not the strongest link.
    Standard,
    /// The strongest link, fully available.
    Full,
}

impl ChainStatus {
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

const APPLY_FAILED: &str = "failed to apply: ";

type ProbeFn = Box<dyn Fn() -> Probe + Send + Sync>;
type ActivateFn = Box<dyn Fn() -> std::io::Result<()> + Send + Sync>;

pub struct Link {
    pub id: &'static str,
    /// The mechanism's name as the user sees it ("memfd_secret", "Landlock").
    pub mechanism: &'static str,
    /// A stacking link is applied on top of whichever exclusive link wins (dumpable(0), modes).
    pub stacks: bool,
    probe: ProbeFn,
    activate: Option<ActivateFn>,
}

impl Link {
    pub fn new(
        id: &'static str,
        mechanism: &'static str,
        probe: impl Fn() -> Probe + Send + Sync + 'static,
    ) -> Self {
        Self {
            id,
            mechanism,
            stacks: false,
            probe: Box::new(probe),
            activate: None,
        }
    }

    #[must_use]
    pub const fn stacking(mut self) -> Self {
        self.stacks = true;
        self
    }

    /// Runs when the link is chosen; an error moves the chain on to the next link.
    #[must_use]
    pub fn on_activate(
        mut self,
        activate: impl Fn() -> std::io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.activate = Some(Box::new(activate));
        self
    }
}

pub struct Chain {
    pub id: &'static str,
    pub name: &'static str,
    pub required: Required,
    /// Index into `links` of the weakest link that still counts as Standard.
    pub minimum: usize,
    pub links: Vec<Link>,
    /// The fix shown when the chain is below its minimum (already picked for this distribution).
    pub fix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    pub link: String,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReport {
    pub id: String,
    pub name: String,
    pub required: Required,
    pub status: ChainStatus,
    /// Mechanism of the exclusive link in use.
    pub active: Option<String>,
    pub stacked: Vec<String>,
    /// The next weaker exclusive link that would take over if `active` went away.
    pub fallback: Option<String>,
    pub skipped: Vec<Skipped>,
    pub note: Option<String>,
    pub fix: Option<String>,
}

/// Whether links are applied while probing (startup) or only probed (Re-check, which compares
/// with the startup report when there is one).
#[derive(Clone, Copy)]
enum Mode<'a> {
    Apply,
    Recheck(Option<&'a ChainReport>),
}

fn applied_at_startup(link: &Link, startup: Option<&ChainReport>) -> bool {
    startup.is_some_and(|report| {
        report.active.as_deref() == Some(link.mechanism)
            || report
                .stacked
                .iter()
                .any(|stacked| stacked == link.mechanism)
    })
}

/// The startup's own reason when the link failed to apply, else a generic one.
fn not_applied(link: &Link, startup: Option<&ChainReport>) -> Skipped {
    startup
        .and_then(|report| {
            report
                .skipped
                .iter()
                .find(|skipped| skipped.link == link.id)
        })
        .cloned()
        .unwrap_or_else(|| Skipped {
            link: link.id.to_owned(),
            why: "not applied at startup".to_owned(),
        })
}

impl Chain {
    /// Probes every link, activates the strongest working exclusive link and every working
    /// stacking link.
    #[must_use]
    pub fn evaluate(&self) -> ChainReport {
        self.run(Mode::Apply)
    }

    /// Probes again without activating anything: the links were applied once at startup, and
    /// applying them twice (Landlock, `dumpable`) is not safe. A link with an activation counts
    /// only if `startup` had it applied, so a re-check never claims a mechanism nothing applied;
    /// only a restart can apply another.
    #[must_use]
    pub fn reevaluate(&self, startup: Option<&ChainReport>) -> ChainReport {
        self.run(Mode::Recheck(startup))
    }

    fn run(&self, mode: Mode<'_>) -> ChainReport {
        let mut active: Option<usize> = None;
        let mut strongest: Option<(usize, bool)> = None;
        let mut fallback = None;
        let mut stacked = Vec::new();
        let mut skipped = Vec::new();
        let mut note = None;

        for (index, link) in self.links.iter().enumerate() {
            if !link.stacks && active.is_some() {
                if fallback.is_none()
                    && matches!((link.probe)(), Probe::Available | Probe::Degraded(_))
                {
                    fallback = Some(link.mechanism.to_owned());
                }
                continue;
            }
            if let Mode::Recheck(startup) = mode
                && link.activate.is_some()
                && !applied_at_startup(link, startup)
            {
                skipped.push(not_applied(link, startup));
                continue;
            }
            let degraded = match (link.probe)() {
                Probe::Available => false,
                Probe::Degraded(why) => {
                    note.get_or_insert(why);
                    true
                }
                Probe::Unavailable(why) => {
                    skipped.push(Skipped {
                        link: link.id.to_owned(),
                        why,
                    });
                    continue;
                }
            };
            if matches!(mode, Mode::Apply)
                && let Some(activate) = &link.activate
                && let Err(error) = activate()
            {
                skipped.push(Skipped {
                    link: link.id.to_owned(),
                    why: format!("{APPLY_FAILED}{error}"),
                });
                continue;
            }
            if link.stacks {
                stacked.push(link.mechanism.to_owned());
            } else {
                active = Some(index);
            }
            strongest.get_or_insert((index, degraded));
        }

        let status = match strongest {
            None => ChainStatus::Off,
            Some((0, false)) => ChainStatus::Full,
            Some((index, _)) if index <= self.minimum => ChainStatus::Standard,
            Some(_) => ChainStatus::Reduced,
        };
        ChainReport {
            id: self.id.to_owned(),
            name: self.name.to_owned(),
            required: self.required,
            status,
            active: active.map(|index| self.links[index].mechanism.to_owned()),
            stacked,
            fallback,
            skipped,
            note,
            fix: (status < ChainStatus::Standard)
                .then(|| self.fix.clone())
                .flatten(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub chains: Vec<ChainReport>,
}

impl Report {
    #[must_use]
    pub fn evaluate(chains: &[Chain]) -> Self {
        Self {
            chains: chains.iter().map(Chain::evaluate).collect(),
        }
    }

    /// The chains probed again without activation, keeping what `startup` could not apply.
    #[must_use]
    pub fn reevaluate(chains: &[Chain], startup: &Self) -> Self {
        Self {
            chains: chains
                .iter()
                .map(|chain| {
                    let at_startup = startup.chains.iter().find(|report| report.id == chain.id);
                    chain.reevaluate(at_startup)
                })
                .collect(),
        }
    }

    /// `Refuse` chains with no working link: these stop startup unless skipped or accepted.
    #[must_use]
    pub fn refusals(&self) -> Vec<&ChainReport> {
        self.chains
            .iter()
            .filter(|chain| chain.required == Required::Refuse && chain.status == ChainStatus::Off)
            .collect()
    }

    /// Chains below their minimum that do not refuse.
    #[must_use]
    pub fn warnings(&self) -> Vec<&ChainReport> {
        self.chains
            .iter()
            .filter(|chain| {
                chain.required != Required::Status
                    && chain.status < ChainStatus::Standard
                    && !(chain.required == Required::Refuse && chain.status == ChainStatus::Off)
            })
            .collect()
    }

    /// Stable id of the refusal set, so `security accept` covers exactly what the user saw.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut ids: Vec<&str> = self
            .refusals()
            .iter()
            .map(|chain| chain.id.as_str())
            .collect();
        ids.sort_unstable();
        let digest = Sha256::digest(ids.join("\n").as_bytes());
        digest[..8].iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
    }

    /// One line per chain: name, status, active mechanism (plus stacked ones), note, fix.
    #[must_use]
    pub fn table(&self) -> String {
        let width = self
            .chains
            .iter()
            .map(|chain| chain.name.len())
            .max()
            .unwrap_or(0);
        let mut out = String::new();
        for chain in &self.chains {
            let mechanisms: Vec<&str> = chain
                .active
                .iter()
                .chain(&chain.stacked)
                .map(String::as_str)
                .collect();
            let using = if mechanisms.is_empty() {
                "none".to_owned()
            } else {
                mechanisms.join(" + ")
            };
            let _ = write!(
                out,
                "{:width$}  {:8}  {using}",
                chain.name,
                chain.status.label()
            );
            if let Some(note) = &chain.note {
                let _ = write!(out, " ({note})");
            }
            if let Some(fix) = &chain.fix {
                let _ = write!(out, " — {fix}");
            }
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    fn up(id: &'static str) -> Link {
        Link::new(id, id, || Probe::Available)
    }

    fn down(id: &'static str) -> Link {
        Link::new(id, id, || Probe::Unavailable("missing".to_owned()))
    }

    fn chain(required: Required, minimum: usize, links: Vec<Link>) -> Chain {
        Chain {
            id: "c",
            name: "Chain",
            required,
            minimum,
            links,
            fix: Some("install it".to_owned()),
        }
    }

    #[test]
    fn the_strongest_available_link_wins_and_the_next_is_the_fallback() {
        let report = chain(
            Required::Refuse,
            1,
            vec![down("bpf"), up("pidfd"), up("peercred")],
        )
        .evaluate();
        assert_eq!(report.active.as_deref(), Some("pidfd"));
        assert_eq!(report.fallback.as_deref(), Some("peercred"));
        assert_eq!(report.status, ChainStatus::Standard);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.fix, None);
    }

    #[test]
    fn top_link_is_full_but_degraded_top_link_is_standard() {
        assert_eq!(
            chain(Required::Warn, 0, vec![up("a")]).evaluate().status,
            ChainStatus::Full
        );
        let degraded = chain(
            Required::Warn,
            0,
            vec![Link::new("a", "a", || Probe::Degraded("ABI 7".to_owned()))],
        )
        .evaluate();
        assert_eq!(degraded.status, ChainStatus::Standard);
        assert_eq!(degraded.note.as_deref(), Some("ABI 7"));
    }

    #[test]
    fn every_available_stacking_link_activates() {
        let activations = Arc::new(AtomicUsize::new(0));
        let count = |id| {
            let activations = Arc::clone(&activations);
            up(id).stacking().on_activate(move || {
                activations.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        };
        let report = chain(
            Required::Refuse,
            0,
            vec![
                up("memfd"),
                up("keyctl"),
                count("core"),
                count("mdwe"),
                down("mseal").stacking(),
            ],
        )
        .evaluate();
        assert_eq!(report.active.as_deref(), Some("memfd"));
        assert_eq!(report.stacked, ["core", "mdwe"]);
        assert_eq!(activations.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_link_that_fails_to_apply_falls_through() {
        let report = chain(
            Required::Refuse,
            1,
            vec![
                up("a").on_activate(|| Err(std::io::Error::other("EPERM"))),
                up("b"),
            ],
        )
        .evaluate();
        assert_eq!(report.active.as_deref(), Some("b"));
        assert!(report.skipped[0].why.contains("EPERM"));
    }

    #[test]
    fn reevaluating_never_activates_and_keeps_a_failed_link_failed() {
        let activations = Arc::new(AtomicUsize::new(0));
        let counted = |id| {
            let activations = Arc::clone(&activations);
            up(id).on_activate(move || {
                activations.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        };
        let build = || {
            chain(
                Required::Refuse,
                1,
                vec![
                    up("a").on_activate(|| Err(std::io::Error::other("EPERM"))),
                    counted("b"),
                ],
            )
        };
        let startup = build().evaluate();
        assert_eq!(activations.load(Ordering::SeqCst), 1);
        let again = build().reevaluate(Some(&startup));
        assert_eq!(
            activations.load(Ordering::SeqCst),
            1,
            "no second activation"
        );
        assert_eq!(again.active.as_deref(), Some("b"));
        assert!(again.skipped[0].why.contains("EPERM"));
    }

    #[test]
    fn reevaluating_does_not_claim_a_link_that_startup_never_applied() {
        let build = |top_up: bool| {
            chain(
                Required::Refuse,
                1,
                vec![
                    Link::new("a", "a", move || {
                        if top_up {
                            Probe::Available
                        } else {
                            Probe::Unavailable("gone".to_owned())
                        }
                    })
                    .on_activate(|| Ok(())),
                    up("b").on_activate(|| Ok(())),
                    up("c"),
                ],
            )
        };
        let startup = build(true).evaluate();
        assert_eq!(startup.active.as_deref(), Some("a"));
        let again = build(false).reevaluate(Some(&startup));
        assert_eq!(again.active.as_deref(), Some("c"), "b was never applied");
        assert_eq!(again.skipped.len(), 2);
        let alone = build(true).reevaluate(None);
        assert_eq!(alone.active.as_deref(), Some("c"), "nothing was applied");
    }

    #[test]
    fn below_minimum_is_reduced_and_carries_the_fix() {
        let report = chain(Required::Warn, 0, vec![down("a"), up("b")]).evaluate();
        assert_eq!(report.status, ChainStatus::Reduced);
        assert_eq!(report.fix.as_deref(), Some("install it"));
        let report = Report {
            chains: vec![report],
        };
        assert_eq!(report.warnings().len(), 1);
        assert_eq!(report.refusals().len(), 0);
    }

    #[test]
    fn no_link_refuses_only_for_refuse_chains() {
        let report = Report::evaluate(&[
            chain(Required::Refuse, 0, vec![down("a")]),
            chain(Required::Warn, 0, vec![down("a")]),
            chain(Required::Status, 0, vec![down("a")]),
        ]);
        assert_eq!(report.refusals().len(), 1);
        assert_eq!(report.warnings().len(), 1);
    }

    #[test]
    fn fingerprint_ignores_order_and_changes_with_the_set() {
        let refused = |id: &str| ChainReport {
            id: id.to_owned(),
            name: id.to_owned(),
            required: Required::Refuse,
            status: ChainStatus::Off,
            active: None,
            stacked: Vec::new(),
            fallback: None,
            skipped: Vec::new(),
            note: None,
            fix: None,
        };
        let ab = Report {
            chains: vec![refused("a"), refused("b")],
        };
        let ba = Report {
            chains: vec![refused("b"), refused("a")],
        };
        let a = Report {
            chains: vec![refused("a")],
        };
        assert_eq!(ab.fingerprint(), ba.fingerprint());
        assert_ne!(ab.fingerprint(), a.fingerprint());
        assert_eq!(ab.fingerprint().len(), 16);
    }

    #[test]
    fn table_names_status_mechanisms_and_fix() {
        let report = Report::evaluate(&[chain(
            Required::Warn,
            0,
            vec![down("a"), up("b"), up("rlimit").stacking()],
        )]);
        assert_eq!(report.table(), "Chain  Reduced   b + rlimit — install it\n");
    }

    #[test]
    fn report_round_trips_through_json() {
        let report = Report::evaluate(&[chain(Required::Refuse, 0, vec![up("a")])]);
        let json = serde_json::to_string(&report).expect("serialize");
        assert_eq!(
            serde_json::from_str::<Report>(&json).expect("parse"),
            report
        );
    }
}
