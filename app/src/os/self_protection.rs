//! What the daemon did to its own process after the instance lock: non-dumpable (chain C3) and
//! the Landlock sandbox (chain C6). Recorded here because neither can be probed from outside the
//! process that applied it, so the rows exist only in the daemon's report (Settings), not in the
//! `security status` a separate CLI process prints.

use std::sync::{Mutex, PoisonError};

use vk_platform::{
    sandbox::Enforcement,
    security::{Chain, Link, Probe, Required},
};

/// The sandbox outcome of this start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sandbox {
    /// `VAULTKEEPER_LANDLOCK=1` was not set.
    NotRequested,
    Applied {
        enforcement: Enforcement,
        /// The kernel's Landlock ABI, when it could be read.
        abi: Option<u32>,
    },
    /// Requested, but no rule set was applied; carries why.
    Failed(String),
}

static NON_DUMPABLE: Mutex<bool> = Mutex::new(false);
static SANDBOX: Mutex<Option<Sandbox>> = Mutex::new(None);

pub fn note_non_dumpable() {
    *NON_DUMPABLE.lock().unwrap_or_else(PoisonError::into_inner) = true;
}

pub fn note_sandbox(sandbox: Sandbox) {
    *SANDBOX.lock().unwrap_or_else(PoisonError::into_inner) = Some(sandbox);
}

/// `None` in a process that never hardened itself as the daemon.
#[must_use]
pub fn sandbox() -> Option<Sandbox> {
    SANDBOX
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// `None` before the daemon dropped dumpable; afterwards the state as it reads now, so a tracer
/// that a debug build let through shows.
#[must_use]
pub fn memory_read() -> Option<Result<(), String>> {
    if !*NON_DUMPABLE.lock().unwrap_or_else(PoisonError::into_inner) {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some(read_back())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(Ok(()))
    }
}

#[cfg(target_os = "linux")]
fn read_back() -> Result<(), String> {
    if vk_linux::probes::dumpable()? {
        return Err("the process is dumpable".to_owned());
    }
    match vk_linux::probes::tracer_pid()? {
        0 => Ok(()),
        tracer => Err(format!("process {tracer} is tracing Vaultkeeper")),
    }
}

/// C3: other programs of this user cannot read the daemon's memory or attach to it.
#[must_use]
pub fn memory_chain(state: &Result<(), String>) -> Chain {
    let probe = match state {
        Ok(()) => Probe::Available,
        Err(why) => Probe::Unavailable(why.clone()),
    };
    Chain {
        id: "memory-read",
        name: "Memory read by other programs",
        required: Required::Status,
        minimum: 0,
        links: vec![Link::new(
            "non-dumpable",
            "non-dumpable, no tracer",
            move || probe.clone(),
        )],
        fix: None,
    }
}

const NO_SANDBOX: &str = "No sandbox";

/// The Landlock link's skip reasons. The catalog tells "not asked for" from "asked for, kernel
/// has none" from "asked for, failed" by these, so they live next to where they are produced.
pub const NOT_REQUESTED: &str = "not requested";
pub const NO_LANDLOCK: &str = "this kernel has no Landlock";

const PARTIAL_PREFIX: &str = "partly enforced: the kernel's Landlock ABI ";

/// The ABI number inside the note of a partly enforced sandbox.
#[must_use]
pub fn landlock_abi(note: &str) -> Option<u32> {
    let rest = note.strip_prefix(PARTIAL_PREFIX)?;
    rest.split_whitespace().next()?.parse().ok()
}

/// C6. Off by default is the documented state and reads Standard; a sandbox that was asked for
/// and is missing or partial must not look the same, so it reads Reduced with the reason.
#[must_use]
pub fn sandbox_chain(state: &Sandbox) -> Chain {
    let (landlock, without, minimum) = match state {
        Sandbox::NotRequested => (
            Probe::Unavailable(NOT_REQUESTED.to_owned()),
            Some("off unless Vaultkeeper starts with VAULTKEEPER_LANDLOCK=1".to_owned()),
            1,
        ),
        Sandbox::Applied {
            enforcement: Enforcement::Full,
            ..
        } => (Probe::Available, None, 0),
        Sandbox::Applied {
            enforcement: Enforcement::Partial,
            abi,
        } => (
            Probe::Degraded(format!(
                "{PARTIAL_PREFIX}{} lacks some of the rules",
                abi.map_or_else(|| "?".to_owned(), |abi| abi.to_string())
            )),
            None,
            0,
        ),
        Sandbox::Applied {
            enforcement: Enforcement::None,
            ..
        } => (
            Probe::Unavailable(NO_LANDLOCK.to_owned()),
            Some("requested but not enforced: this kernel has no Landlock".to_owned()),
            0,
        ),
        Sandbox::Failed(why) => (
            Probe::Unavailable(why.clone()),
            Some(format!("requested but not applied: {why}")),
            0,
        ),
    };
    let mut links = vec![Link::new("landlock", "Landlock", move || landlock.clone())];
    if let Some(why) = without {
        links.push(Link::new("no-sandbox", NO_SANDBOX, move || {
            Probe::Degraded(why.clone())
        }));
    }
    Chain {
        id: "sandbox",
        name: "Self-sandbox",
        required: Required::Status,
        minimum,
        links,
        fix: None,
    }
}

#[cfg(test)]
mod tests {
    use vk_platform::security::ChainStatus;

    use super::*;

    fn applied(enforcement: Enforcement) -> Sandbox {
        Sandbox::Applied {
            enforcement,
            abi: Some(7),
        }
    }

    #[test]
    fn a_full_sandbox_is_full_and_the_default_off_state_is_not_a_fault() {
        let full = sandbox_chain(&applied(Enforcement::Full)).evaluate();
        assert_eq!(full.status, ChainStatus::Full);
        assert_eq!(full.active.as_deref(), Some("Landlock"));
        assert_eq!(full.note, None);

        let off = sandbox_chain(&Sandbox::NotRequested).evaluate();
        assert_eq!(off.status, ChainStatus::Standard);
        assert_eq!(off.active.as_deref(), Some(NO_SANDBOX));
        assert!(
            off.note
                .as_deref()
                .is_some_and(|note| note.contains("VAULTKEEPER_LANDLOCK=1"))
        );
    }

    #[test]
    fn a_requested_sandbox_that_is_partial_or_missing_shows_with_its_reason() {
        let partial = sandbox_chain(&applied(Enforcement::Partial)).evaluate();
        assert_eq!(partial.status, ChainStatus::Standard);
        assert_eq!(partial.active.as_deref(), Some("Landlock"));
        assert!(
            partial
                .note
                .as_deref()
                .is_some_and(|note| note.contains("ABI 7"))
        );

        for (state, reason) in [
            (applied(Enforcement::None), "no Landlock"),
            (
                Sandbox::Failed("the install path is unknown".to_owned()),
                "the install path is unknown",
            ),
        ] {
            let report = sandbox_chain(&state).evaluate();
            assert_eq!(report.status, ChainStatus::Reduced, "{state:?}");
            assert_eq!(report.active.as_deref(), Some(NO_SANDBOX));
            assert!(
                report
                    .note
                    .as_deref()
                    .is_some_and(|note| note.starts_with("requested") && note.contains(reason)),
                "{:?}",
                report.note
            );
        }
    }

    #[test]
    fn the_abi_is_read_back_from_the_partial_note() {
        let partial = sandbox_chain(&applied(Enforcement::Partial)).evaluate();
        assert_eq!(landlock_abi(partial.note.as_deref().unwrap_or("")), Some(7));
        assert_eq!(landlock_abi("something else"), None);
    }

    #[test]
    fn the_memory_row_follows_what_the_process_reads_back() {
        let hardened = memory_chain(&Ok(())).evaluate();
        assert_eq!(hardened.status, ChainStatus::Full);
        let traced = memory_chain(&Err("process 7 is tracing Vaultkeeper".to_owned())).evaluate();
        assert_eq!(traced.status, ChainStatus::Off);
        assert_eq!(traced.skipped[0].why, "process 7 is tracing Vaultkeeper");
    }
}
