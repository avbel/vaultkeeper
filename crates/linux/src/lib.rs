//! Linux kernel and desktop facts for the security chains (linux-plan.md 1b). The parsers are
//! portable and tested everywhere; the probes that touch the kernel exist only on Linux.
//!
//! A probe answers `Ok(detail)` when the mechanism works here and `Err(reason)` when it does not;
//! vk-platform turns that into a chain link, so this crate stays free of the chain types.

pub mod consts;
pub mod distro;
pub mod parse;
#[cfg(target_os = "linux")]
pub mod probes;

pub type ProbeResult = Result<String, String>;
