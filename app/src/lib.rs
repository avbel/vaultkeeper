//! bw-lite desktop app: a Slint UI shell over `bwl_vault::VaultService`.
//!
//! The binary wires the real vault and OS hooks; `--mock` runs everything on [`mock::MockVault`]
//! with logging stubs for the hooks in [`hooks`].

pub mod app;
pub mod cli;
pub mod detail;
pub mod edit_form;
pub mod exec;
pub mod hooks;
pub mod keymap;
pub mod mock;
pub mod rows;
pub mod run;
pub mod server_url;
pub mod settings;
pub mod sidebar;
pub mod viewmodel;

pub mod ui {
    #![allow(clippy::all, clippy::pedantic, clippy::unwrap_used)]
    slint::include_modules!();
}

pub use app::{App, SshApprovalRequest, UiCommand};
pub use run::{UiOptions, run_ui};
