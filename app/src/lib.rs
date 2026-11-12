//! vaultkeeper desktop app: a Slint UI shell over `vk_vault::VaultService`.
//!
//! One binary, two processes: [`daemon`] (`--daemon`/`--tray`) owns the vault, SSH agent, tray
//! and hotkey; [`ui_process`] (`--ui`) shows the windows over IPC and exits when idle. `--mock`
//! runs the UI alone on [`mock::MockVault`] with the logging stubs in [`hooks`].

pub mod app;
pub mod assign;
pub mod autotype;
pub mod browser_host;
pub mod browser_status;
pub mod cli;
pub mod cli_access;
pub mod daemon;
pub mod detail;
pub mod edit_form;
pub mod exec;
pub mod hooks;
pub mod hotkey_recorder;
pub mod keymap;
pub mod last_login;
pub mod mock;
pub mod os;
pub mod rows;
pub mod run;
pub mod server_url;
pub mod settings;
pub mod sidebar;
pub mod site_icon;
pub mod ui_process;
pub mod viewmodel;

pub mod ui {
    #![allow(clippy::all, clippy::pedantic, clippy::unwrap_used)]
    slint::include_modules!();
}

pub use app::{App, SshApprovalRequest, UiCommand};
pub use run::{UiOptions, run_ui};
