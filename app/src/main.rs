use std::{sync::Arc, time::Duration};

use anyhow::Context;
use bw_lite::{
    SshApprovalRequest, UiCommand,
    cli::{self, Mode},
    hooks::Hooks,
    mock::{MOCK_MASTER_PASSWORD, MockConfig, MockVault, mock_user_key},
    run::{Backend, UiOptions, run_ui, select_backend},
};
use tokio::sync::{mpsc, oneshot};

fn main() -> anyhow::Result<()> {
    bwl_platform::hardening::harden_process();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = cli::parse(std::env::args().skip(1))?;
    if args.help {
        tracing::info!("{}", cli::USAGE);
        return Ok(());
    }
    match args.mode() {
        Mode::Mock => run_mock(args),
        Mode::Ui { first_unlock } => bw_lite::ui_process::run(first_unlock),
        Mode::Daemon(launch) => bw_lite::daemon::run(launch),
    }
}

/// `--mock`: the UI alone, in one process with its own tray, on the built-in mock vault.
fn run_mock(args: cli::Args) -> anyhow::Result<()> {
    // Two workers: vault work is short and I/O bound; more threads only cost memory.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("bw-lite-rt")
        .enable_all()
        .build()
        .context("start the async runtime")?;
    let config = MockConfig {
        offline: args.offline,
        unlocked: args.unlocked,
        ..MockConfig::default()
    };
    tracing::info!(password = MOCK_MASTER_PASSWORD, "mock vault");
    let vault = Arc::new(MockVault::new(&config));
    let hooks = Hooks::logging();
    // The mock pretends Touch ID is enrolled for its logged-in accounts.
    for account in ["acc-alice", "acc-bob"] {
        hooks
            .biometrics
            .enroll(account, &mock_user_key(account))
            .context("pre-enrol mock Touch ID")?;
    }
    let mut settings = hooks.settings.load();
    if let Some(theme) = args.theme {
        settings.theme = theme;
    }
    if let Some((width, height)) = args.size {
        settings.manager_geometry = Some(bw_lite::settings::WindowGeometry {
            x: 120,
            y: 120,
            width,
            height,
            sidebar_collapsed: false,
        });
    }
    hooks
        .settings
        .save(&settings)
        .context("apply command-line settings")?;
    let initial = match (args.select, args.quick) {
        (Some(query), _) => Some(UiCommand::ShowItem { query }),
        (None, true) => Some(UiCommand::ShowQuickPanel),
        (None, false) => None,
    };
    let (commands, receiver) = mpsc::unbounded_channel();
    if args.demo_ssh {
        send_demo_ssh_request(commands.clone(), runtime.handle());
    }
    select_backend(Backend::Standalone)?;
    run_ui(
        vault,
        hooks,
        runtime.handle().clone(),
        Some(receiver),
        UiOptions {
            host_tray: true,
            tray_only: args.tray || initial.is_some(),
            initial,
            ui_process: false,
            first_unlock: true,
        },
        |_| tracing::info!("last window closed; the mock keeps running in the tray"),
    )?;
    drop(commands);
    runtime.shutdown_timeout(Duration::from_secs(1));
    Ok(())
}

/// Simulates the daemon forwarding an SSH sign request a few seconds after start.
fn send_demo_ssh_request(
    commands: mpsc::UnboundedSender<UiCommand>,
    runtime: &tokio::runtime::Handle,
) {
    runtime.spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let (reply, answer) = oneshot::channel();
        let request = SshApprovalRequest {
            process: "git".to_owned(),
            pid: Some(48_213),
            key_name: "github-signing".to_owned(),
            fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8".to_owned(),
            purpose: Some("git commit signing".to_owned()),
            reply,
        };
        if commands.send(UiCommand::ShowSshApproval(request)).is_err() {
            return;
        }
        let decision = answer.await.unwrap_or(bwl_ipc::SshDecision::DENY);
        tracing::info!(?decision, "demo SSH request answered");
    });
}
