use std::{io::Write, sync::Arc, time::Duration};

use anyhow::Context;
use tokio::sync::{mpsc, oneshot};
use vaultkeeper::os::log_file::{BoundedLog, LOG_CAP, log_dir};
use vaultkeeper::{
    SshApprovalRequest, UiCommand,
    cli::{self, Mode},
    hooks::Hooks,
    mock::{MOCK_MASTER_PASSWORD, MockConfig, MockVault},
    run::{Backend, UiOptions, run_ui, select_backend},
};

fn main() -> anyhow::Result<()> {
    vk_platform::hardening::harden_process();
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(
        raw_args.first().map(String::as_str),
        Some("list" | "get_fields" | "get")
    ) {
        return vaultkeeper::cli_access::run(&raw_args);
    }
    if let Some(caller) = cli::browser_host_caller(&raw_args) {
        init_logging(Some("browser-host"));
        return vaultkeeper::browser_host::run(caller);
    }
    let args = cli::parse(raw_args)?;
    if args.help {
        writeln!(std::io::stdout(), "{}", cli::USAGE)?;
        return Ok(());
    }
    if args.version {
        writeln!(
            std::io::stdout(),
            "vaultkeeper {}",
            env!("CARGO_PKG_VERSION")
        )?;
        return Ok(());
    }
    let mode = args.mode();
    init_logging(match mode {
        Mode::Daemon(_) => Some("daemon"),
        Mode::Ui { .. } => Some("ui"),
        Mode::Mock => None,
    });
    match mode {
        Mode::Mock => run_mock(args),
        Mode::Ui { first_unlock } => vaultkeeper::ui_process::run(first_unlock, args.no_activate),
        Mode::Daemon(launch) => vaultkeeper::daemon::run(launch),
    }
}

/// stderr, plus the bounded log file for the daemon and the UI process (stderr goes nowhere when
/// launchd starts them).
fn init_logging(file_name: Option<&str>) {
    use tracing_subscriber::{EnvFilter, Layer as _, layer::SubscriberExt as _};

    let filter = || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let file = file_name.and_then(|name| {
        let dir = log_dir()?;
        match BoundedLog::open(&dir, name, LOG_CAP) {
            Ok(log) => Some(log),
            Err(error) => {
                // No subscriber yet, and this is the only way left to say it.
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("vaultkeeper: no log file in {}: {error}", dir.display());
                }
                None
            }
        }
    });
    let file_layer = file.map(|log| {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(log))
            .with_filter(filter())
    });
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(filter()),
        )
        .with(file_layer);
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        tracing::warn!("a logger was already installed");
    }
    // Release builds abort on panic; this puts the reason into the log file before they do.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(%info, "panic");
        default_hook(info);
    }));
}

/// `--mock`: the UI alone, in one process with its own tray, on the built-in mock vault.
fn run_mock(args: cli::Args) -> anyhow::Result<()> {
    // Two workers: vault work is short and I/O bound; more threads only cost memory.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("vaultkeeper-rt")
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
    // The mock pretends Touch ID is enrolled for its logged-in accounts.
    let hooks = Hooks::mock(&vault, &["acc-alice", "acc-bob"]);
    let mut settings = hooks.settings.load();
    if let Some(theme) = args.theme {
        settings.theme = theme;
    }
    if let Some((width, height)) = args.size {
        settings.manager_geometry = Some(vaultkeeper::settings::WindowGeometry {
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
        // Read before the event loop starts; launching brings this process to the front.
        (None, true) => Some(UiCommand::ShowQuickPanel {
            target: hooks.autotype.frontmost(),
        }),
        (None, false) => None,
    };
    let (commands, receiver) = mpsc::unbounded_channel();
    if args.demo_ssh {
        send_demo_ssh_request(commands.clone(), runtime.handle());
    }
    for (enabled, prompt) in [
        (
            args.demo_browser_fill,
            vk_ipc::BrowserPrompt::Fill {
                browser: "Firefox".into(),
                host: "github.com".into(),
                insecure: false,
                matches: vec![],
                touch_id: false,
                return_to: None,
            },
        ),
        (
            args.demo_browser_pair,
            vk_ipc::BrowserPrompt::Pair {
                browser: "Firefox".into(),
                fingerprint: "A1B2-C3D4-E5F6-0718".into(),
            },
        ),
        (
            args.demo_browser_save,
            vk_ipc::BrowserPrompt::Save {
                browser: "Firefox".into(),
                host: "github.com".into(),
                username: "octocat".into(),
                update_of: None,
                choices: vec![],
                return_to: None,
            },
        ),
    ] {
        if enabled {
            send_demo_browser_prompt(commands.clone(), runtime.handle(), prompt);
        }
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

fn send_demo_browser_prompt(
    commands: mpsc::UnboundedSender<UiCommand>,
    runtime: &tokio::runtime::Handle,
    prompt: vk_ipc::BrowserPrompt,
) {
    runtime.spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let (reply, answer) = oneshot::channel();
        if commands
            .send(UiCommand::ShowBrowserPrompt(
                vaultkeeper::app::BrowserPromptRequest { prompt, reply },
            ))
            .is_ok()
        {
            let result = answer.await;
            tracing::info!(?result, "demo browser prompt answered");
        }
    });
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
            return_to: None,
            reply,
        };
        if commands.send(UiCommand::ShowSshApproval(request)).is_err() {
            return;
        }
        let decision = answer.await.unwrap_or(vk_ipc::SshDecision::DENY);
        tracing::info!(?decision, "demo SSH request answered");
    });
}
