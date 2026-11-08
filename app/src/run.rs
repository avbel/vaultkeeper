//! UI process entry point: the daemon (or `--mock`) hands over a `VaultService`, the hooks and a
//! command channel, and this runs the Slint event loop until quit.

use std::{rc::Rc, sync::Arc};

use anyhow::Context;
use bwl_vault::VaultService;
use tokio::{runtime::Handle, sync::mpsc};

use crate::{
    app::{App, UiCommand},
    exec::Exec,
    hooks::Hooks,
};

pub struct UiOptions {
    /// Host the tray icon in this process (`--mock`); the daemon hosts it otherwise.
    pub host_tray: bool,
    /// Start without opening a window.
    pub tray_only: bool,
    pub initial: Option<UiCommand>,
}

/// Software renderer only (see the step 0 RAM numbers); on macOS the title bar is transparent with
/// full-size content, so the Manager header draws under the traffic lights.
pub fn select_backend() -> anyhow::Result<()> {
    let selector = slint::BackendSelector::new()
        .backend_name("winit".to_owned())
        .renderer_name("software".to_owned());
    #[cfg(target_os = "macos")]
    let selector = selector.with_winit_window_attributes_hook(|attributes| {
        use slint::winit_030::winit::platform::macos::WindowAttributesExtMacOS;
        attributes
            .with_titlebar_transparent(true)
            .with_fullsize_content_view(true)
            .with_title_hidden(true)
    });
    selector
        .select()
        .context("select the winit software backend")
}

/// Runs the UI until `slint::quit_event_loop`. `on_last_window_closed` fires each time the last
/// window closes, for the UI process's linger timer.
pub fn run_ui<S: VaultService>(
    vault: Arc<S>,
    hooks: Hooks,
    runtime: Handle,
    commands: Option<mpsc::UnboundedReceiver<UiCommand>>,
    options: UiOptions,
    on_last_window_closed: impl Fn() + 'static,
) -> anyhow::Result<()> {
    select_backend()?;
    let app = App::new(vault, Exec::event_loop(runtime), hooks);
    app.set_on_last_window_closed(on_last_window_closed);
    if options.host_tray {
        app.install_tray();
    }
    watch_vault(&app)?;
    if let Some(commands) = commands {
        forward_commands(&app, commands)?;
    }
    app.start(options.tray_only);
    if let Some(command) = options.initial {
        app.handle(command);
    }
    slint::run_event_loop_until_quit().context("run the event loop")?;
    Ok(())
}

/// Re-renders open views whenever the vault reports a change (sync, lock, writes).
fn watch_vault<S: VaultService>(app: &Rc<App<S>>) -> anyhow::Result<()> {
    let mut changes = app.vault().changes();
    let weak = Rc::downgrade(app);
    slint::spawn_local(async move {
        while changes.changed().await.is_ok() {
            match weak.upgrade() {
                Some(app) => app.on_vault_changed(),
                None => break,
            }
        }
    })
    .context("watch vault changes")?;
    Ok(())
}

fn forward_commands<S: VaultService>(
    app: &Rc<App<S>>,
    mut commands: mpsc::UnboundedReceiver<UiCommand>,
) -> anyhow::Result<()> {
    let weak = Rc::downgrade(app);
    slint::spawn_local(async move {
        while let Some(command) = commands.recv().await {
            match weak.upgrade() {
                Some(app) => app.handle(command),
                None => break,
            }
        }
    })
    .context("forward daemon commands")?;
    Ok(())
}
