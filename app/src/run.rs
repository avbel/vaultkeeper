//! UI process entry point: the daemon (or `--mock`) hands over a `VaultService`, the hooks and a
//! command channel, and this runs the Slint event loop until quit.

use std::{
    rc::{Rc, Weak},
    sync::Arc,
};

use anyhow::Context;
use tokio::{runtime::Handle, sync::mpsc};
use vk_vault::VaultService;

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
    /// The `--ui` process: the daemon owns start-up behaviour (hotkey, unlock on start, syncs),
    /// so this process only shows what it is asked to.
    pub ui_process: bool,
    /// No unlock happened since the app started, for "Require master password on app start".
    pub first_unlock: bool,
}

/// How the process presents itself on macOS.
pub enum Backend {
    /// `--mock`: an ordinary app with a Dock icon.
    Standalone,
    /// No Dock icon and never takes focus at launch.
    Daemon,
    /// No Dock icon until the Manager opens; activates when launched; `on_input` runs on every
    /// key press, click and scroll in its windows.
    Ui {
        on_input: Box<dyn FnMut()>,
        activate_at_launch: bool,
    },
}

/// Software renderer only (see the step 0 RAM numbers); on macOS the title bar is transparent with
/// full-size content, so the Manager header draws under the traffic lights.
pub fn select_backend(backend: Backend) -> anyhow::Result<()> {
    let selector = slint::BackendSelector::new()
        .backend_name("winit".to_owned())
        .renderer_name("software".to_owned());
    #[cfg(target_os = "macos")]
    let selector = macos_backend(selector, backend);
    #[cfg(not(target_os = "macos"))]
    drop(backend);
    selector
        .select()
        .context("select the winit software backend")
}

#[cfg(target_os = "macos")]
fn macos_backend(selector: slint::BackendSelector, backend: Backend) -> slint::BackendSelector {
    use slint::winit_030::{
        SlintEvent,
        winit::{
            event_loop::EventLoop,
            platform::macos::{
                ActivationPolicy, EventLoopBuilderExtMacOS, WindowAttributesExtMacOS,
            },
        },
    };
    let selector = selector.with_winit_window_attributes_hook(|attributes| {
        attributes
            .with_titlebar_transparent(true)
            .with_fullsize_content_view(true)
            .with_title_hidden(true)
    });
    let (activate_at_launch, on_input) = match backend {
        Backend::Standalone => return selector,
        Backend::Daemon => (false, None),
        Backend::Ui {
            on_input,
            activate_at_launch,
        } => (activate_at_launch, Some(on_input)),
    };
    // winit applies the policy in applicationDidFinishLaunching; setting it later through AppKit
    // would be overridden there, and the Dock icon would flash.
    let mut builder = EventLoop::<SlintEvent>::with_user_event();
    builder
        .with_activation_policy(ActivationPolicy::Accessory)
        .with_activate_ignoring_other_apps(activate_at_launch);
    let selector = selector.with_winit_event_loop_builder(builder);
    match on_input {
        Some(on_input) => selector.with_winit_custom_application_handler(InputObserver(on_input)),
        None => selector,
    }
}

#[cfg(target_os = "macos")]
struct InputObserver(Box<dyn FnMut()>);

#[cfg(target_os = "macos")]
impl slint::winit_030::CustomApplicationHandler for InputObserver {
    fn window_event(
        &mut self,
        _event_loop: &slint::winit_030::winit::event_loop::ActiveEventLoop,
        _window_id: slint::winit_030::winit::window::WindowId,
        _winit_window: Option<&slint::winit_030::winit::window::Window>,
        _slint_window: Option<&slint::Window>,
        event: &slint::winit_030::winit::event::WindowEvent,
    ) -> slint::winit_030::EventResult {
        use slint::winit_030::winit::event::{ElementState, WindowEvent};
        if matches!(
            event,
            WindowEvent::KeyboardInput { .. }
                | WindowEvent::MouseWheel { .. }
                | WindowEvent::MouseInput {
                    state: ElementState::Pressed,
                    ..
                }
        ) {
            (self.0)();
        }
        slint::winit_030::EventResult::Propagate
    }
}

/// Runs the UI until `slint::quit_event_loop`; the backend must be selected first. Fires
/// `on_last_window_closed` each time the last window closes (and once at start in the UI
/// process, which starts without a window), for the UI process's linger timer.
pub fn run_ui<S: VaultService>(
    vault: Arc<S>,
    hooks: Hooks,
    runtime: Handle,
    commands: Option<mpsc::UnboundedReceiver<UiCommand>>,
    options: UiOptions,
    on_last_window_closed: impl Fn(&Weak<App<S>>) + 'static,
) -> anyhow::Result<()> {
    let app = App::new(vault, Exec::event_loop(runtime), hooks);
    let weak = Rc::downgrade(&app);
    let on_closed = Rc::new(on_last_window_closed);
    let closed = Rc::clone(&on_closed);
    let closed_app = Weak::clone(&weak);
    app.set_on_last_window_closed(move || closed(&closed_app));
    app.set_first_unlock(options.first_unlock);
    if options.host_tray {
        app.install_tray();
    }
    watch_vault(&app)?;
    if let Some(commands) = commands {
        forward_commands(&app, commands)?;
    }
    if options.ui_process {
        on_closed(&weak);
    } else {
        app.start(options.tray_only);
    }
    if let Some(command) = options.initial {
        app.handle(command);
    }
    app.show_pending_notices();
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
                Some(app) => {
                    app.handle(command);
                    app.show_pending_notices();
                }
                None => break,
            }
        }
    })
    .context("forward daemon commands")?;
    Ok(())
}
