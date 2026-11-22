//! The wlroots route: `zwp_virtual_keyboard_v1` through `wayland-client`. The protocol is only
//! served by wlroots-based compositors (Sway, Hyprland); GNOME and KDE use the RemoteDesktop
//! portal instead. The virtual keyboard gets a keymap generated for the text ([`keysym::chunks`]),
//! so no character depends on the user's layout.

use std::{
    fs::File,
    io::Write as _,
    os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{RecvTimeoutError, channel},
    },
    time::{Duration, Instant},
};

use wayland_client::{
    Connection, Dispatch, EventQueue, QueueHandle, delegate_noop,
    globals::{GlobalList, GlobalListContents, registry_queue_init},
    protocol::{wl_registry::WlRegistry, wl_seat::WlSeat},
};
use wayland_protocols_misc::zwp_virtual_keyboard_v1::client::{
    zwp_virtual_keyboard_manager_v1::ZwpVirtualKeyboardManagerV1,
    zwp_virtual_keyboard_v1::ZwpVirtualKeyboardV1,
};

use super::{Failure, PACE};
use crate::os::autotype::keysym::{self, Chunk};

/// A compositor that takes longer than this to answer a round trip is stuck.
const ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(5);
/// `wl_keyboard.keymap_format.xkb_v1`.
const XKB_V1: u32 = 1;
const KEY_RELEASED: u32 = 0;
const KEY_PRESSED: u32 = 1;
const NO_COMPOSITOR_SUPPORT: &str = "the compositor has no virtual keyboard (zwp_virtual_keyboard_v1 is served by wlroots-based compositors such as Sway and Hyprland)";

struct State;

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &WlRegistry,
        _: <WlRegistry as wayland_client::Proxy>::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(State: ignore WlSeat);
delegate_noop!(State: ZwpVirtualKeyboardManagerV1);
delegate_noop!(State: ZwpVirtualKeyboardV1);

struct Keyboard {
    connection: Connection,
    queue: EventQueue<State>,
    device: ZwpVirtualKeyboardV1,
}

/// Types `keysyms` through a virtual keyboard; blocks, so it runs on the typing thread.
pub(super) fn type_keysyms(keysyms: &[u32], cancel: &AtomicBool) -> Result<(), Failure> {
    let mut keyboard = connect()?;
    let started = Instant::now();
    for chunk in keysym::chunks(keysyms) {
        keyboard.load_keymap(&chunk)?;
        for key in chunk.keys.iter() {
            if cancel.load(Ordering::Relaxed) {
                return Err(Failure::Cancelled);
            }
            keyboard.tap(*key, started)?;
            std::thread::sleep(PACE);
        }
    }
    keyboard.finish()?;
    tracing::info!("auto-type: typed through the compositor's virtual keyboard");
    Ok(())
}

fn connect() -> Result<Keyboard, Failure> {
    let connection = Connection::connect_to_env().map_err(|error| {
        Failure::Unavailable(format!("no Wayland connection to type through ({error})"))
    })?;
    let (globals, mut queue) = bounded(&connection, || {
        registry_queue_init::<State>(&connection)
            .map_err(|error| Failure::Unavailable(format!("the Wayland registry failed ({error})")))
    })?;
    let qh = queue.handle();
    let manager = bind::<ZwpVirtualKeyboardManagerV1>(&globals, &qh, 1..=1)
        .ok_or_else(|| Failure::Unavailable(NO_COMPOSITOR_SUPPORT.to_owned()))?;
    let seat = bind::<WlSeat>(&globals, &qh, 1..=1)
        .ok_or_else(|| Failure::Unavailable("the compositor offers no seat".to_owned()))?;
    let device = manager.create_virtual_keyboard(&seat, &qh, ());
    bounded(&connection, || {
        queue.roundtrip(&mut State).map_err(|error| {
            Failure::Stopped(format!(
                "the compositor refused the virtual keyboard ({error})"
            ))
        })
    })?;
    Ok(Keyboard {
        connection,
        queue,
        device,
    })
}

/// wayland-client's round trip polls the socket with no limit, so a watchdog shuts the socket down
/// when `work` outlasts [`ROUNDTRIP_TIMEOUT`]; that wakes the wait with an error and the typing
/// job ends instead of leaving its thread stuck behind a frozen compositor.
fn bounded<T>(
    connection: &Connection,
    work: impl FnOnce() -> Result<T, Failure>,
) -> Result<T, Failure> {
    let fd = connection.backend().poll_fd().as_raw_fd();
    let (finished, waiting) = channel::<()>();
    let expired = AtomicBool::new(false);
    let expired_ref = &expired;
    let outcome = std::thread::scope(|scope| {
        scope.spawn(move || {
            if waiting.recv_timeout(ROUNDTRIP_TIMEOUT) == Err(RecvTimeoutError::Timeout) {
                expired_ref.store(true, Ordering::Release);
                // SAFETY: the descriptor belongs to `connection`, which outlives this scope;
                // shutdown only changes the socket's state and does not close it.
                unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
            }
        });
        let outcome = work();
        drop(finished);
        outcome
    });
    if expired.load(Ordering::Acquire) {
        return Err(Failure::Stopped(
            "the compositor did not answer in time".to_owned(),
        ));
    }
    outcome
}

fn bind<I>(
    globals: &GlobalList,
    qh: &QueueHandle<State>,
    versions: std::ops::RangeInclusive<u32>,
) -> Option<I>
where
    I: wayland_client::Proxy + 'static,
    State: Dispatch<I, ()>,
{
    globals.bind(qh, versions, ()).ok()
}

impl Keyboard {
    fn load_keymap(&mut self, chunk: &Chunk) -> Result<(), Failure> {
        let file = keymap_file(&chunk.keymap)?;
        // The protocol counts the terminating NUL; wlroots hands the mapping to
        // `xkb_keymap_new_from_string`.
        let size = u32::try_from(chunk.keymap.len() + 1)
            .map_err(|_| Failure::Stopped("the keymap is too large".to_owned()))?;
        self.device.keymap(XKB_V1, file.as_fd(), size);
        self.device.modifiers(0, 0, 0, 0);
        self.roundtrip()
    }

    fn tap(&self, key: u32, started: Instant) -> Result<(), Failure> {
        for state in [KEY_PRESSED, KEY_RELEASED] {
            let millis = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
            self.device.key(millis, key, state);
        }
        self.connection
            .flush()
            .map_err(|error| Failure::Stopped(format!("the compositor connection broke ({error})")))
    }

    fn finish(mut self) -> Result<(), Failure> {
        self.device.destroy();
        self.roundtrip()
    }

    fn roundtrip(&mut self) -> Result<(), Failure> {
        let Self {
            connection, queue, ..
        } = self;
        bounded(connection, || {
            queue.roundtrip(&mut State).map(drop).map_err(|error| {
                Failure::Stopped(format!("the compositor connection broke ({error})"))
            })
        })
    }
}

/// A memfd holding the keymap text and its NUL; the compositor maps it, so it stays alive until
/// the next round trip has finished.
fn keymap_file(keymap: &str) -> Result<File, Failure> {
    let failed = |what: &str, error: std::io::Error| {
        Failure::Stopped(format!("cannot share the keymap ({what}: {error})"))
    };
    // SAFETY: the name is a valid NUL-terminated string and the flags are valid; the call only
    // creates a descriptor.
    let fd = unsafe { libc::memfd_create(c"vaultkeeper-keymap".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(failed("memfd_create", std::io::Error::last_os_error()));
    }
    // SAFETY: `fd` is a fresh descriptor that nothing else owns.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(keymap.as_bytes())
        .and_then(|()| file.write_all(&[0]))
        .map_err(|error| failed("write", error))?;
    Ok(file)
}
