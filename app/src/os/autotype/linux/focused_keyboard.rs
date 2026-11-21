//! The keyboard as the compositor describes it to the focused Quick Panel: the keymap and the
//! active layout. Wayland sends the layout (`wl_keyboard.modifiers`) only to the client that has
//! the keyboard focus, and Mutter and KWin send it to a `wl_keyboard` that such a client binds
//! later, so this must run on the window's own connection and before the panel closes. A second
//! connection would get the keymap but never the layout.
//!
//! The objects live on an event queue of their own on winit's `wl_display`, the way softbuffer
//! shares that display for its buffers.

use std::{
    cell::RefCell, ffi::c_void, fs::File, mem::ManuallyDrop, os::unix::fs::FileExt as _,
    ptr::NonNull,
};

use slint::winit_030::{
    WinitWindowAccessor as _,
    winit::raw_window_handle::{HasDisplayHandle as _, RawDisplayHandle},
};
use wayland_client::{
    Connection, Dispatch, EventQueue, QueueHandle, WEnum,
    backend::Backend,
    globals::{GlobalList, GlobalListContents, registry_queue_init},
    protocol::{
        wl_keyboard::{self, KeymapFormat, WlKeyboard},
        wl_registry::WlRegistry,
        wl_seat::{self, Capability, WlSeat},
    },
};

use super::typeable::Seen;

/// A compiled desktop keymap is some 40 to 70 kB of text; this only stops a nonsense size from
/// being allocated.
const MAX_KEYMAP_BYTES: usize = 4 << 20;
/// `wl_keyboard.release` exists from version 3 and the keymap is sealed from 7; newer versions
/// add nothing that is read here.
const SEAT_VERSIONS: std::ops::RangeInclusive<u32> = 3..=7;

#[derive(Default)]
struct State {
    has_keyboard: bool,
    keymap: Option<Result<Vec<u8>, String>>,
    layout: Option<u32>,
    locked_modifiers: u32,
}

/// The interface of the chain's second link (`virtual_keyboard`).
const VIRTUAL_KEYBOARD: &str = "zwp_virtual_keyboard_manager_v1";

pub(super) struct Reading {
    pub keyboard: Result<Seen, String>,
    /// The compositor offers no virtual keyboard, so only the RemoteDesktop portal can type.
    pub portal_only: bool,
}

struct Link {
    display: NonNull<c_void>,
    globals: GlobalList,
    queue: EventQueue<State>,
    seat: WlSeat,
    state: State,
}

thread_local! {
    // Never dropped: dropping it destroys the event queue on a `wl_display` that winit owns and
    // may already have closed when thread-locals are torn down at exit.
    static LINK: RefCell<Option<ManuallyDrop<Link>>> = const { RefCell::new(None) };
}

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

impl Dispatch<WlSeat, ()> for State {
    fn event(
        state: &mut Self,
        _: &WlSeat,
        event: wl_seat::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_seat::Event::Capabilities {
            capabilities: WEnum::Value(capabilities),
        } = event
        {
            state.has_keyboard = capabilities.contains(Capability::Keyboard);
        }
    }
}

impl Dispatch<WlKeyboard, ()> for State {
    fn event(
        state: &mut Self,
        _: &WlKeyboard,
        event: wl_keyboard::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_keyboard::Event::Keymap { format, fd, size } => {
                state.keymap = Some(match format {
                    WEnum::Value(KeymapFormat::XkbV1) => keymap_text(&File::from(fd), size),
                    _ => Err("the compositor sent no XKB keymap".to_owned()),
                });
            }
            wl_keyboard::Event::Modifiers {
                mods_locked, group, ..
            } => {
                state.layout = Some(group);
                state.locked_modifiers = mods_locked;
            }
            _ => {}
        }
    }
}

fn keymap_text(file: &File, size: u32) -> Result<Vec<u8>, String> {
    let size = usize::try_from(size)
        .ok()
        .filter(|size| *size <= MAX_KEYMAP_BYTES)
        .ok_or("the keymap is too large")?;
    let mut text = vec![0; size];
    file.read_exact_at(&mut text, 0)
        .map_err(|error| format!("the keymap cannot be read: {error}"))?;
    // The size counts the terminating NUL of the C string.
    while text.last() == Some(&0) {
        text.pop();
    }
    Ok(text)
}

/// Reads the keyboard that `focused`, a window of ours with the keyboard focus, is typed into.
pub(super) fn read(focused: &slint::Window) -> Reading {
    LINK.with_borrow_mut(|slot| match linked(slot, focused) {
        Ok(link) => Reading {
            portal_only: !link.globals.contents().with_list(|globals| {
                globals
                    .iter()
                    .any(|global| global.interface == VIRTUAL_KEYBOARD)
            }),
            keyboard: ask(link),
        },
        Err(reason) => Reading {
            keyboard: Err(reason),
            portal_only: false,
        },
    })
}

fn linked<'a>(
    slot: &'a mut Option<ManuallyDrop<Link>>,
    focused: &slint::Window,
) -> Result<&'a mut Link, String> {
    let display = focused
        .with_winit_window(
            |window| match window.display_handle().map(|handle| handle.as_raw()) {
                Ok(RawDisplayHandle::Wayland(handle)) => Some(handle.display),
                _ => None,
            },
        )
        .flatten()
        .ok_or("the window is not a Wayland window")?;
    if slot.as_ref().is_none_or(|link| link.display != display) {
        *slot = Some(ManuallyDrop::new(connect(display)?));
    }
    slot.as_deref_mut()
        .ok_or_else(|| "no Wayland link".to_owned())
}

fn connect(display: NonNull<c_void>) -> Result<Link, String> {
    // SAFETY: `display` is the `wl_display` of the window's winit event loop, read from the live
    // window a moment ago. Slint keeps that loop, and with it the display, for the rest of the
    // process, and the backend made here is only used on this (the UI) thread while a window of
    // that loop is open.
    let backend = unsafe { Backend::from_foreign_display(display.as_ptr().cast()) };
    let connection = Connection::from_backend(backend);
    let (globals, queue) = registry_queue_init::<State>(&connection)
        .map_err(|error| format!("the Wayland registry failed: {error}"))?;
    let seat = globals
        .bind::<WlSeat, State, ()>(&queue.handle(), SEAT_VERSIONS, ())
        .map_err(|error| format!("the compositor offers no usable seat: {error}"))?;
    Ok(Link {
        display,
        globals,
        queue,
        seat,
        state: State::default(),
    })
}

fn ask(link: &mut Link) -> Result<Seen, String> {
    let Link {
        queue, seat, state, ..
    } = link;
    let broke = |error| format!("the compositor connection broke: {error}");
    // Brings the seat's capabilities up to date; asking a seat without a keyboard for one is a
    // protocol error that would end the whole connection, and with it the windows.
    queue.roundtrip(state).map_err(broke)?;
    if !state.has_keyboard {
        return Err("the seat has no keyboard".to_owned());
    }
    state.keymap = None;
    state.layout = None;
    state.locked_modifiers = 0;
    let keyboard = seat.get_keyboard(&queue.handle(), ());
    let answered = queue.roundtrip(state).map_err(broke);
    // Released at once: a bound keyboard would queue every key typed into our windows here.
    keyboard.release();
    queue.flush().map_err(|error| broke(error.into()))?;
    answered?;
    let keymap = state
        .keymap
        .take()
        .ok_or("the compositor sent no keymap")??;
    Ok(Seen {
        keymap,
        layout: state.layout,
        locked_modifiers: state.locked_modifiers,
    })
}
