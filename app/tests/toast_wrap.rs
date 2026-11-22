//! A long message in a toast wraps and grows the toast; it is never cut to one elided line.

mod common;

use common::{Setup, find, harness, pump};
use slint::ComponentHandle;
use vaultkeeper::UiCommand;

const LONGEST: &str = "Vaultkeeper's sandbox (VAULTKEEPER_LANDLOCK) can't read files outside its own folders: move the file to ~/.cache or restart without the sandbox";
const LAYOUT: &str =
    "Auto-type stopped: the active keyboard layout lacks some characters; switch it or copy";
const LOCKED: &str =
    "Auto-type stopped: a locked modifier such as Caps Lock would change the text; turn it off";
const SHORT: &str = "Copied";

fn toast_height(window: &impl ComponentHandle, text: &str) -> f32 {
    find(window, text).size().height
}

#[test]
fn a_long_quick_panel_toast_wraps_inside_the_panel() {
    let h = harness(Setup::default());
    h.app.handle(UiCommand::ToggleQuickPanel { target: None });
    h.app.show_pending_notices();
    let panel = h.app.quick_panel().expect("quick panel");

    panel.set_toast_text(SHORT.into());
    panel.set_toast_error(true);
    panel.set_toast_shown(true);
    pump();
    let one_line = toast_height(&panel, SHORT);

    let doubled = format!("{LAYOUT}. {LOCKED}");
    for text in [LONGEST, LAYOUT, LOCKED, doubled.as_str()] {
        panel.set_toast_text(text.into());
        pump();
        let toast = find(&panel, text);
        let size = toast.size();
        let x = toast.absolute_position().x;
        assert!(size.width <= 560.0 - 24.0 + 0.5, "{text}: {}", size.width);
        assert!(x >= 0.0 && x + size.width <= 560.0 + 0.5, "{text}: x {x}");
        // The testing backend's font is narrower than a real one, so only a toast that fills the
        // panel is required to have wrapped; the doubled text always does.
        if size.width >= 560.0 - 24.0 - 0.5 {
            assert!(size.height > one_line + 8.0, "{text}: {}", size.height);
        }
    }
    panel.set_toast_text(doubled.as_str().into());
    pump();
    assert!(toast_height(&panel, &doubled) > one_line + 8.0);
}
