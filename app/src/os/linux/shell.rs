//! Shell hooks on Linux. Wayland gives clients no Dock and no say over window placement, so both
//! leave the decision to the compositor (linux-support.md §6).

use crate::hooks::{DockIcon, WindowPlacement};

pub struct LinuxDock;

impl DockIcon for LinuxDock {
    fn set_visible(&self, _visible: bool) {}
}

pub struct CompositorPlacement;

impl WindowPlacement for CompositorPlacement {
    fn quick_panel_origin(&self, _width: f32, _height: f32) -> Option<slint::LogicalPosition> {
        None
    }
}
