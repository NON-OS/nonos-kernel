// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Mouse settings state - delegates to the real input subsystem config.

use crate::input::config;

/// Mouse settings state (mirrors input config for UI display)
#[derive(Clone, Copy)]
pub struct MouseState {
    pub tracking_speed: u8,
    pub scroll_speed: u8,
    pub double_click_speed: u8,
    pub natural_scroll: bool,
    pub secondary_click: bool,
    pub pointer_acceleration: bool,
}

/// Get current state from the real input subsystem
pub(super) fn get_state() -> MouseState {
    let cfg = config::get_mouse_config();
    MouseState {
        tracking_speed: cfg.tracking_speed,
        scroll_speed: cfg.scroll_speed,
        double_click_speed: cfg.double_click_speed,
        natural_scroll: cfg.natural_scroll,
        secondary_click: cfg.secondary_click,
        pointer_acceleration: cfg.pointer_acceleration,
    }
}

/// Set tracking speed - delegates to real input subsystem
pub(super) fn set_tracking_speed(speed: u8) {
    config::set_tracking_speed(speed);
}

/// Set scroll speed - delegates to real input subsystem
pub(super) fn set_scroll_speed(speed: u8) {
    config::set_scroll_speed(speed);
}

/// Set double-click speed - delegates to real input subsystem
pub(super) fn set_double_click_speed(speed: u8) {
    config::set_double_click_speed(speed);
}

/// Set natural scroll - delegates to real input subsystem
pub(super) fn set_natural_scroll(enabled: bool) {
    config::set_natural_scroll(enabled);
}

/// Set pointer acceleration - delegates to real input subsystem
pub(super) fn set_pointer_acceleration(enabled: bool) {
    config::set_pointer_acceleration(enabled);
}
