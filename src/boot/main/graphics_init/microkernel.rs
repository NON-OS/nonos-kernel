// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::input;
use super::components::init_desktop;

/// Initialize graphics for microkernel desktop service.
/// Note: Storage, network, and other services are initialized by their
/// respective service processes - desktop only needs framebuffer and GUI.
pub fn init_graphics_for_microkernel() -> bool {
    crate::sys::serial::println(b"[DESK] get_framebuffer...");
    let Ok(info) = crate::display::get_framebuffer() else {
        crate::sys::serial::println(b"[DESK] FAIL: no framebuffer");
        return false;
    };
    crate::sys::serial::println(b"[DESK] FB OK, init input bounds...");
    input::set_screen_bounds_unified(info.width, info.height);
    crate::sys::serial::println(b"[DESK] init desktop GUI...");
    init_desktop();
    crate::sys::serial::println(b"[DESK] ALL DONE!");
    true
}
