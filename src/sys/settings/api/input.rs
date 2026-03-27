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

use crate::sys::settings::state::{CURRENT_SETTINGS, mark_modified};

pub fn mouse_sensitivity() -> u8 {
    unsafe { CURRENT_SETTINGS.mouse_sensitivity }
}

pub fn set_mouse_sensitivity(val: u8) {
    unsafe { CURRENT_SETTINGS.mouse_sensitivity = val.clamp(1, 10); }
    mark_modified();
}

pub fn keyboard_layout() -> u8 {
    unsafe { CURRENT_SETTINGS.keyboard_layout }
}

pub fn set_keyboard_layout(layout: u8) {
    unsafe { CURRENT_SETTINGS.keyboard_layout = layout.min(5); }
    mark_modified();
}

pub fn sound_enabled() -> bool {
    unsafe { CURRENT_SETTINGS.sound_enabled }
}

pub fn set_sound_enabled(enabled: bool) {
    unsafe { CURRENT_SETTINGS.sound_enabled = enabled; }
    mark_modified();
}
