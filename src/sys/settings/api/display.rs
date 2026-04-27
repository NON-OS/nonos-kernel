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

use crate::sys::settings::state::{mark_modified, CURRENT_SETTINGS};

pub fn brightness() -> u8 {
    unsafe { CURRENT_SETTINGS.brightness }
}

pub fn set_brightness(val: u8) {
    unsafe {
        CURRENT_SETTINGS.brightness = val.min(100);
    }
    mark_modified();
}

pub fn screen_timeout() -> u8 {
    unsafe { CURRENT_SETTINGS.screen_timeout }
}

pub fn set_screen_timeout(val: u8) {
    unsafe {
        CURRENT_SETTINGS.screen_timeout = val.min(60);
    }
    mark_modified();
}

pub fn notifications_enabled() -> bool {
    unsafe { CURRENT_SETTINGS.notifications_enabled }
}
pub fn set_notifications_enabled(v: bool) {
    unsafe {
        CURRENT_SETTINGS.notifications_enabled = v;
    }
    mark_modified();
}

pub fn animations_enabled() -> bool {
    unsafe { CURRENT_SETTINGS.animations_enabled }
}
pub fn set_animations_enabled(v: bool) {
    unsafe {
        CURRENT_SETTINGS.animations_enabled = v;
    }
    mark_modified();
}
