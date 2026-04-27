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

pub fn anonymous_mode() -> bool {
    unsafe { CURRENT_SETTINGS.anonymous_mode }
}

pub fn set_anonymous_mode(enabled: bool) {
    unsafe {
        CURRENT_SETTINGS.anonymous_mode = enabled;
    }
    mark_modified();
}

pub fn nym_enabled() -> bool {
    unsafe { CURRENT_SETTINGS.nym_enabled }
}

pub fn set_nym_enabled(enabled: bool) {
    unsafe {
        CURRENT_SETTINGS.nym_enabled = enabled;
    }
    mark_modified();
}

pub fn auto_wipe() -> bool {
    unsafe { CURRENT_SETTINGS.auto_wipe }
}

pub fn set_auto_wipe(enabled: bool) {
    unsafe {
        CURRENT_SETTINGS.auto_wipe = enabled;
    }
    mark_modified();
}

pub fn auto_lock_timeout() -> u8 {
    unsafe { CURRENT_SETTINGS.auto_lock_timeout }
}
pub fn set_auto_lock_timeout(v: u8) {
    unsafe {
        CURRENT_SETTINGS.auto_lock_timeout = v.min(30);
    }
    mark_modified();
}

pub fn wifi_autoconnect() -> bool {
    unsafe { CURRENT_SETTINGS.wifi_autoconnect }
}
pub fn set_wifi_autoconnect(v: bool) {
    unsafe {
        CURRENT_SETTINGS.wifi_autoconnect = v;
    }
    mark_modified();
}
