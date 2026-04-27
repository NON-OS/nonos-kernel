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

pub fn theme() -> u8 {
    unsafe { CURRENT_SETTINGS.theme }
}

pub fn set_theme(t: u8) {
    unsafe {
        CURRENT_SETTINGS.theme = t;
    }
    mark_modified();
}

pub fn timezone() -> i8 {
    unsafe { CURRENT_SETTINGS.timezone }
}

pub fn set_timezone(tz: i8) {
    unsafe {
        CURRENT_SETTINGS.timezone = tz.clamp(-12, 14);
    }
    mark_modified();
}

pub fn language() -> u8 {
    unsafe { CURRENT_SETTINGS.language }
}
pub fn set_language(l: u8) {
    unsafe {
        CURRENT_SETTINGS.language = l;
    }
    mark_modified();
}

pub fn developer_mode() -> bool {
    unsafe { CURRENT_SETTINGS.developer_mode }
}
pub fn set_developer_mode(v: bool) {
    unsafe {
        CURRENT_SETTINGS.developer_mode = v;
    }
    mark_modified();
}

pub fn hardware_crypto() -> bool {
    unsafe { CURRENT_SETTINGS.hardware_crypto }
}
pub fn set_hardware_crypto(v: bool) {
    unsafe {
        CURRENT_SETTINGS.hardware_crypto = v;
    }
    mark_modified();
}

pub fn zk_attestation() -> bool {
    unsafe { CURRENT_SETTINGS.zk_attestation }
}
pub fn set_zk_attestation(v: bool) {
    unsafe {
        CURRENT_SETTINGS.zk_attestation = v;
    }
    mark_modified();
}

pub fn system_keys_generated() -> bool {
    unsafe { CURRENT_SETTINGS.system_keys_generated }
}
pub fn set_system_keys_generated(v: bool) {
    unsafe {
        CURRENT_SETTINGS.system_keys_generated = v;
    }
    mark_modified();
}
