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

pub fn theme() -> u8 {
    unsafe { CURRENT_SETTINGS.theme }
}

pub fn set_theme(t: u8) {
    unsafe { CURRENT_SETTINGS.theme = t; }
    mark_modified();
}

pub fn timezone() -> i8 {
    unsafe { CURRENT_SETTINGS.timezone }
}

pub fn set_timezone(tz: i8) {
    unsafe { CURRENT_SETTINGS.timezone = tz.clamp(-12, 14); }
    mark_modified();
}
