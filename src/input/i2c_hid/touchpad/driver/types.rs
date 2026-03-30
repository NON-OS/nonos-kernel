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

use crate::input::i2c_hid::descriptor::TouchpadLayout;

pub(super) fn timestamp() -> u64 {
    crate::arch::x86_64::time::tsc::elapsed_us()
}

pub struct TouchpadDriver {
    pub(super) logical_max_x: i32,
    pub(super) logical_max_y: i32,
    pub(super) layout: TouchpadLayout,
    pub(super) last_x: i32,
    pub(super) last_y: i32,
    pub(super) is_tracking: bool,
    pub(super) accumulated_dx: i32,
    pub(super) accumulated_dy: i32,
    pub(super) tap_start_time: u64,
    pub(super) tap_start_x: i32,
    pub(super) tap_start_y: i32,
    pub(super) tap_enabled: bool,
    pub(super) last_tap_time: u64,
    pub(super) tap_count: u8,
    pub(super) was_touching: bool,
    pub(super) sensitivity: i32,
    pub(super) acceleration: i32,
    pub(super) palm_rejection: bool,
}
