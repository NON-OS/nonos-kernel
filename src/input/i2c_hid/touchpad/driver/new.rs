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

use super::types::TouchpadDriver;
use crate::input::i2c_hid::descriptor::TouchpadLayout;

impl TouchpadDriver {
    pub fn new(
        logical_max_x: i32,
        logical_max_y: i32,
        _max_contacts: u8,
        layout: TouchpadLayout,
    ) -> Self {
        Self {
            logical_max_x: logical_max_x.max(1000),
            logical_max_y: logical_max_y.max(1000),
            layout,
            last_x: 0,
            last_y: 0,
            is_tracking: false,
            accumulated_dx: 0,
            accumulated_dy: 0,
            tap_start_time: 0,
            tap_start_x: 0,
            tap_start_y: 0,
            tap_enabled: true,
            last_tap_time: 0,
            tap_count: 0,
            was_touching: false,
            sensitivity: 100,
            acceleration: 100,
            palm_rejection: true,
        }
    }

    pub fn is_using_layout(&self) -> bool {
        self.layout.contacts[0].x.is_valid() && self.layout.contacts[0].y.is_valid()
    }

    pub fn logical_max_x(&self) -> i32 {
        self.logical_max_x
    }

    pub fn logical_max_y(&self) -> i32 {
        self.logical_max_y
    }
}
