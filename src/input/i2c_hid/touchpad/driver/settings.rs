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

use super::super::parsing;
use super::types::TouchpadDriver;

impl TouchpadDriver {
    pub fn set_sensitivity(&mut self, sensitivity: i32) {
        self.sensitivity = sensitivity.clamp(1, 200);
    }

    pub fn set_acceleration(&mut self, acceleration: i32) {
        self.acceleration = acceleration.clamp(1, 200);
    }

    pub fn set_palm_rejection(&mut self, enabled: bool) {
        self.palm_rejection = enabled;
    }

    pub fn sensitivity(&self) -> i32 {
        self.sensitivity
    }

    pub fn acceleration(&self) -> i32 {
        self.acceleration
    }

    pub fn palm_rejection_enabled(&self) -> bool {
        self.palm_rejection
    }

    pub fn set_tap_to_click(&mut self, enabled: bool) {
        self.tap_enabled = enabled;
        if !enabled {
            self.tap_count = 0;
            self.last_tap_time = 0;
        }
    }

    pub fn is_tap_enabled(&self) -> bool {
        self.tap_enabled
    }

    pub fn parse_buttons(&self, data: &[u8], offset: usize) -> u8 {
        parsing::parse_buttons(data, offset)
    }

    pub fn parse_contact_point(
        &self,
        data: &[u8],
        offset: usize,
    ) -> Option<super::super::TouchPoint> {
        parsing::parse_contact_point(data, offset)
    }
}
