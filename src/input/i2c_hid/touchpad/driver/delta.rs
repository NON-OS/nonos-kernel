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

impl TouchpadDriver {
    pub(super) fn calculate_delta(&mut self, x: i32, y: i32) -> (i32, i32) {
        if !self.is_tracking {
            self.last_x = x;
            self.last_y = y;
            self.is_tracking = true;
            self.accumulated_dx = 0;
            self.accumulated_dy = 0;
            return (0, 0);
        }
        let raw_dx = x - self.last_x;
        let raw_dy = y - self.last_y;
        self.last_x = x;
        self.last_y = y;
        let max_jump = self.logical_max_x / 4;
        if raw_dx.abs() > max_jump || raw_dy.abs() > max_jump {
            return (0, 0);
        }
        let scale = self.calculate_scale();
        let scaled_dx = raw_dx / scale;
        let scaled_dy = raw_dy / scale;
        self.accumulated_dx += raw_dx % scale;
        self.accumulated_dy += raw_dy % scale;
        let extra_dx = self.accumulated_dx / scale;
        let extra_dy = self.accumulated_dy / scale;
        self.accumulated_dx %= scale;
        self.accumulated_dy %= scale;
        let final_dx = scaled_dx + extra_dx;
        let final_dy = scaled_dy + extra_dy;
        (final_dx.clamp(-20, 20), final_dy.clamp(-20, 20))
    }

    fn calculate_scale(&self) -> i32 {
        (self.logical_max_x / 400).max(1)
    }

    pub(super) fn reset_tracking(&mut self) {
        self.is_tracking = false;
        self.accumulated_dx = 0;
        self.accumulated_dy = 0;
    }
}
