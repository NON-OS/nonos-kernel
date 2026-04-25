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

use super::super::constants::{DOUBLE_TAP_TIMEOUT_US, TAP_TIMEOUT_US};
use super::super::types::{Gesture, TouchpadState};
use super::types::{timestamp, TouchpadDriver};

impl TouchpadDriver {
    pub fn process_report(&mut self, _report_id: u8, data: &[u8]) -> Option<TouchpadState> {
        let mut state = TouchpadState::default();
        if data.len() < 4 {
            self.reset_tracking();
            return Some(state);
        }
        let touch = self.extract_touch(data);
        let now = timestamp();
        match touch {
            Some((x, y)) => {
                state.contact_count = 1;
                state.contacts[0].x = x;
                state.contacts[0].y = y;
                state.contacts[0].tip = true;
                if !self.was_touching && self.tap_enabled {
                    self.tap_start_time = now;
                    self.tap_start_x = x;
                    self.tap_start_y = y;
                }
                self.was_touching = true;
                let (dx, dy) = self.calculate_delta(x, y);
                state.delta_x = dx;
                state.delta_y = dy;
            }
            None => {
                if self.was_touching && self.tap_enabled {
                    state.gesture = self.detect_tap(now);
                }
                self.was_touching = false;
                self.reset_tracking();
            }
        }
        Some(state)
    }

    pub(super) fn detect_tap(&mut self, now: u64) -> Gesture {
        let tap_duration = now.saturating_sub(self.tap_start_time);
        if tap_duration > TAP_TIMEOUT_US {
            self.tap_count = 0;
            return Gesture::None;
        }
        let dx = (self.last_x - self.tap_start_x).abs();
        let dy = (self.last_y - self.tap_start_y).abs();
        let max_tap_movement = self.logical_max_x / 50;
        if dx > max_tap_movement || dy > max_tap_movement {
            self.tap_count = 0;
            return Gesture::None;
        }
        let time_since_last_tap = now.saturating_sub(self.last_tap_time);
        if time_since_last_tap < DOUBLE_TAP_TIMEOUT_US && self.tap_count > 0 {
            self.tap_count = 0;
            self.last_tap_time = 0;
            return Gesture::DoubleTap;
        }
        self.tap_count = 1;
        self.last_tap_time = now;
        Gesture::Tap
    }
}
