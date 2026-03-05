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

use super::types::{TouchpadState, Gesture};
use super::parsing;
use super::constants::{TAP_TIMEOUT_US, DOUBLE_TAP_TIMEOUT_US};
use crate::input::i2c_hid::descriptor::TouchpadLayout;

fn timestamp() -> u64 {
    crate::arch::x86_64::time::tsc::elapsed_us()
}

pub struct TouchpadDriver {
    logical_max_x: i32,
    logical_max_y: i32,
    layout: TouchpadLayout,

    last_x: i32,
    last_y: i32,
    is_tracking: bool,

    accumulated_dx: i32,
    accumulated_dy: i32,

    tap_start_time: u64,
    tap_start_x: i32,
    tap_start_y: i32,
    tap_enabled: bool,
    last_tap_time: u64,
    tap_count: u8,
    was_touching: bool,
}

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

    fn detect_tap(&mut self, now: u64) -> Gesture {
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

    fn extract_touch(&self, data: &[u8]) -> Option<(i32, i32)> {
        if self.is_using_layout() {
            if let Some(coords) = self.extract_from_layout(data) {
                return Some(coords);
            }
        }

        self.extract_fallback(data)
    }

    fn extract_from_layout(&self, data: &[u8]) -> Option<(i32, i32)> {
        let contact = &self.layout.contacts[0];

        if contact.tip_switch.is_valid() {
            let tip = contact.tip_switch.extract(data);
            if tip == 0 {
                return None;
            }
        }

        let x = contact.x.extract(data);
        let y = contact.y.extract(data);

        if self.is_valid_coordinate(x, y) {
            Some((x, y))
        } else {
            None
        }
    }

    fn extract_fallback(&self, data: &[u8]) -> Option<(i32, i32)> {
        let mut state = TouchpadState::default();

        if parsing::try_parse_hp_precision_touchpad(data, &mut state, 5, self.logical_max_x, self.logical_max_y) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if parsing::try_parse_precision_touchpad(data, &mut state, 5, self.logical_max_x, self.logical_max_y) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if parsing::try_parse_windows_precision(data, &mut state, 5, self.logical_max_x, self.logical_max_y) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if parsing::try_parse_synaptics(data, &mut state) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if parsing::try_parse_elan(data, &mut state) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if parsing::try_parse_standard_touchpad(data, &mut state, self.logical_max_x, self.logical_max_y) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }

        if let Some(coords) = self.try_format_raw(data) {
            return Some(coords);
        }

        None
    }

    fn try_format_raw(&self, data: &[u8]) -> Option<(i32, i32)> {
        if data.len() < 4 {
            return None;
        }

        let x = u16::from_le_bytes([data[0], data[1]]) as i32;
        let y = u16::from_le_bytes([data[2], data[3]]) as i32;

        if x > 100 && y > 100 && self.is_valid_coordinate(x, y) {
            Some((x, y))
        } else {
            None
        }
    }

    fn is_valid_coordinate(&self, x: i32, y: i32) -> bool {
        x > 0 && y > 0 && x <= self.logical_max_x && y <= self.logical_max_y
    }

    fn calculate_delta(&mut self, x: i32, y: i32) -> (i32, i32) {
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

    fn reset_tracking(&mut self) {
        self.is_tracking = false;
        self.accumulated_dx = 0;
        self.accumulated_dy = 0;
    }

    pub fn set_sensitivity(&mut self, _sensitivity: i32) {}
    pub fn set_acceleration(&mut self, _acceleration: i32) {}
    pub fn set_palm_rejection(&mut self, _enabled: bool) {}

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

    pub fn parse_contact_point(&self, data: &[u8], offset: usize) -> Option<super::TouchPoint> {
        parsing::parse_contact_point(data, offset)
    }
}
