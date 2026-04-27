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
use super::super::types::TouchpadState;
use super::types::TouchpadDriver;

impl TouchpadDriver {
    pub(super) fn extract_touch(&self, data: &[u8]) -> Option<(i32, i32)> {
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
        if parsing::try_parse_hp_precision_touchpad(
            data,
            &mut state,
            5,
            self.logical_max_x,
            self.logical_max_y,
        ) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }
        if parsing::try_parse_precision_touchpad(
            data,
            &mut state,
            5,
            self.logical_max_x,
            self.logical_max_y,
        ) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }
        if parsing::try_parse_windows_precision(
            data,
            &mut state,
            5,
            self.logical_max_x,
            self.logical_max_y,
        ) {
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
        if parsing::try_parse_standard_touchpad(
            data,
            &mut state,
            self.logical_max_x,
            self.logical_max_y,
        ) {
            if state.contact_count > 0 && state.contacts[0].tip {
                return Some((state.contacts[0].x, state.contacts[0].y));
            }
        }
        self.try_format_raw(data)
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

    pub(super) fn is_valid_coordinate(&self, x: i32, y: i32) -> bool {
        x > 0 && y > 0 && x <= self.logical_max_x && y <= self.logical_max_y
    }
}
