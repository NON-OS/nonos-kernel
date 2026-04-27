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

pub(super) struct ParseContext {
    pub usage_page: u32,
    pub usage: u32,
    pub report_size: u32,
    pub report_count: u32,
    pub report_id: u8,
    pub logical_min: i32,
    pub logical_max: i32,
    pub physical_max: i32,
    pub in_touchpad: bool,
    pub in_finger: bool,
    pub current_bit_offset: u16,
    pub finger_index: usize,
    pub finger_start_bit: u16,
    pub pending_usage: Option<(u32, u32)>,
}

impl Default for ParseContext {
    fn default() -> Self {
        Self {
            usage_page: 0,
            usage: 0,
            report_size: 0,
            report_count: 0,
            report_id: 0,
            logical_min: 0,
            logical_max: 0,
            physical_max: 0,
            in_touchpad: false,
            in_finger: false,
            current_bit_offset: 0,
            finger_index: 0,
            finger_start_bit: 0,
            pending_usage: None,
        }
    }
}
