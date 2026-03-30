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

use super::offset::try_parse_at_offset;
use crate::input::i2c_hid::touchpad::types::TouchpadState;

pub(crate) fn try_parse_hp_precision_touchpad(
    data: &[u8],
    state: &mut TouchpadState,
    max_contacts: u8,
    logical_max_x: i32,
    logical_max_y: i32,
) -> bool {
    if data.len() < 3 {
        return false;
    }
    if let Some(result) = try_parse_at_offset(data, 2, max_contacts, logical_max_x, logical_max_y) {
        *state = result;
        return true;
    }
    if let Some(result) = try_parse_at_offset(data, 0, max_contacts, logical_max_x, logical_max_y) {
        *state = result;
        return true;
    }
    if let Some(result) = try_parse_at_offset(data, 3, max_contacts, logical_max_x, logical_max_y) {
        *state = result;
        return true;
    }
    false
}
