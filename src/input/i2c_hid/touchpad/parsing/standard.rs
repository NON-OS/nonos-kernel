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

use crate::input::i2c_hid::touchpad::types::{TouchPoint, TouchpadState};

pub(crate) fn try_parse_standard_touchpad(
    data: &[u8],
    state: &mut TouchpadState,
    logical_max_x: i32,
    logical_max_y: i32,
) -> bool {
    if data.len() < 5 {
        return false;
    }
    let tip = (data[0] & 0x01) != 0;
    let confidence = (data[0] & 0x02) != 0;
    let x = u16::from_le_bytes([data[1], data[2]]) as i32;
    let y = u16::from_le_bytes([data[3], data[4]]) as i32;
    let max_x = if logical_max_x > 0 { logical_max_x } else { 65535 };
    let max_y = if logical_max_y > 0 { logical_max_y } else { 65535 };
    if x < 0 || y < 0 || x > max_x || y > max_y {
        return false;
    }
    if !tip {
        state.contact_count = 0;
        state.buttons = 0;
        return true;
    }
    state.contact_count = 1;
    state.contacts[0] = TouchPoint {
        id: 0,
        x,
        y,
        tip,
        pressure: if confidence { 200 } else { 100 },
        width: 0,
        height: 0,
    };
    if data.len() > 5 && tip {
        state.buttons = data[5] & 0x03;
    } else {
        state.buttons = 0;
    }
    true
}
