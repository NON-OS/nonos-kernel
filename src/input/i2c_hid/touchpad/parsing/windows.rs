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

use super::helpers::MAX_CONTACTS;
use crate::input::i2c_hid::touchpad::types::{TouchPoint, TouchpadState};

pub(crate) fn try_parse_windows_precision(
    data: &[u8],
    state: &mut TouchpadState,
    max_contacts: u8,
    logical_max_x: i32,
    logical_max_y: i32,
) -> bool {
    if data.len() < 9 {
        return false;
    }
    let contact_count = data[0] & 0x1F;
    if contact_count == 0 {
        state.contact_count = 0;
        state.buttons = 0;
        return true;
    }
    if contact_count > max_contacts.min(5) {
        return false;
    }
    state.contact_count = contact_count;
    let mut offset = 2;
    let mut valid_count = 0;
    for i in 0..(contact_count as usize).min(MAX_CONTACTS) {
        if offset + 7 > data.len() {
            break;
        }
        let flags = data[offset];
        let tip = (flags & 0x01) != 0;
        let confidence = (flags & 0x02) != 0;
        let contact_id = (flags >> 2) & 0x3F;
        let x = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) as i32;
        let y = u16::from_le_bytes([data[offset + 3], data[offset + 4]]) as i32;
        let pressure = data[offset + 5];
        let width = data[offset + 6];
        let max_x = if logical_max_x > 0 { logical_max_x } else { 65535 };
        let max_y = if logical_max_y > 0 { logical_max_y } else { 65535 };
        if x < 0 || y < 0 || x > max_x || y > max_y {
            return false;
        }
        if tip {
            valid_count += 1;
        }
        state.contacts[i] = TouchPoint {
            id: contact_id,
            x,
            y,
            tip,
            pressure: if tip && confidence {
                pressure.max(100)
            } else if tip {
                pressure.max(50)
            } else {
                0
            },
            width,
            height: width,
        };
        offset += 7;
    }
    if contact_count > 0 && valid_count == 0 {
        state.contact_count = 0;
    }
    if valid_count > 0 {
        state.buttons = data[1] & 0x03;
    } else {
        state.buttons = 0;
    }
    true
}
