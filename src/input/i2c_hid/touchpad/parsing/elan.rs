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

pub(crate) fn try_parse_elan(data: &[u8], state: &mut TouchpadState) -> bool {
    if data.len() < 6 {
        return false;
    }
    if data[0] != 0x04 && data[0] != 0x0D {
        return false;
    }
    let fingers = data[1] & 0x0F;
    if fingers == 0 {
        state.contact_count = 0;
        state.buttons = 0;
        return true;
    }
    if fingers > 5 {
        return false;
    }
    state.contact_count = fingers as u8;
    state.buttons = (data[1] >> 4) & 0x03;
    let mut offset = 2;
    for i in 0..(fingers as usize).min(MAX_CONTACTS) {
        if offset + 4 > data.len() {
            break;
        }
        let x = u16::from_le_bytes([data[offset], data[offset + 1]]) as i32;
        let y = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as i32;
        let pressure = if offset + 4 < data.len() { data[offset + 4] } else { 128 };
        state.contacts[i] =
            TouchPoint { id: i as u8, x, y, tip: pressure > 30, pressure, width: 0, height: 0 };
        offset += 5;
    }
    true
}
