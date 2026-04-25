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

pub(crate) use crate::input::i2c_hid::touchpad::constants::MAX_CONTACTS;
use crate::input::i2c_hid::touchpad::types::TouchPoint;

pub(crate) fn parse_buttons(data: &[u8], offset: usize) -> u8 {
    if offset < data.len() {
        data[offset] & 0x03
    } else {
        0
    }
}

pub(crate) fn parse_contact_point(data: &[u8], offset: usize) -> Option<TouchPoint> {
    if offset + 5 > data.len() {
        return None;
    }
    let flags = data[offset];
    let tip = (flags & 0x01) != 0;
    let confidence = (flags & 0x02) != 0;
    let contact_id = (flags >> 2) & 0x3F;
    let x = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) as i32;
    let y = u16::from_le_bytes([data[offset + 3], data[offset + 4]]) as i32;
    Some(TouchPoint {
        id: contact_id,
        x,
        y,
        tip,
        pressure: if tip && confidence {
            200
        } else if tip {
            50
        } else {
            0
        },
        width: 0,
        height: 0,
    })
}
