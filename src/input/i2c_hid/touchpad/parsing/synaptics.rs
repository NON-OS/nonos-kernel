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

pub(crate) fn try_parse_synaptics(data: &[u8], state: &mut TouchpadState) -> bool {
    if data.len() < 8 {
        return false;
    }
    let packet_type = data[0] & 0xC0;
    if packet_type != 0x80 && packet_type != 0xC0 {
        return false;
    }
    let finger_count = ((data[0] >> 4) & 0x03) + 1;
    state.contact_count = finger_count as u8;
    let x1 = ((data[1] as i32) << 4) | ((data[3] as i32) & 0x0F);
    let y1 = ((data[2] as i32) << 4) | ((data[3] as i32) >> 4);
    let pressure1 = data[4];
    state.buttons = data[0] & 0x03;
    state.contacts[0] = TouchPoint {
        id: 0,
        x: x1,
        y: y1,
        tip: pressure1 > 30,
        pressure: pressure1,
        width: (data[5] & 0x0F) * 2,
        height: (data[5] >> 4) * 2,
    };
    if finger_count >= 2 && data.len() >= 12 {
        let x2 = ((data[6] as i32) << 4) | ((data[8] as i32) & 0x0F);
        let y2 = ((data[7] as i32) << 4) | ((data[8] as i32) >> 4);
        let pressure2 = data[9];
        state.contacts[1] = TouchPoint {
            id: 1,
            x: x2,
            y: y2,
            tip: pressure2 > 30,
            pressure: pressure2,
            width: 0,
            height: 0,
        };
    }
    true
}
