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

use super::mouse_types::{MouseType, MousePacket};
use super::super::types::{MouseButtons, MouseButton};

pub fn parse_packet(buffer: &[u8; 4], mouse_type: MouseType) -> MousePacket {
    let (byte0, byte1, byte2) = (buffer[0], buffer[1], buffer[2]);
    let mut buttons = MouseButtons::new();
    if byte0 & 0x01 != 0 { buttons.set(MouseButton::Left); }
    if byte0 & 0x02 != 0 { buttons.set(MouseButton::Right); }
    if byte0 & 0x04 != 0 { buttons.set(MouseButton::Middle); }
    let dx = if byte0 & 0x10 != 0 { byte1 as i16 | 0xFF00u16 as i16 } else { byte1 as i16 };
    let dy = if byte0 & 0x20 != 0 { -(byte2 as i16 | 0xFF00u16 as i16) } else { -(byte2 as i16) };
    let mut dz: i8 = 0;
    if mouse_type != MouseType::Standard {
        let byte3 = buffer[3];
        dz = (byte3 & 0x0F) as i8;
        if byte3 & 0x08 != 0 { dz |= 0xF0u8 as i8; }
        if mouse_type == MouseType::FiveButton {
            if byte3 & 0x10 != 0 { buttons.set(MouseButton::Button4); }
            if byte3 & 0x20 != 0 { buttons.set(MouseButton::Button5); }
        }
    }
    MousePacket { buttons, dx, dy, dz }
}
