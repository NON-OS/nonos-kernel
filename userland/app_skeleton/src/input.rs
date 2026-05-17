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

use crate::app::InputEvent;

pub fn decode(b: &[u8]) -> Option<InputEvent> {
    if b.len() < 32 {
        return None;
    }
    Some(InputEvent {
        kind: u16::from_le_bytes([b[0], b[1]]),
        code: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        x: i32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        y: i32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        delta_x: i32::from_le_bytes([b[16], b[17], b[18], b[19]]),
        delta_y: i32::from_le_bytes([b[20], b[21], b[22], b[23]]),
    })
}
