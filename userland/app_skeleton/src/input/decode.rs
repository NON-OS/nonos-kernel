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

use super::event::InputEvent;
use super::kind::InputKind;

impl InputEvent {
    pub fn from_delivery(payload: &[u8]) -> Option<Self> {
        if payload.len() < 32 {
            return None;
        }
        let kind = match u16::from_le_bytes(payload[0..2].try_into().ok()?) {
            0 => InputKind::KeyDown,
            1 => InputKind::KeyUp,
            2 => InputKind::PointerRel,
            3 => InputKind::PointerAbs,
            4 => InputKind::Wheel,
            5 => InputKind::ButtonDown,
            6 => InputKind::ButtonUp,
            7 => InputKind::Touch,
            _ => return None,
        };
        Some(InputEvent {
            kind,
            flags: u16::from_le_bytes(payload[2..4].try_into().ok()?),
            code: u32::from_le_bytes(payload[4..8].try_into().ok()?),
            x: i32::from_le_bytes(payload[8..12].try_into().ok()?),
            y: i32::from_le_bytes(payload[12..16].try_into().ok()?),
            delta_x: i32::from_le_bytes(payload[16..20].try_into().ok()?),
            delta_y: i32::from_le_bytes(payload[20..24].try_into().ok()?),
            timestamp_ns: u64::from_le_bytes(payload[24..32].try_into().ok()?),
        })
    }
}
