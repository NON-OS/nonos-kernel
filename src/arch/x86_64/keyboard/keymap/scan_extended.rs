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

use crate::arch::x86_64::keyboard::types::{KeyCode, KeyMapping};

pub fn map_extended_scan_code(code: u8) -> KeyMapping {
    match code {
        0x47 => KeyMapping::non_printable(KeyCode::Home, true),
        0x48 => KeyMapping::non_printable(KeyCode::ArrowUp, true),
        0x49 => KeyMapping::non_printable(KeyCode::PageUp, true),
        0x4B => KeyMapping::non_printable(KeyCode::ArrowLeft, true),
        0x4D => KeyMapping::non_printable(KeyCode::ArrowRight, true),
        0x4F => KeyMapping::non_printable(KeyCode::End, true),
        0x50 => KeyMapping::non_printable(KeyCode::ArrowDown, true),
        0x51 => KeyMapping::non_printable(KeyCode::PageDown, true),
        0x52 => KeyMapping::non_printable(KeyCode::Insert, true),
        0x53 => KeyMapping::non_printable(KeyCode::Delete, true),
        0x1C => KeyMapping::new(KeyCode::Enter, b'\n', b'\n', true, true),
        0x35 => KeyMapping::new(KeyCode::Slash, b'/', b'/', true, true),
        0x1D => KeyMapping::non_printable(KeyCode::RightCtrl, true),
        0x38 => KeyMapping::non_printable(KeyCode::RightAlt, true),
        0x5B => KeyMapping::non_printable(KeyCode::LeftSuper, true),
        0x5C => KeyMapping::non_printable(KeyCode::RightSuper, true),
        0x5D => KeyMapping::non_printable(KeyCode::Menu, true),
        0x37 => KeyMapping::non_printable(KeyCode::PrintScreen, true),
        0x2A => KeyMapping::non_printable(KeyCode::Unknown, true),
        _ => KeyMapping::unknown(),
    }
}
