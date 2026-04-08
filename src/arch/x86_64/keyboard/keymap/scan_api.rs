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

use crate::arch::x86_64::keyboard::layout::{get_ascii_mapping, get_shifted_mapping, Layout};
use crate::arch::x86_64::keyboard::types::{KeyCode, KeyMapping};
use super::convert::ascii_to_keycode;

pub fn map_scan_code(scan: u8, shifted: bool, layout: Layout) -> KeyCode {
    if scan as usize >= 128 { return KeyCode::Unknown; }
    let base_map = get_ascii_mapping(layout);
    let shift_map = get_shifted_mapping(layout);
    let ascii = if shifted { shift_map[scan as usize] } else { base_map[scan as usize] };
    scan_to_keycode(scan, ascii)
}

pub fn map_scan_code_full(scan: u8, shifted: bool, layout: Layout) -> KeyMapping {
    if scan as usize >= 128 { return KeyMapping::unknown(); }
    let base_map = get_ascii_mapping(layout);
    let shift_map = get_shifted_mapping(layout);
    let ascii = base_map[scan as usize];
    let shifted_ascii = shift_map[scan as usize];
    let keycode = if shifted { scan_to_keycode(scan, shifted_ascii) } else { scan_to_keycode(scan, ascii) };
    KeyMapping::new(keycode, ascii, shifted_ascii, false, ascii != 0)
}

fn scan_to_keycode(scan: u8, ascii: u8) -> KeyCode {
    match scan {
        0x01 => KeyCode::Escape, 0x0E => KeyCode::Backspace, 0x0F => KeyCode::Tab,
        0x1C => KeyCode::Enter, 0x1D => KeyCode::LeftCtrl, 0x2A => KeyCode::LeftShift,
        0x36 => KeyCode::RightShift, 0x38 => KeyCode::LeftAlt, 0x39 => KeyCode::Space,
        0x3A => KeyCode::CapsLock, 0x3B => KeyCode::F1, 0x3C => KeyCode::F2,
        0x3D => KeyCode::F3, 0x3E => KeyCode::F4, 0x3F => KeyCode::F5, 0x40 => KeyCode::F6,
        0x41 => KeyCode::F7, 0x42 => KeyCode::F8, 0x43 => KeyCode::F9, 0x44 => KeyCode::F10,
        0x45 => KeyCode::NumLock, 0x46 => KeyCode::ScrollLock,
        0x47 => KeyCode::Home, 0x48 => KeyCode::ArrowUp, 0x49 => KeyCode::PageUp,
        0x4B => KeyCode::ArrowLeft, 0x4D => KeyCode::ArrowRight, 0x4F => KeyCode::End,
        0x50 => KeyCode::ArrowDown, 0x51 => KeyCode::PageDown,
        0x52 => KeyCode::Insert, 0x53 => KeyCode::Delete,
        0x57 => KeyCode::F11, 0x58 => KeyCode::F12,
        _ => ascii_to_keycode(ascii),
    }
}
