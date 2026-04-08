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
use super::numpad::NumpadKey;
use super::state::get_modifiers;

pub fn map_standard_scan_code(code: u8, layout: Layout) -> KeyMapping {
    let keycode = match code {
        0x01 => KeyCode::Escape, 0x0E => KeyCode::Backspace, 0x0F => KeyCode::Tab,
        0x1C => KeyCode::Enter, 0x1D => KeyCode::LeftCtrl, 0x2A => KeyCode::LeftShift,
        0x36 => KeyCode::RightShift, 0x38 => KeyCode::LeftAlt, 0x39 => KeyCode::Space,
        0x3A => KeyCode::CapsLock, 0x3B => KeyCode::F1, 0x3C => KeyCode::F2,
        0x3D => KeyCode::F3, 0x3E => KeyCode::F4, 0x3F => KeyCode::F5, 0x40 => KeyCode::F6,
        0x41 => KeyCode::F7, 0x42 => KeyCode::F8, 0x43 => KeyCode::F9, 0x44 => KeyCode::F10,
        0x45 => KeyCode::NumLock, 0x46 => KeyCode::ScrollLock,
        0x57 => KeyCode::F11, 0x58 => KeyCode::F12,
        _ => KeyCode::Unknown,
    };
    if keycode != KeyCode::Unknown {
        let (ascii, shifted) = match keycode {
            KeyCode::Tab => (b'\t', b'\t'), KeyCode::Enter => (b'\n', b'\n'),
            KeyCode::Space => (b' ', b' '), KeyCode::Backspace => (8, 8),
            KeyCode::Escape => (0x1B, 0x1B), _ => (0, 0),
        };
        return KeyMapping::new(keycode, ascii, shifted, false, ascii != 0);
    }
    let mods = get_modifiers();
    if let Some(np) = NumpadKey::from_scan_code(code) {
        let num_lock = mods.num_lock();
        let keycode = np.to_keycode(num_lock);
        let ascii = np.to_ascii(num_lock).unwrap_or(0);
        return KeyMapping::new(keycode, ascii, ascii, false, ascii != 0);
    }
    let base_map = get_ascii_mapping(layout);
    let shift_map = get_shifted_mapping(layout);
    if (code as usize) < base_map.len() {
        let ascii = base_map[code as usize];
        let shifted = shift_map[code as usize];
        KeyMapping::new(ascii_to_keycode(ascii), ascii, shifted, false, ascii != 0)
    } else { KeyMapping::unknown() }
}
