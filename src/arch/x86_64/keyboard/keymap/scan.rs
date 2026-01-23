// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::arch::x86_64::keyboard::error::KeymapError;
use crate::arch::x86_64::keyboard::layout::{get_ascii_mapping, get_shifted_mapping, Layout};
use crate::arch::x86_64::keyboard::types::{KeyCode, KeyMapping};

use super::convert::ascii_to_keycode;
use super::numpad::NumpadKey;
use super::state::{
    get_extended_state, get_modifiers, set_extended_state, update_modifiers, ExtendedState,
};

pub type KeymapResult<T> = Result<T, KeymapError>;

pub fn process_scan_code(scan_code: u8, layout: Layout) -> KeymapResult<Option<KeyMapping>> {
    let state = get_extended_state();

    match (state, scan_code) {
        (ExtendedState::None, 0xE0) => {
            set_extended_state(ExtendedState::E0Pending);
            return Ok(None);
        }
        (ExtendedState::None, 0xE1) => {
            set_extended_state(ExtendedState::E1Pending(1));
            return Ok(None);
        }
        (ExtendedState::E1Pending(1), _) => {
            set_extended_state(ExtendedState::E1Pending(2));
            return Ok(None);
        }
        (ExtendedState::E1Pending(_), _) => {
            set_extended_state(ExtendedState::None);
            return Ok(Some(KeyMapping::non_printable(KeyCode::Pause, true)));
        }
        _ => {}
    }

    let is_release = (scan_code & 0x80) != 0;
    let code = scan_code & 0x7F;

    if state == ExtendedState::E0Pending {
        set_extended_state(ExtendedState::None);
        update_modifiers(code, is_release, true);
        return Ok(Some(map_extended_scan_code(code)));
    }

    if code >= 0x60 && code != 0x7F {
        return Err(KeymapError::InvalidScanCode);
    }

    update_modifiers(code, is_release, false);
    Ok(Some(map_standard_scan_code(code, layout)))
}

fn map_extended_scan_code(code: u8) -> KeyMapping {
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

fn map_standard_scan_code(code: u8, layout: Layout) -> KeyMapping {
    let keycode = match code {
        0x01 => KeyCode::Escape,
        0x0E => KeyCode::Backspace,
        0x0F => KeyCode::Tab,
        0x1C => KeyCode::Enter,
        0x1D => KeyCode::LeftCtrl,
        0x2A => KeyCode::LeftShift,
        0x36 => KeyCode::RightShift,
        0x38 => KeyCode::LeftAlt,
        0x39 => KeyCode::Space,
        0x3A => KeyCode::CapsLock,
        0x3B => KeyCode::F1,
        0x3C => KeyCode::F2,
        0x3D => KeyCode::F3,
        0x3E => KeyCode::F4,
        0x3F => KeyCode::F5,
        0x40 => KeyCode::F6,
        0x41 => KeyCode::F7,
        0x42 => KeyCode::F8,
        0x43 => KeyCode::F9,
        0x44 => KeyCode::F10,
        0x45 => KeyCode::NumLock,
        0x46 => KeyCode::ScrollLock,
        0x57 => KeyCode::F11,
        0x58 => KeyCode::F12,
        _ => KeyCode::Unknown,
    };

    if keycode != KeyCode::Unknown {
        let (ascii, shifted) = match keycode {
            KeyCode::Tab => (b'\t', b'\t'),
            KeyCode::Enter => (b'\n', b'\n'),
            KeyCode::Space => (b' ', b' '),
            KeyCode::Backspace => (8, 8),
            KeyCode::Escape => (0x1B, 0x1B),
            _ => (0, 0),
        };
        let printable = ascii != 0;
        return KeyMapping::new(keycode, ascii, shifted, false, printable);
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
        let keycode = ascii_to_keycode(ascii);
        let printable = ascii != 0;
        KeyMapping::new(keycode, ascii, shifted, false, printable)
    } else {
        KeyMapping::unknown()
    }
}

pub fn map_scan_code(scan: u8, shifted: bool, layout: Layout) -> KeyCode {
    if scan as usize >= 128 {
        return KeyCode::Unknown;
    }

    let base_map = get_ascii_mapping(layout);
    let shift_map = get_shifted_mapping(layout);

    let ascii = if shifted {
        shift_map[scan as usize]
    } else {
        base_map[scan as usize]
    };

    scan_to_keycode(scan, ascii)
}

pub fn map_scan_code_full(scan: u8, shifted: bool, layout: Layout) -> KeyMapping {
    if scan as usize >= 128 {
        return KeyMapping::unknown();
    }

    let base_map = get_ascii_mapping(layout);
    let shift_map = get_shifted_mapping(layout);

    let ascii = base_map[scan as usize];
    let shifted_ascii = shift_map[scan as usize];

    let keycode = if shifted {
        scan_to_keycode(scan, shifted_ascii)
    } else {
        scan_to_keycode(scan, ascii)
    };

    KeyMapping::new(keycode, ascii, shifted_ascii, false, ascii != 0)
}

fn scan_to_keycode(scan: u8, ascii: u8) -> KeyCode {
    match scan {
        0x01 => KeyCode::Escape,
        0x0E => KeyCode::Backspace,
        0x0F => KeyCode::Tab,
        0x1C => KeyCode::Enter,
        0x1D => KeyCode::LeftCtrl,
        0x2A => KeyCode::LeftShift,
        0x36 => KeyCode::RightShift,
        0x38 => KeyCode::LeftAlt,
        0x39 => KeyCode::Space,
        0x3A => KeyCode::CapsLock,
        0x3B => KeyCode::F1,
        0x3C => KeyCode::F2,
        0x3D => KeyCode::F3,
        0x3E => KeyCode::F4,
        0x3F => KeyCode::F5,
        0x40 => KeyCode::F6,
        0x41 => KeyCode::F7,
        0x42 => KeyCode::F8,
        0x43 => KeyCode::F9,
        0x44 => KeyCode::F10,
        0x45 => KeyCode::NumLock,
        0x46 => KeyCode::ScrollLock,
        0x47 => KeyCode::Home,
        0x48 => KeyCode::ArrowUp,
        0x49 => KeyCode::PageUp,
        0x4B => KeyCode::ArrowLeft,
        0x4D => KeyCode::ArrowRight,
        0x4F => KeyCode::End,
        0x50 => KeyCode::ArrowDown,
        0x51 => KeyCode::PageDown,
        0x52 => KeyCode::Insert,
        0x53 => KeyCode::Delete,
        0x57 => KeyCode::F11,
        0x58 => KeyCode::F12,
        _ => ascii_to_keycode(ascii),
    }
}
