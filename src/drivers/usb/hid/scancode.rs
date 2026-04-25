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

pub const HID_TO_ASCII: [u8; 128] = [
    0, 0, 0, 0, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n',
    b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z', b'1', b'2', b'3', b'4',
    b'5', b'6', b'7', b'8', b'9', b'0', b'\n', 0x1B, 0x08, b'\t', b' ', b'-', b'=', b'[', b']',
    b'\\', 0, b';', b'\'', b'`', b',', b'.', b'/', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub const HID_TO_ASCII_SHIFT: [u8; 128] = [
    0, 0, 0, 0, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N',
    b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'!', b'@', b'#', b'$',
    b'%', b'^', b'&', b'*', b'(', b')', b'\n', 0x1B, 0x08, b'\t', b' ', b'_', b'+', b'{', b'}',
    b'|', 0, b':', b'"', b'~', b'<', b'>', b'?', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub const KEY_NONE: u8 = 0x00;
pub const KEY_ERR_ROLLOVER: u8 = 0x01;
pub const KEY_A: u8 = 0x04;
pub const KEY_Z: u8 = 0x1D;
pub const KEY_1: u8 = 0x1E;
pub const KEY_0: u8 = 0x27;
pub const KEY_ENTER: u8 = 0x28;
pub const KEY_ESCAPE: u8 = 0x29;
pub const KEY_BACKSPACE: u8 = 0x2A;
pub const KEY_TAB: u8 = 0x2B;
pub const KEY_SPACE: u8 = 0x2C;
pub const KEY_CAPS_LOCK: u8 = 0x39;
pub const KEY_F1: u8 = 0x3A;
pub const KEY_F12: u8 = 0x45;
pub const KEY_INSERT: u8 = 0x49;
pub const KEY_HOME: u8 = 0x4A;
pub const KEY_PAGE_UP: u8 = 0x4B;
pub const KEY_DELETE: u8 = 0x4C;
pub const KEY_END: u8 = 0x4D;
pub const KEY_PAGE_DOWN: u8 = 0x4E;
pub const KEY_RIGHT: u8 = 0x4F;
pub const KEY_LEFT: u8 = 0x50;
pub const KEY_DOWN: u8 = 0x51;
pub const KEY_UP: u8 = 0x52;

pub fn hid_to_ascii(scancode: u8, shift: bool) -> Option<u8> {
    if scancode >= 128 {
        return None;
    }
    let ch =
        if shift { HID_TO_ASCII_SHIFT[scancode as usize] } else { HID_TO_ASCII[scancode as usize] };
    if ch == 0 {
        None
    } else {
        Some(ch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialKey {
    None,
    ErrRollover,
    Enter,
    Escape,
    Backspace,
    Tab,
    Space,
    CapsLock,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    Insert,
    Home,
    PageUp,
    Delete,
    End,
    PageDown,
    Right,
    Left,
    Down,
    Up,
}

pub fn identify_special_key(scancode: u8) -> SpecialKey {
    match scancode {
        KEY_NONE => SpecialKey::None,
        KEY_ERR_ROLLOVER => SpecialKey::ErrRollover,
        KEY_ENTER => SpecialKey::Enter,
        KEY_ESCAPE => SpecialKey::Escape,
        KEY_BACKSPACE => SpecialKey::Backspace,
        KEY_TAB => SpecialKey::Tab,
        KEY_SPACE => SpecialKey::Space,
        KEY_CAPS_LOCK => SpecialKey::CapsLock,
        KEY_F1 => SpecialKey::F1,
        k if k > KEY_F1 && k <= KEY_F12 => match k - KEY_F1 {
            1 => SpecialKey::F2,
            2 => SpecialKey::F3,
            3 => SpecialKey::F4,
            4 => SpecialKey::F5,
            5 => SpecialKey::F6,
            6 => SpecialKey::F7,
            7 => SpecialKey::F8,
            8 => SpecialKey::F9,
            9 => SpecialKey::F10,
            10 => SpecialKey::F11,
            _ => SpecialKey::F12,
        },
        KEY_INSERT => SpecialKey::Insert,
        KEY_HOME => SpecialKey::Home,
        KEY_PAGE_UP => SpecialKey::PageUp,
        KEY_DELETE => SpecialKey::Delete,
        KEY_END => SpecialKey::End,
        KEY_PAGE_DOWN => SpecialKey::PageDown,
        KEY_RIGHT => SpecialKey::Right,
        KEY_LEFT => SpecialKey::Left,
        KEY_DOWN => SpecialKey::Down,
        KEY_UP => SpecialKey::Up,
        _ => SpecialKey::None,
    }
}

pub fn is_letter_key(scancode: u8) -> bool {
    scancode >= KEY_A && scancode <= KEY_Z
}
pub fn is_digit_key(scancode: u8) -> bool {
    scancode >= KEY_1 && scancode <= KEY_0
}
pub fn is_navigation_key(scancode: u8) -> bool {
    matches!(scancode, KEY_INSERT | KEY_HOME | KEY_PAGE_UP | KEY_DELETE | KEY_END | KEY_PAGE_DOWN)
}
pub fn is_arrow_key(scancode: u8) -> bool {
    matches!(scancode, KEY_RIGHT | KEY_LEFT | KEY_DOWN | KEY_UP)
}
pub fn is_function_key(scancode: u8) -> bool {
    scancode >= KEY_F1 && scancode <= KEY_F12
}
