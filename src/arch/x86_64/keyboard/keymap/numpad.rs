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

use crate::arch::x86_64::keyboard::types::KeyCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumpadKey {
    Num0,
    Num1,
    Num2,
    Num3,
    Num4,
    Num5,
    Num6,
    Num7,
    Num8,
    Num9,
    Divide,
    Multiply,
    Subtract,
    Add,
    Enter,
    Decimal,
}

impl NumpadKey {
    pub const fn to_ascii(self, num_lock: bool) -> Option<u8> {
        if num_lock {
            match self {
                Self::Num0 => Some(b'0'),
                Self::Num1 => Some(b'1'),
                Self::Num2 => Some(b'2'),
                Self::Num3 => Some(b'3'),
                Self::Num4 => Some(b'4'),
                Self::Num5 => Some(b'5'),
                Self::Num6 => Some(b'6'),
                Self::Num7 => Some(b'7'),
                Self::Num8 => Some(b'8'),
                Self::Num9 => Some(b'9'),
                Self::Decimal => Some(b'.'),
                Self::Divide => Some(b'/'),
                Self::Multiply => Some(b'*'),
                Self::Subtract => Some(b'-'),
                Self::Add => Some(b'+'),
                Self::Enter => Some(b'\n'),
            }
        } else {
            match self {
                Self::Divide => Some(b'/'),
                Self::Multiply => Some(b'*'),
                Self::Subtract => Some(b'-'),
                Self::Add => Some(b'+'),
                Self::Enter => Some(b'\n'),
                _ => None,
            }
        }
    }

    pub const fn to_keycode(self, num_lock: bool) -> KeyCode {
        if num_lock {
            match self {
                Self::Num0 => KeyCode::Num0,
                Self::Num1 => KeyCode::Num1,
                Self::Num2 => KeyCode::Num2,
                Self::Num3 => KeyCode::Num3,
                Self::Num4 => KeyCode::Num4,
                Self::Num5 => KeyCode::Num5,
                Self::Num6 => KeyCode::Num6,
                Self::Num7 => KeyCode::Num7,
                Self::Num8 => KeyCode::Num8,
                Self::Num9 => KeyCode::Num9,
                Self::Decimal => KeyCode::NumpadDecimal,
                Self::Divide => KeyCode::NumpadDivide,
                Self::Multiply => KeyCode::NumpadMultiply,
                Self::Subtract => KeyCode::NumpadMinus,
                Self::Add => KeyCode::NumpadPlus,
                Self::Enter => KeyCode::NumpadEnter,
            }
        } else {
            match self {
                Self::Num0 => KeyCode::Insert,
                Self::Num1 => KeyCode::End,
                Self::Num2 => KeyCode::ArrowDown,
                Self::Num3 => KeyCode::PageDown,
                Self::Num4 => KeyCode::ArrowLeft,
                Self::Num5 => KeyCode::Unknown,
                Self::Num6 => KeyCode::ArrowRight,
                Self::Num7 => KeyCode::Home,
                Self::Num8 => KeyCode::ArrowUp,
                Self::Num9 => KeyCode::PageUp,
                Self::Decimal => KeyCode::Delete,
                Self::Divide => KeyCode::NumpadDivide,
                Self::Multiply => KeyCode::NumpadMultiply,
                Self::Subtract => KeyCode::NumpadMinus,
                Self::Add => KeyCode::NumpadPlus,
                Self::Enter => KeyCode::NumpadEnter,
            }
        }
    }

    pub const fn from_scan_code(code: u8) -> Option<Self> {
        match code {
            0x47 => Some(Self::Num7),
            0x48 => Some(Self::Num8),
            0x49 => Some(Self::Num9),
            0x4A => Some(Self::Subtract),
            0x4B => Some(Self::Num4),
            0x4C => Some(Self::Num5),
            0x4D => Some(Self::Num6),
            0x4E => Some(Self::Add),
            0x4F => Some(Self::Num1),
            0x50 => Some(Self::Num2),
            0x51 => Some(Self::Num3),
            0x52 => Some(Self::Num0),
            0x53 => Some(Self::Decimal),
            0x37 => Some(Self::Multiply),
            _ => None,
        }
    }
}
