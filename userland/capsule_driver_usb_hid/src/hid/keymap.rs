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

const SHIFT_MASK: u8 = 0x22;
const CAPS_LOCK: u8 = 0x39;

pub fn is_caps_lock(scancode: u8) -> bool {
    scancode == CAPS_LOCK
}

pub fn ascii(scancode: u8, modifiers: u8, caps: bool) -> u8 {
    let shifted = (modifiers & SHIFT_MASK) != 0;
    match scancode {
        0x04..=0x1d => letter(scancode, shifted ^ caps),
        0x1e..=0x27 => digit(scancode, shifted),
        0x28 => b'\n',
        0x29 => 0x1b,
        0x2a => 0x08,
        0x2b => b'\t',
        0x2c => b' ',
        0x2d => if shifted { b'_' } else { b'-' },
        0x2e => if shifted { b'+' } else { b'=' },
        0x2f => if shifted { b'{' } else { b'[' },
        0x30 => if shifted { b'}' } else { b']' },
        0x31 => if shifted { b'|' } else { b'\\' },
        0x33 => if shifted { b':' } else { b';' },
        0x34 => if shifted { b'"' } else { b'\'' },
        0x35 => if shifted { b'~' } else { b'`' },
        0x36 => if shifted { b'<' } else { b',' },
        0x37 => if shifted { b'>' } else { b'.' },
        0x38 => if shifted { b'?' } else { b'/' },
        _ => 0,
    }
}

fn letter(scancode: u8, upper: bool) -> u8 {
    let base = if upper { b'A' } else { b'a' };
    base + (scancode - 0x04)
}

fn digit(scancode: u8, shifted: bool) -> u8 {
    let plain = b"1234567890"[(scancode - 0x1e) as usize];
    if !shifted {
        return plain;
    }
    b"!@#$%^&*()"[(scancode - 0x1e) as usize]
}
