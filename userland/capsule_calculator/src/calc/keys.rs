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

use super::op::Op;

pub enum Key {
    Digit(u8),
    Decimal,
    Operator(Op),
    Equals,
    Clear,
    Negate,
    Percent,
    Close,
    Ignored,
}

pub fn classify(code: u32) -> Key {
    if code > 0x7F {
        return Key::Ignored;
    }
    match code as u8 {
        b'0'..=b'9' => Key::Digit(code as u8 - b'0'),
        b'.' => Key::Decimal,
        b'+' => Key::Operator(Op::Add),
        b'-' => Key::Operator(Op::Sub),
        b'*' | b'x' | b'X' => Key::Operator(Op::Mul),
        b'/' => Key::Operator(Op::Div),
        b'=' | 0x0D => Key::Equals,
        b'c' | b'C' | 0x08 => Key::Clear,
        b'n' | b'N' => Key::Negate,
        b'%' => Key::Percent,
        0x1B => Key::Close,
        _ => Key::Ignored,
    }
}
