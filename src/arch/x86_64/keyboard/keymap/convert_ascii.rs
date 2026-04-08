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

use crate::arch::x86_64::keyboard::types::KeyCode;

pub fn ascii_to_keycode(ascii: u8) -> KeyCode {
    match ascii {
        b'a' | b'A' => KeyCode::A, b'b' | b'B' => KeyCode::B, b'c' | b'C' => KeyCode::C,
        b'd' | b'D' => KeyCode::D, b'e' | b'E' => KeyCode::E, b'f' | b'F' => KeyCode::F,
        b'g' | b'G' => KeyCode::G, b'h' | b'H' => KeyCode::H, b'i' | b'I' => KeyCode::I,
        b'j' | b'J' => KeyCode::J, b'k' | b'K' => KeyCode::K, b'l' | b'L' => KeyCode::L,
        b'm' | b'M' => KeyCode::M, b'n' | b'N' => KeyCode::N, b'o' | b'O' => KeyCode::O,
        b'p' | b'P' => KeyCode::P, b'q' | b'Q' => KeyCode::Q, b'r' | b'R' => KeyCode::R,
        b's' | b'S' => KeyCode::S, b't' | b'T' => KeyCode::T, b'u' | b'U' => KeyCode::U,
        b'v' | b'V' => KeyCode::V, b'w' | b'W' => KeyCode::W, b'x' | b'X' => KeyCode::X,
        b'y' | b'Y' => KeyCode::Y, b'z' | b'Z' => KeyCode::Z,
        b'0' | b')' => KeyCode::Num0, b'1' | b'!' => KeyCode::Num1, b'2' | b'@' => KeyCode::Num2,
        b'3' | b'#' => KeyCode::Num3, b'4' | b'$' => KeyCode::Num4, b'5' | b'%' => KeyCode::Num5,
        b'6' | b'^' => KeyCode::Num6, b'7' | b'&' => KeyCode::Num7, b'8' | b'*' => KeyCode::Num8,
        b'9' | b'(' => KeyCode::Num9,
        b'-' | b'_' => KeyCode::Minus, b'=' | b'+' => KeyCode::Equals,
        b'[' | b'{' => KeyCode::LeftBracket, b']' | b'}' => KeyCode::RightBracket,
        b'\\' | b'|' => KeyCode::Backslash, b';' | b':' => KeyCode::Semicolon,
        b'\'' | b'"' => KeyCode::Quote, b'`' | b'~' => KeyCode::Backtick,
        b',' | b'<' => KeyCode::Comma, b'.' | b'>' => KeyCode::Period, b'/' | b'?' => KeyCode::Slash,
        _ => KeyCode::Unknown,
    }
}
