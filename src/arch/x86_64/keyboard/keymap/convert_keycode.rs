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

use crate::arch::x86_64::keyboard::types::{KeyCode, Modifiers};

pub fn keycode_to_ascii(keycode: KeyCode, shifted: bool) -> Option<u8> {
    let mods = if shifted { Modifiers::from_bits(Modifiers::SHIFT) } else { Modifiers::NONE };
    keycode_to_ascii_with_mods(keycode, mods)
}

pub fn keycode_to_ascii_with_mods(keycode: KeyCode, modifiers: Modifiers) -> Option<u8> {
    if modifiers.ctrl() {
        return match keycode {
            KeyCode::A => Some(0x01), KeyCode::B => Some(0x02), KeyCode::C => Some(0x03),
            KeyCode::D => Some(0x04), KeyCode::E => Some(0x05), KeyCode::F => Some(0x06),
            KeyCode::G => Some(0x07), KeyCode::H => Some(0x08), KeyCode::I => Some(0x09),
            KeyCode::J => Some(0x0A), KeyCode::K => Some(0x0B), KeyCode::L => Some(0x0C),
            KeyCode::M => Some(0x0D), KeyCode::N => Some(0x0E), KeyCode::O => Some(0x0F),
            KeyCode::P => Some(0x10), KeyCode::Q => Some(0x11), KeyCode::R => Some(0x12),
            KeyCode::S => Some(0x13), KeyCode::T => Some(0x14), KeyCode::U => Some(0x15),
            KeyCode::V => Some(0x16), KeyCode::W => Some(0x17), KeyCode::X => Some(0x18),
            KeyCode::Y => Some(0x19), KeyCode::Z => Some(0x1A),
            KeyCode::LeftBracket => Some(0x1B), KeyCode::Backslash => Some(0x1C),
            KeyCode::RightBracket => Some(0x1D), _ => None,
        };
    }
    let shifted = if keycode.is_letter() { modifiers.effective_shift() } else { modifiers.shift() };
    keycode_to_ascii_shifted(keycode, shifted)
}

fn keycode_to_ascii_shifted(keycode: KeyCode, shifted: bool) -> Option<u8> {
    match keycode {
        KeyCode::A => Some(if shifted { b'A' } else { b'a' }),
        KeyCode::B => Some(if shifted { b'B' } else { b'b' }),
        KeyCode::C => Some(if shifted { b'C' } else { b'c' }),
        KeyCode::D => Some(if shifted { b'D' } else { b'd' }),
        KeyCode::E => Some(if shifted { b'E' } else { b'e' }),
        KeyCode::F => Some(if shifted { b'F' } else { b'f' }),
        KeyCode::G => Some(if shifted { b'G' } else { b'g' }),
        KeyCode::H => Some(if shifted { b'H' } else { b'h' }),
        KeyCode::I => Some(if shifted { b'I' } else { b'i' }),
        KeyCode::J => Some(if shifted { b'J' } else { b'j' }),
        KeyCode::K => Some(if shifted { b'K' } else { b'k' }),
        KeyCode::L => Some(if shifted { b'L' } else { b'l' }),
        KeyCode::M => Some(if shifted { b'M' } else { b'm' }),
        KeyCode::N => Some(if shifted { b'N' } else { b'n' }),
        KeyCode::O => Some(if shifted { b'O' } else { b'o' }),
        KeyCode::P => Some(if shifted { b'P' } else { b'p' }),
        KeyCode::Q => Some(if shifted { b'Q' } else { b'q' }),
        KeyCode::R => Some(if shifted { b'R' } else { b'r' }),
        KeyCode::S => Some(if shifted { b'S' } else { b's' }),
        KeyCode::T => Some(if shifted { b'T' } else { b't' }),
        KeyCode::U => Some(if shifted { b'U' } else { b'u' }),
        KeyCode::V => Some(if shifted { b'V' } else { b'v' }),
        KeyCode::W => Some(if shifted { b'W' } else { b'w' }),
        KeyCode::X => Some(if shifted { b'X' } else { b'x' }),
        KeyCode::Y => Some(if shifted { b'Y' } else { b'y' }),
        KeyCode::Z => Some(if shifted { b'Z' } else { b'z' }),
        _ => keycode_to_ascii_symbol(keycode, shifted),
    }
}

fn keycode_to_ascii_symbol(keycode: KeyCode, shifted: bool) -> Option<u8> {
    match keycode {
        KeyCode::Num0 => Some(if shifted { b')' } else { b'0' }),
        KeyCode::Num1 => Some(if shifted { b'!' } else { b'1' }),
        KeyCode::Num2 => Some(if shifted { b'@' } else { b'2' }),
        KeyCode::Num3 => Some(if shifted { b'#' } else { b'3' }),
        KeyCode::Num4 => Some(if shifted { b'$' } else { b'4' }),
        KeyCode::Num5 => Some(if shifted { b'%' } else { b'5' }),
        KeyCode::Num6 => Some(if shifted { b'^' } else { b'6' }),
        KeyCode::Num7 => Some(if shifted { b'&' } else { b'7' }),
        KeyCode::Num8 => Some(if shifted { b'*' } else { b'8' }),
        KeyCode::Num9 => Some(if shifted { b'(' } else { b'9' }),
        KeyCode::Space => Some(b' '), KeyCode::Enter => Some(b'\n'),
        KeyCode::Tab => Some(b'\t'), KeyCode::Backspace => Some(8), KeyCode::Escape => Some(0x1B),
        KeyCode::Minus => Some(if shifted { b'_' } else { b'-' }),
        KeyCode::Equals => Some(if shifted { b'+' } else { b'=' }),
        KeyCode::LeftBracket => Some(if shifted { b'{' } else { b'[' }),
        KeyCode::RightBracket => Some(if shifted { b'}' } else { b']' }),
        KeyCode::Backslash => Some(if shifted { b'|' } else { b'\\' }),
        KeyCode::Semicolon => Some(if shifted { b':' } else { b';' }),
        KeyCode::Quote => Some(if shifted { b'"' } else { b'\'' }),
        KeyCode::Backtick => Some(if shifted { b'~' } else { b'`' }),
        KeyCode::Comma => Some(if shifted { b'<' } else { b',' }),
        KeyCode::Period => Some(if shifted { b'>' } else { b'.' }),
        KeyCode::Slash => Some(if shifted { b'?' } else { b'/' }),
        _ => None,
    }
}
