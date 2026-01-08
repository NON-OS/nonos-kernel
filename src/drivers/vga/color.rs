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

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Black = 0x0,
    Blue = 0x1,
    Green = 0x2,
    Cyan = 0x3,
    Red = 0x4,
    Magenta = 0x5,
    Brown = 0x6,
    LightGrey = 0x7,
    DarkGrey = 0x8,
    LightBlue = 0x9,
    LightGreen = 0xA,
    LightCyan = 0xB,
    LightRed = 0xC,
    Pink = 0xD,
    Yellow = 0xE,
    White = 0xF,
}

impl Color {
    #[inline]
    pub fn from_u8(n: u8) -> Color {
        match n & 0x0F {
            0x0 => Color::Black,
            0x1 => Color::Blue,
            0x2 => Color::Green,
            0x3 => Color::Cyan,
            0x4 => Color::Red,
            0x5 => Color::Magenta,
            0x6 => Color::Brown,
            0x7 => Color::LightGrey,
            0x8 => Color::DarkGrey,
            0x9 => Color::LightBlue,
            0xA => Color::LightGreen,
            0xB => Color::LightCyan,
            0xC => Color::LightRed,
            0xD => Color::Pink,
            0xE => Color::Yellow,
            _ => Color::White,
        }
    }

    #[inline]
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn name(&self) -> &'static str {
        match self {
            Color::Black => "Black",
            Color::Blue => "Blue",
            Color::Green => "Green",
            Color::Cyan => "Cyan",
            Color::Red => "Red",
            Color::Magenta => "Magenta",
            Color::Brown => "Brown",
            Color::LightGrey => "LightGrey",
            Color::DarkGrey => "DarkGrey",
            Color::LightBlue => "LightBlue",
            Color::LightGreen => "LightGreen",
            Color::LightCyan => "LightCyan",
            Color::LightRed => "LightRed",
            Color::Pink => "Pink",
            Color::Yellow => "Yellow",
            Color::White => "White",
        }
    }

    #[inline]
    pub fn is_bright(&self) -> bool {
        (*self as u8) >= 0x8
    }
}

#[inline(always)]
pub const fn vga_color(fg: Color, bg: Color) -> u8 {
    ((bg as u8) << 4) | (fg as u8 & 0x0F)
}

#[inline]
pub fn decode_color(attr: u8) -> (Color, Color) {
    let fg = Color::from_u8(attr & 0x0F);
    let bg = Color::from_u8((attr >> 4) & 0x0F);
    (fg, bg)
}

pub const DEFAULT_FG: Color = Color::LightGrey;
pub const DEFAULT_BG: Color = Color::Black;
pub const DEFAULT_COLOR: u8 = vga_color(DEFAULT_FG, DEFAULT_BG);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vga_color() {
        assert_eq!(vga_color(Color::White, Color::Black), 0x0F);
        assert_eq!(vga_color(Color::Black, Color::White), 0xF0);
        assert_eq!(vga_color(Color::LightGrey, Color::Black), 0x07);
    }

    #[test]
    fn test_decode_color() {
        let (fg, bg) = decode_color(0x0F);
        assert_eq!(fg, Color::White);
        assert_eq!(bg, Color::Black);

        let (fg, bg) = decode_color(0x74);
        assert_eq!(fg, Color::Red);
        assert_eq!(bg, Color::LightGrey);
    }

    #[test]
    fn test_color_from_u8() {
        assert_eq!(Color::from_u8(0), Color::Black);
        assert_eq!(Color::from_u8(15), Color::White);
        assert_eq!(Color::from_u8(16), Color::Black);
    }

    #[test]
    fn test_color_is_bright() {
        assert!(!Color::Black.is_bright());
        assert!(!Color::Blue.is_bright());
        assert!(Color::DarkGrey.is_bright());
        assert!(Color::White.is_bright());
    }
}
