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
    pub const fn from_ansi(code: u8) -> Self {
        match code {
            0 => Color::Black,
            1 => Color::Red,
            2 => Color::Green,
            3 => Color::Brown,
            4 => Color::Blue,
            5 => Color::Magenta,
            6 => Color::Cyan,
            _ => Color::LightGrey,
        }
    }

    pub const fn from_ansi_bright(code: u8) -> Self {
        match code {
            0 => Color::DarkGrey,
            1 => Color::LightRed,
            2 => Color::LightGreen,
            3 => Color::Yellow,
            4 => Color::LightBlue,
            5 => Color::Pink,
            6 => Color::LightCyan,
            _ => Color::White,
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        match value {
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
            0xF => Color::White,
            _ => Color::LightGrey,
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn bright(self) -> Self {
        match self {
            Color::Black => Color::DarkGrey,
            Color::Blue => Color::LightBlue,
            Color::Green => Color::LightGreen,
            Color::Cyan => Color::LightCyan,
            Color::Red => Color::LightRed,
            Color::Magenta => Color::Pink,
            Color::Brown => Color::Yellow,
            Color::LightGrey => Color::White,
            other => other,
        }
    }

    pub const fn dim(self) -> Self {
        match self {
            Color::DarkGrey => Color::Black,
            Color::LightBlue => Color::Blue,
            Color::LightGreen => Color::Green,
            Color::LightCyan => Color::Cyan,
            Color::LightRed => Color::Red,
            Color::Pink => Color::Magenta,
            Color::Yellow => Color::Brown,
            Color::White => Color::LightGrey,
            other => other,
        }
    }

    #[inline]
    pub const fn is_bright(self) -> bool {
        (self as u8) >= 0x08
    }

    pub const fn name(self) -> &'static str {
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
}

impl Default for Color {
    fn default() -> Self {
        Color::LightGrey
    }
}

#[inline]
pub(crate) const fn make_color(fg: Color, bg: Color) -> u8 {
    ((bg as u8) << 4) | (fg as u8 & 0x0F)
}

#[inline]
pub(crate) const fn fg_from_attr(attr: u8) -> u8 {
    attr & 0x0F
}

#[inline]
pub(crate) const fn bg_from_attr(attr: u8) -> u8 {
    (attr >> 4) & 0x0F
}

#[inline]
pub(crate) const fn set_fg(attr: u8, fg: Color) -> u8 {
    (attr & 0xF0) | (fg as u8 & 0x0F)
}

#[inline]
pub(crate) const fn set_bg(attr: u8, bg: Color) -> u8 {
    ((bg as u8) << 4) | (attr & 0x0F)
}
