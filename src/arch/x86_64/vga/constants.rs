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

pub const VGA_BUFFER_ADDR: usize = 0xB8000;
pub const SCREEN_WIDTH: usize = 80;
pub const SCREEN_HEIGHT: usize = 25;
pub const SCREEN_SIZE: usize = SCREEN_WIDTH * SCREEN_HEIGHT;
pub const BYTES_PER_CHAR: usize = 2;
pub const VGA_BUFFER_SIZE: usize = SCREEN_SIZE * BYTES_PER_CHAR;
pub const MAX_CONSOLES: usize = 4;
pub const SCROLLBACK_LINES: usize = 200;
// CRT Controller ports (internal)
pub(crate) const CRT_INDEX: u16 = 0x3D4;
pub(crate) const CRT_DATA: u16 = 0x3D5;
// Cursor registers (internal)
pub(crate) const CURSOR_HIGH: u8 = 0x0E;
pub(crate) const CURSOR_LOW: u8 = 0x0F;
pub(crate) const CURSOR_START: u8 = 0x0A;
pub(crate) const CURSOR_END: u8 = 0x0B;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

impl Color {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Black => "Black",
            Self::Blue => "Blue",
            Self::Green => "Green",
            Self::Cyan => "Cyan",
            Self::Red => "Red",
            Self::Magenta => "Magenta",
            Self::Brown => "Brown",
            Self::LightGray => "LightGray",
            Self::DarkGray => "DarkGray",
            Self::LightBlue => "LightBlue",
            Self::LightGreen => "LightGreen",
            Self::LightCyan => "LightCyan",
            Self::LightRed => "LightRed",
            Self::Pink => "Pink",
            Self::Yellow => "Yellow",
            Self::White => "White",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ColorCode(u8);

impl ColorCode {
    pub const fn new(foreground: Color, background: Color) -> Self {
        Self((background as u8) << 4 | (foreground as u8))
    }

    pub const fn with_blink(foreground: Color, background: Color) -> Self {
        Self(0x80 | (background as u8) << 4 | (foreground as u8))
    }

    pub const fn foreground(self) -> u8 {
        self.0 & 0x0F
    }

    pub const fn background(self) -> u8 {
        (self.0 >> 4) & 0x07
    }

    pub const fn is_blinking(self) -> bool {
        self.0 & 0x80 != 0
    }

    pub const fn value(self) -> u8 {
        self.0
    }
}

impl Default for ColorCode {
    fn default() -> Self {
        Self::new(Color::LightGray, Color::Black)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ScreenChar {
    pub character: u8,
    pub color: ColorCode,
}

impl ScreenChar {
    pub const fn new(character: u8, color: ColorCode) -> Self {
        Self { character, color }
    }

    pub const fn blank(color: ColorCode) -> Self {
        Self {
            character: b' ',
            color,
        }
    }

    pub const fn as_u16(self) -> u16 {
        (self.color.value() as u16) << 8 | (self.character as u16)
    }
}

impl Default for ScreenChar {
    fn default() -> Self {
        Self::blank(ColorCode::default())
    }
}
