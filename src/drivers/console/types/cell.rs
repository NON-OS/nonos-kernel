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

use super::color::{make_color, Color};

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct VgaCell {
    pub ascii: u8,
    pub color: u8,
}

impl VgaCell {
    #[inline]
    pub const fn new(ascii: u8, color: u8) -> Self {
        Self { ascii, color }
    }

    #[inline]
    pub const fn blank(color: u8) -> Self {
        Self { ascii: b' ', color }
    }

    #[inline]
    pub const fn with_colors(ascii: u8, fg: Color, bg: Color) -> Self {
        Self {
            ascii,
            color: make_color(fg, bg),
        }
    }

    #[inline]
    pub const fn fg(&self) -> Color {
        Color::from_u8(self.color & 0x0F)
    }

    #[inline]
    pub const fn bg(&self) -> Color {
        Color::from_u8((self.color >> 4) & 0x07)
    }

    #[inline]
    pub const fn is_blank(&self) -> bool {
        self.ascii == b' '
    }

    #[inline]
    pub const fn as_u16(&self) -> u16 {
        (self.color as u16) << 8 | (self.ascii as u16)
    }

    #[inline]
    pub const fn from_u16(value: u16) -> Self {
        Self {
            ascii: (value & 0xFF) as u8,
            color: ((value >> 8) & 0xFF) as u8,
        }
    }
}

impl Default for VgaCell {
    fn default() -> Self {
        Self::blank(make_color(Color::LightGrey, Color::Black))
    }
}

impl core::fmt::Debug for VgaCell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let ascii = { self.ascii };
        let color = { self.color };
        f.debug_struct("VgaCell")
            .field("ascii", &(ascii as char))
            .field("color", &color)
            .field("fg", &Color::from_u8(color & 0x0F).name())
            .field("bg", &Color::from_u8((color >> 4) & 0x07).name())
            .finish()
    }
}
