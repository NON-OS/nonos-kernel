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

pub const BLACK: u8 = 0x00;
pub const BLUE: u8 = 0x01;
pub const GREEN: u8 = 0x02;
pub const CYAN: u8 = 0x03;
pub const RED: u8 = 0x04;
pub const MAGENTA: u8 = 0x05;
pub const BROWN: u8 = 0x06;
pub const LIGHT_GRAY: u8 = 0x07;
pub const DARK_GRAY: u8 = 0x08;
pub const LIGHT_BLUE: u8 = 0x09;
pub const LIGHT_GREEN: u8 = 0x0A;
pub const LIGHT_CYAN: u8 = 0x0B;
pub const LIGHT_RED: u8 = 0x0C;
pub const PINK: u8 = 0x0D;
pub const YELLOW: u8 = 0x0E;
pub const WHITE: u8 = 0x0F;
pub const fn make_attr(fg: u8, bg: u8) -> u8 {
    (bg << 4) | (fg & 0x0F)
}

pub const fn fg_color(attr: u8) -> u8 {
    attr & 0x0F
}

pub const fn bg_color(attr: u8) -> u8 {
    (attr >> 4) & 0x0F
}
