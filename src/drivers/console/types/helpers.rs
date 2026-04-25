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

use super::color::Color;

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
