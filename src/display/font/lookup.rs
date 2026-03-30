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

use super::glyphs_20::GLYPHS_20;
use super::glyphs_30::GLYPHS_30;
use super::glyphs_40::GLYPHS_40;
use super::glyphs_50::GLYPHS_50;
use super::glyphs_60::GLYPHS_60;
use super::glyphs_70::GLYPHS_70;

pub fn get_glyph(c: char) -> [u8; 16] {
    let code = c as u8;
    match code {
        0x20..=0x2F => GLYPHS_20[(code - 0x20) as usize],
        0x30..=0x3F => GLYPHS_30[(code - 0x30) as usize],
        0x40..=0x4F => GLYPHS_40[(code - 0x40) as usize],
        0x50..=0x5F => GLYPHS_50[(code - 0x50) as usize],
        0x60..=0x6F => GLYPHS_60[(code - 0x60) as usize],
        0x70..=0x7E => GLYPHS_70[(code - 0x70) as usize],
        _ => [0; 16],
    }
}
