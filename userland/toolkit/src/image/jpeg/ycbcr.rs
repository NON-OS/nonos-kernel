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

fn clamp_u8(x: i32) -> u8 {
    if x < 0 {
        0
    } else if x > 255 {
        255
    } else {
        x as u8
    }
}

pub fn ycbcr_to_argb8888(y: u8, cb: u8, cr: u8) -> u32 {
    let yi = y as i32;
    let cbi = cb as i32 - 128;
    let cri = cr as i32 - 128;
    let r = yi + ((91881 * cri + 32768) >> 16);
    let g = yi - ((22554 * cbi + 46802 * cri + 32768) >> 16);
    let b = yi + ((116130 * cbi + 32768) >> 16);
    let r8 = clamp_u8(r) as u32;
    let g8 = clamp_u8(g) as u32;
    let b8 = clamp_u8(b) as u32;
    0xFF00_0000 | (r8 << 16) | (g8 << 8) | b8
}

pub fn gray_to_argb8888(y: u8) -> u32 {
    let v = y as u32;
    0xFF00_0000 | (v << 16) | (v << 8) | v
}
