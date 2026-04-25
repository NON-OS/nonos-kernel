// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pub const CHAR_WIDTH: u32 = 8;
pub const CHAR_HEIGHT: u32 = 16;

pub const SCALE_NORMAL: u32 = 1;
pub const SCALE_LARGE: u32 = 2;
pub const SCALE_XLARGE: u32 = 3;
pub const SCALE_HUGE: u32 = 4;

pub const LINE_HEIGHT_TIGHT: u32 = 16;
pub const LINE_HEIGHT_NORMAL: u32 = 20;
pub const LINE_HEIGHT_RELAXED: u32 = 24;
pub const LINE_HEIGHT_LOOSE: u32 = 32;

#[inline]
pub const fn text_width(text_len: usize) -> u32 {
    text_len as u32 * CHAR_WIDTH
}

#[inline]
pub const fn text_width_scaled(text_len: usize, scale: u32) -> u32 {
    text_len as u32 * CHAR_WIDTH * scale
}

#[inline]
pub const fn text_height_scaled(scale: u32) -> u32 {
    CHAR_HEIGHT * scale
}

#[inline]
pub const fn chars_that_fit(container_width: u32) -> usize {
    (container_width / CHAR_WIDTH) as usize
}

#[inline]
pub const fn center_text_x(container_width: u32, text_len: usize) -> u32 {
    let text_w = text_width(text_len);
    if container_width > text_w {
        (container_width - text_w) / 2
    } else {
        0
    }
}

#[inline]
pub const fn center_text_y(container_height: u32) -> u32 {
    if container_height > CHAR_HEIGHT {
        (container_height - CHAR_HEIGHT) / 2
    } else {
        0
    }
}
