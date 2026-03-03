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


pub const VGA_BUFFER_ADDR: usize = 0xB8000;

pub const VGA_WIDTH: usize = 80;

pub const VGA_HEIGHT: usize = 25;

pub const VGA_CELLS: usize = VGA_WIDTH * VGA_HEIGHT;

pub const VGA_BUFFER_SIZE: usize = VGA_CELLS * 2;

pub const VGA_CRTC_INDEX: u16 = 0x3D4;

pub const VGA_CRTC_DATA: u16 = 0x3D5;

pub const CRTC_CURSOR_LOW: u8 = 0x0F;

pub const CRTC_CURSOR_HIGH: u8 = 0x0E;

pub const DEFAULT_FG: u8 = 0x07;

pub const DEFAULT_BG: u8 = 0x00;

pub const DEFAULT_COLOR: u8 = (DEFAULT_BG << 4) | DEFAULT_FG;

pub const ASCII_ESC: u8 = 0x1B;

pub const ASCII_NEWLINE: u8 = b'\n';

pub const ASCII_CR: u8 = b'\r';

pub const ASCII_SPACE: u8 = 0x20;

pub const ASCII_TILDE: u8 = 0x7E;

pub const ASCII_LBRACKET: u8 = b'[';

pub const ASCII_TAB: u8 = b'\t';

pub const ASCII_BACKSPACE: u8 = 0x08;

pub const ASCII_BELL: u8 = 0x07;

pub const ASCII_FORM_FEED: u8 = 0x0C;

pub const ASCII_DELETE: u8 = 0x7F;

pub const TAB_WIDTH: usize = 8;

pub const CRTC_CURSOR_START: u8 = 0x0A;

pub const CRTC_CURSOR_END: u8 = 0x0B;

pub const CURSOR_DISABLE: u8 = 0x20;

pub const DEFAULT_CURSOR_START: u8 = 0;

pub const DEFAULT_CURSOR_END: u8 = 15;

pub const ERROR_COLOR: u8 = 0x0C;

pub const WARNING_COLOR: u8 = 0x0E;

pub const SUCCESS_COLOR: u8 = 0x0A;

pub const INFO_COLOR: u8 = 0x0B;

pub const HIGHLIGHT_COLOR: u8 = 0x1F;

pub const DIM_COLOR: u8 = 0x08;

#[inline]
pub const fn is_valid_row(row: usize) -> bool {
    row < VGA_HEIGHT
}

#[inline]
pub const fn is_valid_col(col: usize) -> bool {
    col < VGA_WIDTH
}

#[inline]
pub const fn is_valid_position(row: usize, col: usize) -> bool {
    row < VGA_HEIGHT && col < VGA_WIDTH
}

#[inline]
pub const fn position_to_offset(row: usize, col: usize) -> usize {
    row * VGA_WIDTH + col
}

#[inline]
pub const fn position_to_byte_offset(row: usize, col: usize) -> usize {
    (row * VGA_WIDTH + col) * 2
}

#[inline]
pub const fn offset_to_position(offset: usize) -> (usize, usize) {
    (offset / VGA_WIDTH, offset % VGA_WIDTH)
}

#[inline]
pub const fn is_printable(ch: u8) -> bool {
    ch >= ASCII_SPACE && ch <= ASCII_TILDE
}

#[inline]
pub const fn is_control(ch: u8) -> bool {
    ch < ASCII_SPACE || ch == ASCII_DELETE
}

#[inline]
pub const fn next_tab_stop(col: usize) -> usize {
    ((col / TAB_WIDTH) + 1) * TAB_WIDTH
}
