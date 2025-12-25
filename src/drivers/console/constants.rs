// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! VGA text mode constants.
//! Standard VGA text mode uses a fixed memory buffer at 0xB8000
//! with 80x25 character cells, each cell being 2 bytes (char + attr).
//!
//! # Memory Layout
//! The VGA text buffer occupies 4000 bytes (80 × 25 × 2). Each cell consists
//! of an ASCII character byte followed by an attribute byte:
//!
/// VGA text mode buffer physical address.
/// The VGA text buffer is memory-mapped at this fixed address in the
/// legacy PC memory map. Each character cell is 2 bytes.
///
/// This address is part of the legacy VGA memory map:
/// - 0xA0000-0xAFFFF: VGA graphics mode
/// - 0xB0000-0xB7FFF: MDA text mode (monochrome)
/// - 0xB8000-0xBFFFF: CGA/VGA text mode (color)

pub const VGA_BUFFER_ADDR: usize = 0xB8000;

/// Number of columns in VGA text mode.
pub const VGA_WIDTH: usize = 80;

/// Number of rows in VGA text mode.
pub const VGA_HEIGHT: usize = 25;

/// Total number of character cells.
pub const VGA_CELLS: usize = VGA_WIDTH * VGA_HEIGHT;

/// Size of VGA text buffer in bytes.
pub const VGA_BUFFER_SIZE: usize = VGA_CELLS * 2;

// =============================================================================
// VGA CRT Controller Ports
// =============================================================================

/// VGA CRT controller index port.
pub const VGA_CRTC_INDEX: u16 = 0x3D4;

/// VGA CRT controller data port.
pub const VGA_CRTC_DATA: u16 = 0x3D5;

/// CRT controller register: cursor location low byte.
pub const CRTC_CURSOR_LOW: u8 = 0x0F;

/// CRT controller register: cursor location high byte.
pub const CRTC_CURSOR_HIGH: u8 = 0x0E;

// =============================================================================
// Default Colors
// =============================================================================

/// Default foreground color (light grey).
pub const DEFAULT_FG: u8 = 0x07;

/// Default background color (black).
pub const DEFAULT_BG: u8 = 0x00;

/// Default color attribute (light grey on black).
pub const DEFAULT_COLOR: u8 = (DEFAULT_BG << 4) | DEFAULT_FG;

// =============================================================================
// ASCII Constants
// =============================================================================

/// ASCII escape character (starts ANSI sequences).
pub const ASCII_ESC: u8 = 0x1B;

/// ASCII newline.
pub const ASCII_NEWLINE: u8 = b'\n';

/// ASCII carriage return.
pub const ASCII_CR: u8 = b'\r';

/// ASCII space (first printable character).
pub const ASCII_SPACE: u8 = 0x20;

/// ASCII tilde (last printable character).
pub const ASCII_TILDE: u8 = 0x7E;

/// ASCII left bracket (CSI introducer).
pub const ASCII_LBRACKET: u8 = b'[';

/// ASCII tab character.
pub const ASCII_TAB: u8 = b'\t';

/// ASCII backspace character.
pub const ASCII_BACKSPACE: u8 = 0x08;

/// ASCII bell character.
pub const ASCII_BELL: u8 = 0x07;

/// ASCII form feed (clear screen).
pub const ASCII_FORM_FEED: u8 = 0x0C;

/// ASCII delete character.
pub const ASCII_DELETE: u8 = 0x7F;

// =============================================================================
// Tab Configuration
// =============================================================================

/// Tab stop width in characters.
pub const TAB_WIDTH: usize = 8;

// =============================================================================
// Cursor Control Registers
// =============================================================================

/// CRT controller register: cursor start scanline.
pub const CRTC_CURSOR_START: u8 = 0x0A;

/// CRT controller register: cursor end scanline.
pub const CRTC_CURSOR_END: u8 = 0x0B;

/// Cursor disable bit (set in CRTC_CURSOR_START to hide cursor).
pub const CURSOR_DISABLE: u8 = 0x20;

/// Default cursor start scanline (block cursor).
pub const DEFAULT_CURSOR_START: u8 = 0;

/// Default cursor end scanline (block cursor, 15 for CGA, 7 for EGA/VGA).
pub const DEFAULT_CURSOR_END: u8 = 15;

// =============================================================================
// Color Constants
// =============================================================================

/// Error color (bright red on black).
pub const ERROR_COLOR: u8 = 0x0C;

/// Warning color (yellow on black).
pub const WARNING_COLOR: u8 = 0x0E;

/// Success color (light green on black).
pub const SUCCESS_COLOR: u8 = 0x0A;

/// Info color (light cyan on black).
pub const INFO_COLOR: u8 = 0x0B;

/// Highlight color (white on blue).
pub const HIGHLIGHT_COLOR: u8 = 0x1F;

/// Dim color (dark grey on black).
pub const DIM_COLOR: u8 = 0x08;

// =============================================================================
// Validation Functions
// =============================================================================

/// Checks if a row is within bounds.
#[inline]
pub const fn is_valid_row(row: usize) -> bool {
    row < VGA_HEIGHT
}

/// Checks if a column is within bounds.
#[inline]
pub const fn is_valid_col(col: usize) -> bool {
    col < VGA_WIDTH
}

/// Checks if a position is within screen bounds.
#[inline]
pub const fn is_valid_position(row: usize, col: usize) -> bool {
    row < VGA_HEIGHT && col < VGA_WIDTH
}

/// Calculates the linear offset for a position in the VGA buffer.
#[inline]
pub const fn position_to_offset(row: usize, col: usize) -> usize {
    row * VGA_WIDTH + col
}

/// Calculates the byte offset for a position in the VGA buffer.
#[inline]
pub const fn position_to_byte_offset(row: usize, col: usize) -> usize {
    (row * VGA_WIDTH + col) * 2
}

/// Converts a linear offset to (row, col).
#[inline]
pub const fn offset_to_position(offset: usize) -> (usize, usize) {
    (offset / VGA_WIDTH, offset % VGA_WIDTH)
}

/// Checks if a character is printable (0x20-0x7E).
#[inline]
pub const fn is_printable(ch: u8) -> bool {
    ch >= ASCII_SPACE && ch <= ASCII_TILDE
}

/// Checks if a character is a control character (0x00-0x1F or 0x7F).
#[inline]
pub const fn is_control(ch: u8) -> bool {
    ch < ASCII_SPACE || ch == ASCII_DELETE
}

/// Calculates the next tab stop position.
#[inline]
pub const fn next_tab_stop(col: usize) -> usize {
    ((col / TAB_WIDTH) + 1) * TAB_WIDTH
}
