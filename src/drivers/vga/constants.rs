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
pub const VGA_WIDTH: usize = 80;
pub const VGA_HEIGHT: usize = 25;
pub const VGA_TOTAL_CELLS: usize = VGA_WIDTH * VGA_HEIGHT;
pub const VGA_BUFFER_SIZE: usize = VGA_TOTAL_CELLS * 2;
pub const CRT_INDEX_PORT: u16 = 0x3D4;
pub const CRT_DATA_PORT: u16 = 0x3D5;
pub const CRT_CURSOR_START: u8 = 0x0A;
pub const CRT_CURSOR_END: u8 = 0x0B;
pub const CRT_CURSOR_LOC_HIGH: u8 = 0x0E;
pub const CRT_CURSOR_LOC_LOW: u8 = 0x0F;
pub const CURSOR_DISABLE_BIT: u8 = 0x20;
pub const CURSOR_START_MASK: u8 = 0x1F;
pub const CURSOR_END_MASK: u8 = 0x1F;
pub const DEFAULT_CURSOR_START: u8 = 0;
pub const DEFAULT_CURSOR_END: u8 = 15;
pub const SPACE_CHAR: u8 = b' ';
pub const BACKSPACE_CHAR: u8 = 0x08;
pub const PRINTABLE_START: u8 = 0x20;
pub const PRINTABLE_END: u8 = 0x7E;
