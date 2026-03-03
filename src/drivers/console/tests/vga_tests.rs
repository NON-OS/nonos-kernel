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

use crate::drivers::console::types::*;
use crate::drivers::console::constants::*;

#[test]
fn test_vga_cell_new() {
    let cell = VgaCell::new(b'A', 0x07);
    assert_eq!({ cell.ascii }, b'A');
    assert_eq!({ cell.color }, 0x07);
}

#[test]
fn test_vga_cell_blank() {
    let cell = VgaCell::blank(0x1F);
    assert_eq!({ cell.ascii }, b' ');
    assert_eq!({ cell.color }, 0x1F);
}

#[test]
fn test_vga_cell_default() {
    let cell = VgaCell::default();
    assert_eq!({ cell.ascii }, b' ');
    assert_eq!({ cell.color }, 0x07);
}

#[test]
fn test_vga_cell_size() {
    assert_eq!(core::mem::size_of::<VgaCell>(), 2);
}

#[test]
fn test_vga_dimensions() {
    assert_eq!(VGA_WIDTH, 80);
    assert_eq!(VGA_HEIGHT, 25);
    assert_eq!(VGA_CELLS, 80 * 25);
    assert_eq!(VGA_BUFFER_SIZE, 80 * 25 * 2);
}

#[test]
fn test_vga_buffer_address() {
    assert_eq!(VGA_BUFFER_ADDR, 0xB8000);
}

#[test]
fn test_crtc_ports() {
    assert_eq!(VGA_CRTC_INDEX, 0x3D4);
    assert_eq!(VGA_CRTC_DATA, 0x3D5);
}

#[test]
fn test_default_colors() {
    assert_eq!(DEFAULT_FG, 0x07);
    assert_eq!(DEFAULT_BG, 0x00);
    assert_eq!(DEFAULT_COLOR, 0x07);
}

#[test]
fn test_vga_buffer_bounds() {
    assert!(VGA_WIDTH <= 256);
    assert!(VGA_HEIGHT <= 256);
    assert!(VGA_CELLS <= u16::MAX as usize);
    assert!(VGA_BUFFER_SIZE <= u16::MAX as usize);
}

#[test]
fn test_cursor_position_bounds() {
    let max_pos = (VGA_HEIGHT - 1) * VGA_WIDTH + (VGA_WIDTH - 1);
    assert!(max_pos < u16::MAX as usize);
}

#[test]
fn test_vga_buffer_size_matches_cells() {
    assert_eq!(VGA_BUFFER_SIZE, VGA_CELLS * core::mem::size_of::<VgaCell>());
}

#[test]
fn test_vga_cell_with_colors() {
    let cell = VgaCell::with_colors(b'X', Color::White, Color::Blue);
    assert_eq!({ cell.ascii }, b'X');
    assert_eq!(cell.fg(), Color::White);
    assert_eq!(cell.bg(), Color::Blue);
}

#[test]
fn test_vga_cell_is_blank() {
    let blank = VgaCell::blank(0x07);
    let non_blank = VgaCell::new(b'A', 0x07);
    assert!(blank.is_blank());
    assert!(!non_blank.is_blank());
}

#[test]
fn test_vga_cell_as_u16() {
    let cell = VgaCell::new(b'A', 0x1F);
    assert_eq!(cell.as_u16(), 0x1F41);
}

#[test]
fn test_vga_cell_from_u16() {
    let cell = VgaCell::from_u16(0x1F41);
    assert_eq!({ cell.ascii }, b'A');
    assert_eq!({ cell.color }, 0x1F);
}
