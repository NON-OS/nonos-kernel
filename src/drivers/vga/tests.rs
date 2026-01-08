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

use super::*;

#[test]
fn test_vga_dimensions() {
    assert_eq!(VGA_WIDTH, 80);
    assert_eq!(VGA_HEIGHT, 25);
    assert_eq!(VGA_TOTAL_CELLS, 2000);
}

#[test]
fn test_vga_buffer_address() {
    assert_eq!(VGA_BUFFER_ADDR, 0xB8000);
}

#[test]
fn test_color_values() {
    assert_eq!(Color::Black as u8, 0);
    assert_eq!(Color::White as u8, 15);
    assert_eq!(Color::Blue as u8, 1);
    assert_eq!(Color::Red as u8, 4);
}

#[test]
fn test_vga_color_encoding() {
    assert_eq!(vga_color(Color::White, Color::Black), 0x0F);
    assert_eq!(vga_color(Color::Black, Color::White), 0xF0);
    assert_eq!(vga_color(Color::LightGrey, Color::Black), 0x07);
    assert_eq!(vga_color(Color::Yellow, Color::Blue), 0x1E);
}

#[test]
fn test_decode_color() {
    let (fg, bg) = decode_color(0x0F);
    assert_eq!(fg, Color::White);
    assert_eq!(bg, Color::Black);

    let (fg, bg) = decode_color(0xF0);
    assert_eq!(fg, Color::Black);
    assert_eq!(bg, Color::White);
}

#[test]
fn test_color_from_u8() {
    assert_eq!(Color::from_u8(0), Color::Black);
    assert_eq!(Color::from_u8(1), Color::Blue);
    assert_eq!(Color::from_u8(15), Color::White);
    assert_eq!(Color::from_u8(16), Color::Black);
    assert_eq!(Color::from_u8(255), Color::White);
}

#[test]
fn test_color_is_bright() {
    assert!(!Color::Black.is_bright());
    assert!(!Color::LightGrey.is_bright()); // 0x7 < 0x8
    assert!(Color::DarkGrey.is_bright()); // 0x8 >= 0x8
    assert!(Color::White.is_bright());
}

#[test]
fn test_color_names() {
    assert_eq!(Color::Black.name(), "Black");
    assert_eq!(Color::White.name(), "White");
    assert_eq!(Color::LightGrey.name(), "LightGrey");
}

#[test]
fn test_vga_cell() {
    let cell = VgaCell::new(b'X', 0x0F);
    assert_eq!(cell.ascii, b'X');
    assert_eq!(cell.color, 0x0F);
}

#[test]
fn test_vga_cell_blank() {
    let cell = VgaCell::blank(0x07);
    assert_eq!(cell.ascii, b' ');
    assert_eq!(cell.color, 0x07);
}

#[test]
fn test_get_size() {
    let (w, h) = get_size();
    assert_eq!(w, 80);
    assert_eq!(h, 25);
}

#[test]
fn test_default_colors() {
    assert_eq!(DEFAULT_FG, Color::LightGrey);
    assert_eq!(DEFAULT_BG, Color::Black);
    assert_eq!(DEFAULT_COLOR, 0x07);
}

#[test]
fn test_constants() {
    use constants::*;

    assert_eq!(CRT_INDEX_PORT, 0x3D4);
    assert_eq!(CRT_DATA_PORT, 0x3D5);

    assert_eq!(CRT_CURSOR_START, 0x0A);
    assert_eq!(CRT_CURSOR_END, 0x0B);
    assert_eq!(CRT_CURSOR_LOC_HIGH, 0x0E);
    assert_eq!(CRT_CURSOR_LOC_LOW, 0x0F);

    assert_eq!(CURSOR_DISABLE_BIT, 0x20);
}

#[test]
fn test_printable_range() {
    use constants::*;

    assert_eq!(PRINTABLE_START, 0x20);
    assert_eq!(PRINTABLE_END, 0x7E);

    assert!((PRINTABLE_START..=PRINTABLE_END).contains(&b' '));
    assert!((PRINTABLE_START..=PRINTABLE_END).contains(&b'A'));
    assert!((PRINTABLE_START..=PRINTABLE_END).contains(&b'~'));
    assert!(!(PRINTABLE_START..=PRINTABLE_END).contains(&b'\n'));
}
