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

use super::colors;
use super::output::{buffer_size, VGA_HEIGHT, VGA_WIDTH};

#[test]
fn test_color_constants() {
    assert_eq!(colors::BLACK, 0x00);
    assert_eq!(colors::WHITE, 0x0F);
    assert_eq!(colors::LIGHT_CYAN, 0x0B);
    assert_eq!(colors::RED, 0x04);
    assert_eq!(colors::LIGHT_GREEN, 0x0A);
}

#[test]
fn test_vga_dimensions() {
    assert_eq!(VGA_WIDTH, 80);
    assert_eq!(VGA_HEIGHT, 25);
    assert_eq!(VGA_WIDTH * VGA_HEIGHT, 2000);
}

#[test]
fn test_buffer_size() {
    assert_eq!(buffer_size(), VGA_WIDTH * VGA_HEIGHT * 2);
    assert_eq!(buffer_size(), 4000);
}

#[test]
fn test_make_attr() {
    assert_eq!(colors::make_attr(colors::WHITE, colors::BLACK), 0x0F);
    assert_eq!(colors::make_attr(colors::BLACK, colors::WHITE), 0xF0);
    assert_eq!(colors::make_attr(colors::LIGHT_CYAN, colors::BLUE), 0x1B);
}

#[test]
fn test_fg_bg_extraction() {
    let attr = colors::make_attr(colors::YELLOW, colors::BLUE);
    assert_eq!(colors::fg_color(attr), colors::YELLOW);
    assert_eq!(colors::bg_color(attr), colors::BLUE);
}
