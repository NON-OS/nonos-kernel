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

use crate::drivers::console::constants::*;

#[test]
fn test_ascii_constants() {
    assert_eq!(ASCII_ESC, 0x1B);
    assert_eq!(ASCII_NEWLINE, b'\n');
    assert_eq!(ASCII_CR, b'\r');
    assert_eq!(ASCII_SPACE, 0x20);
    assert_eq!(ASCII_TILDE, 0x7E);
    assert_eq!(ASCII_LBRACKET, b'[');
}

#[test]
fn test_additional_ascii_constants() {
    assert_eq!(ASCII_TAB, b'\t');
    assert_eq!(ASCII_BACKSPACE, 0x08);
    assert_eq!(ASCII_BELL, 0x07);
    assert_eq!(ASCII_FORM_FEED, 0x0C);
    assert_eq!(ASCII_DELETE, 0x7F);
}

#[test]
fn test_tab_width() {
    assert_eq!(TAB_WIDTH, 8);
}

#[test]
fn test_color_constants() {
    assert_eq!(ERROR_COLOR, 0x0C);
    assert_eq!(WARNING_COLOR, 0x0E);
    assert_eq!(SUCCESS_COLOR, 0x0A);
    assert_eq!(INFO_COLOR, 0x0B);
    assert_eq!(HIGHLIGHT_COLOR, 0x1F);
    assert_eq!(DIM_COLOR, 0x08);
}

#[test]
fn test_next_tab_stop() {
    assert_eq!(next_tab_stop(0), 8);
    assert_eq!(next_tab_stop(1), 8);
    assert_eq!(next_tab_stop(7), 8);
    assert_eq!(next_tab_stop(8), 16);
    assert_eq!(next_tab_stop(15), 16);
    assert_eq!(next_tab_stop(16), 24);
}

#[test]
fn test_is_valid_row() {
    assert!(is_valid_row(0));
    assert!(is_valid_row(24));
    assert!(!is_valid_row(25));
    assert!(!is_valid_row(100));
}

#[test]
fn test_is_valid_col() {
    assert!(is_valid_col(0));
    assert!(is_valid_col(79));
    assert!(!is_valid_col(80));
    assert!(!is_valid_col(100));
}

#[test]
fn test_is_valid_position() {
    assert!(is_valid_position(0, 0));
    assert!(is_valid_position(24, 79));
    assert!(!is_valid_position(25, 0));
    assert!(!is_valid_position(0, 80));
    assert!(!is_valid_position(25, 80));
}

#[test]
fn test_position_to_offset() {
    assert_eq!(position_to_offset(0, 0), 0);
    assert_eq!(position_to_offset(0, 1), 1);
    assert_eq!(position_to_offset(1, 0), 80);
    assert_eq!(position_to_offset(1, 1), 81);
    assert_eq!(position_to_offset(24, 79), 1999);
}

#[test]
fn test_offset_to_position() {
    assert_eq!(offset_to_position(0), (0, 0));
    assert_eq!(offset_to_position(1), (0, 1));
    assert_eq!(offset_to_position(80), (1, 0));
    assert_eq!(offset_to_position(81), (1, 1));
    assert_eq!(offset_to_position(1999), (24, 79));
}

#[test]
fn test_is_printable() {
    assert!(!is_printable(0x00));
    assert!(!is_printable(0x1F));
    assert!(is_printable(0x20));
    assert!(is_printable(b'A'));
    assert!(is_printable(0x7E));
    assert!(!is_printable(0x7F));
}

#[test]
fn test_is_control() {
    assert!(is_control(0x00));
    assert!(is_control(0x1F));
    assert!(!is_control(0x20));
    assert!(!is_control(b'A'));
    assert!(!is_control(0x7E));
    assert!(is_control(0x7F));
}
