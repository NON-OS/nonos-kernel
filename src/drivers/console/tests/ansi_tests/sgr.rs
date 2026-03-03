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

use crate::drivers::console::ansi::*;
use crate::drivers::console::types::*;

#[test]
fn test_apply_sgr_reset() {
    let current = make_color(Color::Red, Color::Blue);
    let result = apply_sgr(current, 0);
    assert_eq!(result, make_color(Color::LightGrey, Color::Black));
}

#[test]
fn test_apply_sgr_foreground() {
    let current = make_color(Color::LightGrey, Color::Black);
    let result = apply_sgr(current, 31);
    assert_eq!(fg_from_attr(result), Color::Red as u8);
    assert_eq!(bg_from_attr(result), Color::Black as u8);
}

#[test]
fn test_apply_sgr_background() {
    let current = make_color(Color::White, Color::Black);
    let result = apply_sgr(current, 44);
    assert_eq!(fg_from_attr(result), Color::White as u8);
    assert_eq!(bg_from_attr(result), Color::Blue as u8);
}

#[test]
fn test_apply_sgr_bright_foreground() {
    let current = make_color(Color::LightGrey, Color::Black);
    let result = apply_sgr(current, 91);
    assert_eq!(fg_from_attr(result), Color::LightRed as u8);
}

#[test]
fn test_apply_sgr_bright_background() {
    let current = make_color(Color::White, Color::Black);
    let result = apply_sgr(current, 104);
    assert_eq!(bg_from_attr(result), Color::LightBlue as u8);
}

#[test]
fn test_apply_sgr_bold() {
    let current = make_color(Color::Blue, Color::Black);
    let result = apply_sgr(current, 1);
    assert_eq!(fg_from_attr(result), 0x09);
}

#[test]
fn test_apply_sgr_unsupported() {
    let current = make_color(Color::White, Color::Black);
    let result = apply_sgr(current, 99);
    assert_eq!(result, current);
}
