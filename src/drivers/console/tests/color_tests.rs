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

#[test]
fn test_color_values() {
    assert_eq!(Color::Black as u8, 0x0);
    assert_eq!(Color::Blue as u8, 0x1);
    assert_eq!(Color::Green as u8, 0x2);
    assert_eq!(Color::Cyan as u8, 0x3);
    assert_eq!(Color::Red as u8, 0x4);
    assert_eq!(Color::Magenta as u8, 0x5);
    assert_eq!(Color::Brown as u8, 0x6);
    assert_eq!(Color::LightGrey as u8, 0x7);
    assert_eq!(Color::DarkGrey as u8, 0x8);
    assert_eq!(Color::LightBlue as u8, 0x9);
    assert_eq!(Color::LightGreen as u8, 0xA);
    assert_eq!(Color::LightCyan as u8, 0xB);
    assert_eq!(Color::LightRed as u8, 0xC);
    assert_eq!(Color::Pink as u8, 0xD);
    assert_eq!(Color::Yellow as u8, 0xE);
    assert_eq!(Color::White as u8, 0xF);
}

#[test]
fn test_color_default() {
    let color: Color = Color::default();
    assert_eq!(color, Color::LightGrey);
}

#[test]
fn test_color_from_ansi() {
    assert_eq!(Color::from_ansi(0), Color::Black);
    assert_eq!(Color::from_ansi(1), Color::Red);
    assert_eq!(Color::from_ansi(2), Color::Green);
    assert_eq!(Color::from_ansi(3), Color::Brown);
    assert_eq!(Color::from_ansi(4), Color::Blue);
    assert_eq!(Color::from_ansi(5), Color::Magenta);
    assert_eq!(Color::from_ansi(6), Color::Cyan);
    assert_eq!(Color::from_ansi(7), Color::LightGrey);
    assert_eq!(Color::from_ansi(8), Color::LightGrey);
}

#[test]
fn test_make_color() {
    assert_eq!(make_color(Color::LightGrey, Color::Black), 0x07);
    assert_eq!(make_color(Color::White, Color::Blue), 0x1F);
    assert_eq!(make_color(Color::Red, Color::Green), 0x24);
    assert_eq!(make_color(Color::Yellow, Color::Cyan), 0x3E);
}

#[test]
fn test_fg_from_attr() {
    assert_eq!(fg_from_attr(0x07), 0x07);
    assert_eq!(fg_from_attr(0x1F), 0x0F);
    assert_eq!(fg_from_attr(0x24), 0x04);
    assert_eq!(fg_from_attr(0xAB), 0x0B);
}

#[test]
fn test_bg_from_attr() {
    assert_eq!(bg_from_attr(0x07), 0x00);
    assert_eq!(bg_from_attr(0x1F), 0x01);
    assert_eq!(bg_from_attr(0x24), 0x02);
    assert_eq!(bg_from_attr(0xAB), 0x0A);
}

#[test]
fn test_set_fg() {
    let attr = make_color(Color::LightGrey, Color::Blue);
    let new_attr = set_fg(attr, Color::Red);
    assert_eq!(fg_from_attr(new_attr), Color::Red as u8);
    assert_eq!(bg_from_attr(new_attr), Color::Blue as u8);
}

#[test]
fn test_set_bg() {
    let attr = make_color(Color::White, Color::Black);
    let new_attr = set_bg(attr, Color::Green);
    assert_eq!(fg_from_attr(new_attr), Color::White as u8);
    assert_eq!(bg_from_attr(new_attr), Color::Green as u8);
}

#[test]
fn test_color_from_ansi_bright() {
    assert_eq!(Color::from_ansi_bright(0), Color::DarkGrey);
    assert_eq!(Color::from_ansi_bright(1), Color::LightRed);
    assert_eq!(Color::from_ansi_bright(2), Color::LightGreen);
    assert_eq!(Color::from_ansi_bright(3), Color::Yellow);
    assert_eq!(Color::from_ansi_bright(4), Color::LightBlue);
    assert_eq!(Color::from_ansi_bright(5), Color::Pink);
    assert_eq!(Color::from_ansi_bright(6), Color::LightCyan);
    assert_eq!(Color::from_ansi_bright(7), Color::White);
}

#[test]
fn test_color_from_u8() {
    assert_eq!(Color::from_u8(0x0), Color::Black);
    assert_eq!(Color::from_u8(0x1), Color::Blue);
    assert_eq!(Color::from_u8(0xF), Color::White);
    assert_eq!(Color::from_u8(0xFF), Color::LightGrey);
}

#[test]
fn test_color_as_u8() {
    assert_eq!(Color::Black.as_u8(), 0x0);
    assert_eq!(Color::White.as_u8(), 0xF);
}

#[test]
fn test_color_bright() {
    assert_eq!(Color::Black.bright(), Color::DarkGrey);
    assert_eq!(Color::Blue.bright(), Color::LightBlue);
    assert_eq!(Color::Brown.bright(), Color::Yellow);
    assert_eq!(Color::White.bright(), Color::White);
}

#[test]
fn test_color_dim() {
    assert_eq!(Color::DarkGrey.dim(), Color::Black);
    assert_eq!(Color::LightBlue.dim(), Color::Blue);
    assert_eq!(Color::Yellow.dim(), Color::Brown);
    assert_eq!(Color::Black.dim(), Color::Black);
}

#[test]
fn test_color_is_bright() {
    assert!(!Color::Black.is_bright());
    assert!(!Color::Blue.is_bright());
    assert!(Color::DarkGrey.is_bright());
    assert!(Color::White.is_bright());
}

#[test]
fn test_color_name() {
    assert_eq!(Color::Black.name(), "Black");
    assert_eq!(Color::White.name(), "White");
    assert_eq!(Color::LightGrey.name(), "LightGrey");
}
