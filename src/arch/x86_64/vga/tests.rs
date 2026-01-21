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
fn test_error_messages() {
    assert_eq!(VgaError::None.as_str(), "no error");
    assert_eq!(VgaError::NotInitialized.as_str(), "VGA not initialized");
}

#[test]
fn test_color_names() {
    assert_eq!(Color::Black.name(), "Black");
    assert_eq!(Color::White.name(), "White");
}

#[test]
fn test_color_code() {
    let cc = ColorCode::new(Color::White, Color::Blue);
    assert_eq!(cc.foreground(), 15);
    assert_eq!(cc.background(), 1);
    assert!(!cc.is_blinking());
}

#[test]
fn test_screen_char() {
    let sc = ScreenChar::new(b'A', ColorCode::default());
    assert_eq!(sc.character, b'A');
}

#[test]
fn test_constants() {
    assert_eq!(SCREEN_WIDTH, 80);
    assert_eq!(SCREEN_HEIGHT, 25);
    assert_eq!(SCREEN_SIZE, 2000);
}
