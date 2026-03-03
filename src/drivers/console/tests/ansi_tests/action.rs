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

#[test]
fn test_ansi_action_equality() {
    assert_eq!(AnsiAction::Print(b'A'), AnsiAction::Print(b'A'));
    assert_ne!(AnsiAction::Print(b'A'), AnsiAction::Print(b'B'));
    assert_eq!(AnsiAction::Sgr(31, None), AnsiAction::Sgr(31, None));
    assert_eq!(AnsiAction::Sgr(31, Some(44)), AnsiAction::Sgr(31, Some(44)));
    assert_ne!(AnsiAction::Sgr(31, None), AnsiAction::Sgr(32, None));
    assert_eq!(
        AnsiAction::CursorPosition(5, 10),
        AnsiAction::CursorPosition(5, 10)
    );
    assert_ne!(
        AnsiAction::CursorPosition(5, 10),
        AnsiAction::CursorPosition(5, 11)
    );
}

#[test]
fn test_ansi_action_is_cursor_action() {
    assert!(AnsiAction::CursorPosition(0, 0).is_cursor_action());
    assert!(AnsiAction::CursorUp(1).is_cursor_action());
    assert!(AnsiAction::SaveCursor.is_cursor_action());
    assert!(AnsiAction::RestoreCursor.is_cursor_action());
    assert!(!AnsiAction::Sgr(0, None).is_cursor_action());
    assert!(!AnsiAction::Print(b'A').is_cursor_action());
}

#[test]
fn test_ansi_action_is_sgr_action() {
    assert!(AnsiAction::Sgr(0, None).is_sgr_action());
    assert!(AnsiAction::Sgr(31, Some(44)).is_sgr_action());
    assert!(!AnsiAction::Print(b'A').is_sgr_action());
    assert!(!AnsiAction::CursorUp(1).is_sgr_action());
}

#[test]
fn test_ansi_action_is_erase_action() {
    assert!(AnsiAction::EraseDisplay(2).is_erase_action());
    assert!(AnsiAction::EraseLine(0).is_erase_action());
    assert!(!AnsiAction::Print(b'A').is_erase_action());
    assert!(!AnsiAction::CursorUp(1).is_erase_action());
}
