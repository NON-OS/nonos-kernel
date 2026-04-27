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

use crate::input::keyboard::{self, KeyEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MenuAction {
    None,
    Up,
    Down,
    Left,
    Right,
    Select,
    Back,
    Skip,
}

pub(super) fn poll_menu_input() -> MenuAction {
    if let Some(event) = keyboard::poll_event() {
        return match event {
            KeyEvent::Up => MenuAction::Up,
            KeyEvent::Down => MenuAction::Down,
            KeyEvent::Left => MenuAction::Left,
            KeyEvent::Right => MenuAction::Right,
            KeyEvent::Enter => MenuAction::Select,
            KeyEvent::Escape | KeyEvent::Backspace => MenuAction::Back,
            _ => MenuAction::None,
        };
    }
    if let Some(ch) = keyboard::read_char() {
        return match ch {
            'k' | 'K' | 'w' | 'W' => MenuAction::Up,
            'j' | 'J' | 's' | 'S' => MenuAction::Down,
            'h' | 'H' | 'a' | 'A' => MenuAction::Left,
            'l' | 'L' | 'd' | 'D' => MenuAction::Right,
            ' ' | '\n' | '\r' => MenuAction::Select,
            'q' | 'Q' => MenuAction::Back,
            'n' | 'N' => MenuAction::Skip,
            _ => MenuAction::None,
        };
    }
    MenuAction::None
}
