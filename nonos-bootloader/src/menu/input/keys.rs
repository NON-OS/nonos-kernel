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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Up,
    Down,
    Select,
    Cancel,
    ShowMenu,
    None,
}

impl KeyAction {
    pub const fn from_scancode(scancode: u16) -> Self {
        match scancode {
            0x01 => Self::Up,
            0x02 => Self::Down,
            0x17 => Self::Cancel,
            _ => Self::None,
        }
    }

    pub const fn from_char(ch: char) -> Self {
        match ch {
            '\r' | '\n' => Self::Select,
            ' ' => Self::ShowMenu,
            'k' | 'K' => Self::Up,
            'j' | 'J' => Self::Down,
            'q' | 'Q' => Self::Cancel,
            _ => Self::None,
        }
    }
}
