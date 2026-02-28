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

use super::keycode::KeyCode;
use super::modifiers::Modifiers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMapping {
    pub keycode: KeyCode,
    pub ascii: u8,
    pub shifted_ascii: u8,
    pub extended: bool,
    pub printable: bool,
}

impl KeyMapping {
    pub const fn new(keycode: KeyCode, ascii: u8, shifted: u8, extended: bool, printable: bool) -> Self {
        Self {
            keycode,
            ascii,
            shifted_ascii: shifted,
            extended,
            printable,
        }
    }

    pub const fn non_printable(keycode: KeyCode, extended: bool) -> Self {
        Self {
            keycode,
            ascii: 0,
            shifted_ascii: 0,
            extended,
            printable: false,
        }
    }

    pub const fn unknown() -> Self {
        Self {
            keycode: KeyCode::Unknown,
            ascii: 0,
            shifted_ascii: 0,
            extended: false,
            printable: false,
        }
    }

    pub fn get_ascii(&self, modifiers: Modifiers) -> Option<u8> {
        if !self.printable {
            return None;
        }

        if modifiers.ctrl() {
            return self.ctrl_char();
        }

        let shifted = if self.keycode.is_letter() {
            modifiers.effective_shift()
        } else {
            modifiers.shift()
        };

        let ch = if shifted { self.shifted_ascii } else { self.ascii };
        if ch == 0 { None } else { Some(ch) }
    }

    fn ctrl_char(&self) -> Option<u8> {
        match self.ascii {
            b'a'..=b'z' => Some(self.ascii - b'a' + 1),
            b'[' => Some(0x1B),
            b'\\' => Some(0x1C),
            b']' => Some(0x1D),
            b'^' => Some(0x1E),
            b'_' => Some(0x1F),
            b'?' => Some(0x7F),
            _ => None,
        }
    }
}
