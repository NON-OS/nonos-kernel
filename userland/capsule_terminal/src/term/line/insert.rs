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

use super::types::Line;
use crate::term::dimensions::COLS;

impl Line {
    pub fn insert(&mut self, byte: u8) -> bool {
        if self.len >= COLS {
            return false;
        }
        if self.cursor < self.len {
            self.buf.copy_within(self.cursor..self.len, self.cursor + 1);
        }
        self.buf[self.cursor] = byte;
        self.cursor += 1;
        self.len += 1;
        true
    }
}
