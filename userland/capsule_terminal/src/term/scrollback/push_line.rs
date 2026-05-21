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

use super::types::Scrollback;
use crate::term::dimensions::{COLS, SCROLLBACK_ROWS};

impl Scrollback {
    pub fn push_line(&mut self, line: &[u8]) {
        let slot = (self.head + self.count) % SCROLLBACK_ROWS;
        let n = line.len().min(COLS);
        self.rows[slot][..n].copy_from_slice(&line[..n]);
        self.lengths[slot] = n as u16;
        if self.count == SCROLLBACK_ROWS {
            self.head = (self.head + 1) % SCROLLBACK_ROWS;
        } else {
            self.count += 1;
        }
        self.view_offset = 0;
    }
}
