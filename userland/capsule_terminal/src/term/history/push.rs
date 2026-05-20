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

use super::types::History;
use crate::term::dimensions::{COLS, HISTORY_DEPTH};

impl History {
    pub fn push(&mut self, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        if self.count > 0 {
            let last = self.count - 1;
            if &self.entries[last][..self.lengths[last]] == line {
                self.cursor = None;
                return;
            }
        }
        if self.count == HISTORY_DEPTH {
            for i in 1..HISTORY_DEPTH {
                self.entries[i - 1] = self.entries[i];
                self.lengths[i - 1] = self.lengths[i];
            }
            self.count = HISTORY_DEPTH - 1;
        }
        let slot = self.count;
        let n = line.len().min(COLS);
        self.entries[slot][..n].copy_from_slice(&line[..n]);
        self.lengths[slot] = n;
        self.count += 1;
        self.cursor = None;
    }
}
