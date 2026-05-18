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

pub const COLS: usize = 64;
pub const ROWS: usize = 6;

pub struct State {
    pub line: [u8; COLS],
    pub len: usize,
    pub hist: [[u8; COLS]; ROWS],
    pub hist_len: [usize; ROWS],
    pub rows: usize,
}

impl State {
    pub fn new() -> Self {
        State {
            line: [0; COLS],
            len: 0,
            hist: [[0; COLS]; ROWS],
            hist_len: [0; ROWS],
            rows: 0,
        }
    }

    pub fn commit_line(&mut self) {
        if self.rows < ROWS {
            self.hist[self.rows][..self.len].copy_from_slice(&self.line[..self.len]);
            self.hist_len[self.rows] = self.len;
            self.rows += 1;
        } else {
            for i in 1..ROWS {
                self.hist[i - 1] = self.hist[i];
                self.hist_len[i - 1] = self.hist_len[i];
            }
            self.hist[ROWS - 1][..self.len].copy_from_slice(&self.line[..self.len]);
            self.hist_len[ROWS - 1] = self.len;
        }
        self.len = 0;
    }
}
