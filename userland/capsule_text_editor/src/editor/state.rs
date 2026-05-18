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

pub const CAPACITY: usize = 256;

pub struct State {
    pub buf: [u8; CAPACITY],
    pub len: usize,
}

impl State {
    pub fn new() -> Self {
        State { buf: [0; CAPACITY], len: 0 }
    }

    pub fn backspace(&mut self) -> bool {
        if self.len > 0 {
            self.len -= 1;
            return true;
        }
        false
    }

    pub fn insert(&mut self, byte: u8) -> bool {
        if self.len < CAPACITY {
            self.buf[self.len] = byte;
            self.len += 1;
            return true;
        }
        false
    }
}
