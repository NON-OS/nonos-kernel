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

pub const LABELS: [&[u8]; 4] = [b"dark mode", b"animations", b"sounds", b"telemetry"];

pub struct State {
    pub on: [bool; LABELS.len()],
    pub cursor: usize,
}

impl State {
    pub fn new() -> Self {
        State { on: [false; LABELS.len()], cursor: 0 }
    }

    pub fn next(&mut self) {
        self.cursor = (self.cursor + 1) % LABELS.len();
    }

    pub fn prev(&mut self) {
        self.cursor = (self.cursor + LABELS.len() - 1) % LABELS.len();
    }

    pub fn toggle(&mut self) {
        self.on[self.cursor] = !self.on[self.cursor];
    }
}
