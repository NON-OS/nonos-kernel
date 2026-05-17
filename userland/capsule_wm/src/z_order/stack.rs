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

// Monotonic z-order counter. Each WINDOW_OPEN and WINDOW_RAISE bumps
// next_z and stamps the window with the new value, so windows()
// sorted by z is the bottom-to-top draw order. Wraparound is bounded
// (windows below the wrap line get re-stamped on the next raise).

pub struct ZStack {
    next_z: u32,
}

impl ZStack {
    pub const fn new() -> Self {
        Self { next_z: 1 }
    }

    pub fn allocate(&mut self) -> u32 {
        let z = self.next_z;
        self.next_z = self.next_z.checked_add(1).unwrap_or(1);
        z
    }
}
