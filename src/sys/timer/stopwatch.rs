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

use super::tsc::{rdtsc, ticks_to_us, ticks_to_ms};

pub struct Stopwatch {
    start_tsc: u64,
}

impl Stopwatch {
    pub fn start() -> Self {
        Self {
            start_tsc: rdtsc(),
        }
    }

    pub fn elapsed_us(&self) -> u64 {
        let elapsed = rdtsc().saturating_sub(self.start_tsc);
        ticks_to_us(elapsed)
    }

    pub fn elapsed_ms(&self) -> u64 {
        let elapsed = rdtsc().saturating_sub(self.start_tsc);
        ticks_to_ms(elapsed)
    }

    pub fn elapsed_ticks(&self) -> u64 {
        rdtsc().saturating_sub(self.start_tsc)
    }

    pub fn reset(&mut self) {
        self.start_tsc = rdtsc();
    }
}
