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

use super::tsc::{rdtsc, us_to_ticks, ms_to_ticks};

pub fn delay_us(us: u64) {
    let target_ticks = us_to_ticks(us);
    let start = rdtsc();

    while rdtsc().saturating_sub(start) < target_ticks {
        core::hint::spin_loop();
    }
}

pub fn delay_ms(ms: u64) {
    let target_ticks = ms_to_ticks(ms);
    let start = rdtsc();

    while rdtsc().saturating_sub(start) < target_ticks {
        core::hint::spin_loop();
    }
}

#[inline]
pub fn short_delay() {
    for _ in 0..10 {
        core::hint::spin_loop();
    }
}
