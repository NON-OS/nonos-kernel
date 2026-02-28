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

use super::timer::{get_system_timer_ticks, get_system_timer_frequency};

pub fn pit_sleep_ticks(ticks: u64) {
    let start = get_system_timer_ticks();
    while get_system_timer_ticks() - start < ticks {
        core::hint::spin_loop();
    }
}

pub fn pit_sleep_ms(ms: u64) {
    let frequency = get_system_timer_frequency() as u64;
    if frequency == 0 {
        for _ in 0..ms * 10000 {
            core::hint::spin_loop();
        }
        return;
    }

    let ticks = (ms * frequency) / 1000;
    pit_sleep_ticks(ticks);
}

pub fn pit_sleep_us(us: u64) {
    let frequency = get_system_timer_frequency() as u64;
    if frequency == 0 {
        for _ in 0..us * 10 {
            core::hint::spin_loop();
        }
        return;
    }

    let ticks = (us * frequency) / 1_000_000;
    if ticks == 0 {
        for _ in 0..us {
            core::hint::spin_loop();
        }
    } else {
        pit_sleep_ticks(ticks);
    }
}

pub fn pit_sleep(ms: u64) {
    pit_sleep_ms(ms);
}
