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

use core::sync::atomic::Ordering;

use super::counters::COUNTERS;

pub struct InterruptStats {
    pub timer_ticks: u64,
    pub keyboard_presses: u64,
    pub mouse_events: u64,
    pub syscalls: u64,
    pub exceptions: u64,
    pub page_faults: u64,
}

pub fn get_stats() -> InterruptStats {
    InterruptStats {
        timer_ticks: COUNTERS.timer_ticks.load(Ordering::Relaxed),
        keyboard_presses: COUNTERS.keyboard_presses.load(Ordering::Relaxed),
        mouse_events: COUNTERS.mouse_events.load(Ordering::Relaxed),
        syscalls: COUNTERS.syscalls.load(Ordering::Relaxed),
        exceptions: COUNTERS.exceptions.load(Ordering::Relaxed),
        page_faults: COUNTERS.page_faults.load(Ordering::Relaxed),
    }
}

pub fn get_stats_tuple() -> (u64, u64, u64, u64) {
    (
        COUNTERS.timer_ticks.load(Ordering::Relaxed),
        COUNTERS.keyboard_presses.load(Ordering::Relaxed),
        COUNTERS.syscalls.load(Ordering::Relaxed),
        COUNTERS.exceptions.load(Ordering::Relaxed),
    )
}

pub fn reset_stats() {
    COUNTERS.timer_ticks.store(0, Ordering::Relaxed);
    COUNTERS.keyboard_presses.store(0, Ordering::Relaxed);
    COUNTERS.mouse_events.store(0, Ordering::Relaxed);
    COUNTERS.syscalls.store(0, Ordering::Relaxed);
    COUNTERS.exceptions.store(0, Ordering::Relaxed);
    COUNTERS.page_faults.store(0, Ordering::Relaxed);
}
