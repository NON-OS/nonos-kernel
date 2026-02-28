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

use super::state::{ACTIVE_TIMERS, HPET_BASE, TSC_FREQUENCY};
use super::time::now_ns;

pub struct TimerStats {
    pub tsc_frequency: u64,
    pub active_timers: usize,
    pub hpet_available: bool,
    pub uptime_ns: u64,
}

pub fn get_timer_stats() -> TimerStats {
    TimerStats {
        tsc_frequency: TSC_FREQUENCY.load(Ordering::Relaxed),
        active_timers: ACTIVE_TIMERS.lock().len(),
        hpet_available: HPET_BASE.load(Ordering::Relaxed) != 0,
        uptime_ns: now_ns(),
    }
}
