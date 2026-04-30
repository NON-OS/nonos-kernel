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

use crate::sched::scheduler::types::SchedulerStats;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub static CURRENT_TIME_SLICE: AtomicU64 = AtomicU64::new(0);
pub const DEFAULT_TIME_SLICE: u64 = 10;
pub(crate) static SCHEDULER_STATS: SchedulerStats = SchedulerStats::new();
pub static NEED_RESCHEDULE: AtomicBool = AtomicBool::new(false);

pub fn need_reschedule() -> bool {
    NEED_RESCHEDULE.load(Ordering::Relaxed)
}
pub fn clear_reschedule() {
    NEED_RESCHEDULE.store(false, Ordering::Relaxed);
}
