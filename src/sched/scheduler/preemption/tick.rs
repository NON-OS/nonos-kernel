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
use crate::sched::realtime;
use super::state::{CURRENT_TIME_SLICE, SCHEDULER_STATS};
use super::switch::preempt_current_process;

pub fn tick() {
    SCHEDULER_STATS.tick_count.fetch_add(1, Ordering::Relaxed);
    let remaining = CURRENT_TIME_SLICE.load(Ordering::Relaxed);
    if remaining > 0 { CURRENT_TIME_SLICE.store(remaining - 1, Ordering::Relaxed); }
    if remaining == 1 {
        SCHEDULER_STATS.time_slice_exhaustions.fetch_add(1, Ordering::Relaxed);
        preempt_current_process();
    }
    if realtime::has_realtime_tasks() { preempt_for_realtime(); }
}

fn preempt_for_realtime() {
    use crate::process::nonos_core::current_pid;
    if let Some(current) = current_pid() {
        let ctx = crate::sched::Context::save();
        crate::process::nonos_core::save_interrupt_context(current, ctx);
    }
    realtime::run_realtime_tasks();
    SCHEDULER_STATS.preemptions.fetch_add(1, Ordering::Relaxed);
}
