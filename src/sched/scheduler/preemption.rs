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

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use crate::sched::realtime;
use super::types::SchedulerStats;
use super::selection::{select_next_process, switch_to_process};

pub(super) static CURRENT_TIME_SLICE: AtomicU64 = AtomicU64::new(0);
pub(super) const DEFAULT_TIME_SLICE: u64 = 10;
pub(super) static SCHEDULER_STATS: SchedulerStats = SchedulerStats::new();
pub(super) static NEED_RESCHEDULE: AtomicBool = AtomicBool::new(false);

pub fn tick() {
    SCHEDULER_STATS.tick_count.fetch_add(1, Ordering::Relaxed);

    let remaining = CURRENT_TIME_SLICE.load(Ordering::Relaxed);
    if remaining > 0 {
        CURRENT_TIME_SLICE.store(remaining - 1, Ordering::Relaxed);
    }

    if remaining == 1 {
        SCHEDULER_STATS.time_slice_exhaustions.fetch_add(1, Ordering::Relaxed);
        preempt_current_process();
    }

    if realtime::has_realtime_tasks() {
        preempt_for_realtime();
    }
}

fn preempt_current_process() {
    use crate::process::nonos_core::{current_pid, PROCESS_TABLE, ProcessState};

    if let Some(current) = current_pid() {
        let ctx = crate::sched::Context::save();
        crate::process::nonos_core::save_interrupt_context(current, ctx);

        if let Some(pcb) = PROCESS_TABLE.find_by_pid(current) {
            let mut state = pcb.state.lock();
            if *state == ProcessState::Running {
                *state = ProcessState::Ready;
            }
        }
    }

    let next_pid = select_next_process();

    if let Some(next) = next_pid {
        SCHEDULER_STATS.context_switches.fetch_add(1, Ordering::Relaxed);
        SCHEDULER_STATS.preemptions.fetch_add(1, Ordering::Relaxed);
        switch_to_process(next);
    }
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

pub fn yield_now() {
    use crate::process::nonos_core::current_pid;

    SCHEDULER_STATS.voluntary_yields.fetch_add(1, Ordering::Relaxed);

    if let Some(pid) = current_pid() {
        let ctx = crate::sched::Context::save();
        crate::process::nonos_core::save_interrupt_context(pid, ctx);
    }

    CURRENT_TIME_SLICE.store(0, Ordering::Relaxed);

    if let Some(next) = select_next_process() {
        switch_to_process(next);
    }
}

pub fn need_reschedule() -> bool {
    NEED_RESCHEDULE.load(Ordering::Relaxed)
}

pub fn clear_reschedule() {
    NEED_RESCHEDULE.store(false, Ordering::Relaxed);
}
