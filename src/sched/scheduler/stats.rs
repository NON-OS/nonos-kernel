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
use super::types::SchedulerStatsSnapshot;
use super::preemption::SCHEDULER_STATS;
use super::process::runnable_process_count;
use super::core::get_queue;

pub fn get_scheduler_stats() -> SchedulerStatsSnapshot {
    SchedulerStatsSnapshot {
        context_switches: SCHEDULER_STATS.context_switches.load(Ordering::Relaxed),
        preemptions: SCHEDULER_STATS.preemptions.load(Ordering::Relaxed),
        voluntary_yields: SCHEDULER_STATS.voluntary_yields.load(Ordering::Relaxed),
        wakeups: SCHEDULER_STATS.wakeups.load(Ordering::Relaxed),
        tick_count: SCHEDULER_STATS.tick_count.load(Ordering::Relaxed),
        time_slice_exhaustions: SCHEDULER_STATS.time_slice_exhaustions.load(Ordering::Relaxed),
        runnable_processes: runnable_process_count(),
        pending_tasks: get_queue().lock().len(),
    }
}
