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

pub mod task;
pub mod runqueue;
pub mod context;
pub mod executor;
pub mod realtime;
pub mod deadline;
pub mod scheduler;
mod api;

#[cfg(test)]
#[cfg(test)]
mod tests;

pub use scheduler::{
    init, get, spawn, run, tick, wakeup, enter,
    add_to_run_queue, remove_from_run_queue, is_in_run_queue,
    runnable_process_count, get_runnable_pids, get_scheduler_stats,
    SchedulerStatsSnapshot, sleep_until, wake_process, is_sleeping,
    get_remaining_sleep, yield_now, need_reschedule, clear_reschedule,
};

pub use api::{current_scheduler, yield_cpu, schedule, current_cpu_id};
pub use task::{Task, Priority, CpuAffinity};
pub use runqueue::RunQueue;
pub use context::Context;
pub use executor::{spawn_async, poll_async_tasks, pending_async_tasks};
pub use realtime::{
    init as realtime_init, spawn_realtime, run_realtime_tasks,
    pending_realtime_tasks, has_realtime_tasks,
};
pub use deadline::{
    init as deadline_init, spawn_deadline, run_deadline_tasks,
    has_runnable as has_deadline_tasks, task_count as deadline_task_count,
    get_stats as get_deadline_stats, bandwidth_utilization,
    AdmissionError, DeadlineStatsSnapshot,
};
pub use scheduler::{
    init_smp_scheduler, init_ap_scheduler, smp_enabled, smp_cpu_count,
    local_queue_len, total_runnable, force_balance, get_smp_stats, SmpSchedStats,
};

pub fn get_cpu_stats() -> CpuStats { CpuStats::current() }
pub fn get_runnable_count() -> usize { runnable_process_count() }

#[derive(Default, Clone, Copy)]
pub struct CpuStats {
    pub user_time: u64,
    pub system_time: u64,
    pub idle_time: u64,
    pub iowait_time: u64,
    pub irq_time: u64,
    pub softirq_time: u64,
    pub steal_time: u64,
    pub guest_time: u64,
    pub guest_nice_time: u64,
    pub processes_created: u64,
    pub procs_running: u32,
    pub procs_blocked: u32,
    pub context_switches: u64,
}

impl CpuStats {
    pub fn current() -> Self {
        let stats = get_scheduler_stats();
        Self {
            user_time: crate::time::timestamp_millis() / 2,
            system_time: crate::time::timestamp_millis() / 4,
            idle_time: crate::time::timestamp_millis() / 4,
            iowait_time: 0, irq_time: 0, softirq_time: 0, steal_time: 0, guest_time: 0, guest_nice_time: 0,
            processes_created: stats.total_scheduled as u64,
            procs_running: stats.runnable_count as u32,
            procs_blocked: 0,
            context_switches: stats.total_scheduled as u64,
        }
    }
    pub fn total(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
        (self.user_time, 0, self.system_time, self.idle_time, self.iowait_time, self.irq_time, self.softirq_time, self.steal_time, self.guest_time, self.guest_nice_time)
    }
    pub fn total_idle_ns(&self) -> u64 { self.idle_time * 1_000_000 }
    pub fn per_cpu(&self) -> alloc::vec::Vec<CpuStats> { alloc::vec![*self] }
}
