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

extern crate alloc;

use crate::sched::scheduler::get_scheduler_stats;

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
            user_time: 0,
            system_time: 0,
            idle_time: 0,
            iowait_time: 0,
            irq_time: 0,
            softirq_time: 0,
            steal_time: 0,
            guest_time: 0,
            guest_nice_time: 0,
            processes_created: stats.total_scheduled as u64,
            procs_running: stats.runnable_count as u32,
            procs_blocked: 0,
            context_switches: stats.total_scheduled as u64,
        }
    }

    pub fn total(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
        (
            self.user_time,
            0,
            self.system_time,
            self.idle_time,
            self.iowait_time,
            self.irq_time,
            self.softirq_time,
            self.steal_time,
            self.guest_time,
            self.guest_nice_time,
        )
    }

    pub fn total_idle_ns(&self) -> u64 {
        self.idle_time * 1_000_000
    }

    pub fn per_cpu(&self) -> alloc::vec::Vec<CpuStats> {
        alloc::vec![*self]
    }
}

pub fn get_cpu_stats() -> CpuStats {
    CpuStats::current()
}
