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

use core::sync::atomic::AtomicU64;

pub struct Scheduler {
    pub running_tasks: usize,
}

impl Scheduler {
    pub fn tick(&self) {
        super::preemption::tick();
    }
}

pub(super) struct SchedulerStats {
    pub context_switches: AtomicU64,
    pub preemptions: AtomicU64,
    pub voluntary_yields: AtomicU64,
    pub wakeups: AtomicU64,
    pub tick_count: AtomicU64,
    pub time_slice_exhaustions: AtomicU64,
}

impl SchedulerStats {
    pub(super) const fn new() -> Self {
        Self {
            context_switches: AtomicU64::new(0),
            preemptions: AtomicU64::new(0),
            voluntary_yields: AtomicU64::new(0),
            wakeups: AtomicU64::new(0),
            tick_count: AtomicU64::new(0),
            time_slice_exhaustions: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchedulerStatsSnapshot {
    pub context_switches: u64,
    pub preemptions: u64,
    pub voluntary_yields: u64,
    pub wakeups: u64,
    pub tick_count: u64,
    pub time_slice_exhaustions: u64,
    pub runnable_processes: usize,
    pub pending_tasks: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleTaskError {
    SpawnFailed,
    NotFound,
    TerminateFailed,
}

pub type ModuleTaskResult<T> = Result<T, ModuleTaskError>;
