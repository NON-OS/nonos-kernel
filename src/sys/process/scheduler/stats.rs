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
use super::state::{TASKS, TASK_COUNT, CONTEXT_SWITCHES, TIME_QUANTUM, SCHEDULER_POLICY};
use super::policy::SchedulerPolicy;
use super::super::{TaskState, MAX_TASKS};

#[derive(Debug, Clone, Copy)]
pub struct TaskStats {
    pub run_time: u64,
    pub switch_count: u64,
    pub priority: u8,
    pub state: TaskState,
}

#[derive(Debug, Clone, Copy)]
pub struct SchedulerStats {
    pub active_tasks: u32,
    pub ready_tasks: u32,
    pub running_tasks: u32,
    pub sleeping_tasks: u32,
    pub blocked_tasks: u32,
    pub context_switches: u64,
    pub policy: SchedulerPolicy,
    pub quantum_us: u64,
}

pub fn context_switch_count() -> u64 {
    CONTEXT_SWITCHES.load(Ordering::Relaxed)
}

pub fn set_time_quantum_us(us: u64) {
    let tsc_freq = crate::sys::timer::tsc_frequency();
    let ticks = (tsc_freq * us) / 1_000_000;
    TIME_QUANTUM.store(ticks, Ordering::SeqCst);
}

pub fn get_time_quantum_us() -> u64 {
    let ticks = TIME_QUANTUM.load(Ordering::Relaxed);
    let tsc_freq = crate::sys::timer::tsc_frequency();
    if tsc_freq > 0 {
        (ticks * 1_000_000) / tsc_freq
    } else {
        10_000
    }
}

pub fn get_task_stats(task_id: u32) -> Option<TaskStats> {
    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].id == task_id && TASKS[i].state != TaskState::Empty {
                return Some(TaskStats {
                    run_time: TASKS[i].run_time,
                    switch_count: TASKS[i].switch_count,
                    priority: TASKS[i].priority,
                    state: TASKS[i].state,
                });
            }
        }
    }
    None
}

pub fn get_scheduler_stats() -> SchedulerStats {
    let active = TASK_COUNT.load(Ordering::Relaxed);
    let mut ready = 0u32;
    let mut running = 0u32;
    let mut sleeping = 0u32;
    let mut blocked = 0u32;

    unsafe {
        for i in 0..MAX_TASKS {
            match TASKS[i].state {
                TaskState::Ready => ready += 1,
                TaskState::Running => running += 1,
                TaskState::Sleeping => sleeping += 1,
                TaskState::Blocked => blocked += 1,
                _ => {}
            }
        }
    }

    SchedulerStats {
        active_tasks: active,
        ready_tasks: ready,
        running_tasks: running,
        sleeping_tasks: sleeping,
        blocked_tasks: blocked,
        context_switches: CONTEXT_SWITCHES.load(Ordering::Relaxed),
        policy: SchedulerPolicy::from_u8(SCHEDULER_POLICY.load(Ordering::Relaxed)),
        quantum_us: get_time_quantum_us(),
    }
}

pub fn get_task_info_extended(id: u32) -> Option<(TaskState, &'static [u8], u8, u64, u64)> {
    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].id == id && TASKS[i].state != TaskState::Empty {
                return Some((
                    TASKS[i].state,
                    TASKS[i].get_name(),
                    TASKS[i].priority,
                    TASKS[i].run_time,
                    TASKS[i].switch_count,
                ));
            }
        }
    }
    None
}
