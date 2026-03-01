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
use super::state::{
    TASKS, SCHEDULER_POLICY, SCHEDULER_INIT, CURRENT_SLICE_END,
    lock_scheduler, unlock_scheduler
};
use super::policy::SchedulerPolicy;
use super::core::schedule;
use super::super::{TaskState, MAX_TASKS};

pub fn get_policy() -> SchedulerPolicy {
    SchedulerPolicy::from_u8(SCHEDULER_POLICY.load(Ordering::Relaxed))
}

pub fn set_policy(policy: SchedulerPolicy) {
    SCHEDULER_POLICY.store(policy as u8, Ordering::SeqCst);
}

pub fn set_task_priority(task_id: u32, priority: u8) -> bool {
    lock_scheduler();
    let result = unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].id == task_id && TASKS[i].state != TaskState::Empty {
                TASKS[i].priority = priority;
                unlock_scheduler();
                return true;
            }
        }
        false
    };
    unlock_scheduler();
    result
}

pub fn get_task_priority(task_id: u32) -> Option<u8> {
    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].id == task_id && TASKS[i].state != TaskState::Empty {
                return Some(TASKS[i].priority);
            }
        }
    }
    None
}

pub fn check_preempt() -> bool {
    let now = crate::sys::timer::rdtsc();
    let slice_end = CURRENT_SLICE_END.load(Ordering::Relaxed);
    now >= slice_end
}

pub fn timer_tick() {
    if !SCHEDULER_INIT.load(Ordering::Relaxed) {
        return;
    }

    if check_preempt() {
        schedule();
    }
}
