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
    TASKS, CURRENT_TASK, TASK_COUNT, SCHEDULER_INIT, SCHEDULER_POLICY,
    lock_scheduler, unlock_scheduler
};
use super::policy::{SchedulerPolicy, find_next_round_robin, find_next_priority, find_next_fair};
use super::context::perform_context_switch;
use super::super::{TaskState, MAX_TASKS};

pub fn init() {
    if SCHEDULER_INIT.load(Ordering::Relaxed) {
        return;
    }

    lock_scheduler();

    unsafe {
        TASKS[0].id = 0;
        TASKS[0].state = TaskState::Running;
        TASKS[0].set_name(b"kernel_main");
        TASKS[0].priority = 0;
        TASKS[0].stack_base = 0;
        TASKS[0].stack_size = 0;
    }

    CURRENT_TASK.store(0, Ordering::SeqCst);
    TASK_COUNT.store(1, Ordering::SeqCst);
    SCHEDULER_INIT.store(true, Ordering::SeqCst);

    unlock_scheduler();
}

pub fn schedule() {
    if !SCHEDULER_INIT.load(Ordering::Relaxed) {
        return;
    }

    lock_scheduler();

    let current = CURRENT_TASK.load(Ordering::Relaxed) as usize;
    let now = crate::sys::timer::rdtsc();

    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].state == TaskState::Sleeping && TASKS[i].sleep_until <= now {
                TASKS[i].state = TaskState::Ready;
            }
        }
    }

    let policy = SchedulerPolicy::from_u8(SCHEDULER_POLICY.load(Ordering::Relaxed));
    let next = match policy {
        SchedulerPolicy::RoundRobin => find_next_round_robin(current),
        SchedulerPolicy::Priority => find_next_priority(current),
        SchedulerPolicy::Fair => find_next_fair(current),
    };

    let (next, found) = match next {
        Some(n) => (n, true),
        None => (current, false),
    };

    if !found {
        unsafe {
            if current < MAX_TASKS && TASKS[current].state == TaskState::Running {
                unlock_scheduler();
                return;
            }
        }
        unlock_scheduler();
        return;
    }

    if next != current {
        perform_context_switch(current, next);
    } else {
        unlock_scheduler();
    }
}

pub fn yield_now() {
    schedule();
}
