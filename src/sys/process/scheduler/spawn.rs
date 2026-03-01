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
use core::alloc::Layout;
use super::state::{
    TASKS, CURRENT_TASK, NEXT_TASK_ID, TASK_COUNT, SCHEDULER_INIT,
    lock_scheduler, unlock_scheduler
};
use super::context::task_trampoline;
use super::core::schedule;
use super::super::{TaskState, CpuContext, MAX_TASKS, TASK_STACK_SIZE};

extern crate alloc;

pub fn spawn(entry_point: fn(), name: &[u8]) -> Option<u32> {
    if !SCHEDULER_INIT.load(Ordering::Relaxed) {
        return None;
    }

    lock_scheduler();

    let slot = unsafe {
        let mut found = None;
        for i in 1..MAX_TASKS {
            if TASKS[i].state == TaskState::Empty {
                found = Some(i);
                break;
            }
        }
        found
    };

    let slot = match slot {
        Some(s) => s,
        None => {
            unlock_scheduler();
            return None;
        }
    };

    let layout = Layout::from_size_align(TASK_STACK_SIZE, 16).ok()?;
    let stack = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if stack.is_null() {
        unlock_scheduler();
        return None;
    }

    let stack_base = stack as u64;
    let stack_top = stack_base + TASK_STACK_SIZE as u64;

    let initial_rsp = stack_top - 16;

    unsafe {
        let stack_ptr = initial_rsp as *mut u64;
        *stack_ptr = task_exit_wrapper as *const () as u64;
        *stack_ptr.add(1) = entry_point as *const () as u64;
    }

    let task_id = NEXT_TASK_ID.fetch_add(1, Ordering::SeqCst);

    unsafe {
        TASKS[slot].id = task_id;
        TASKS[slot].state = TaskState::Ready;
        TASKS[slot].set_name(name);
        TASKS[slot].priority = 128;
        TASKS[slot].stack_base = stack_base;
        TASKS[slot].stack_size = TASK_STACK_SIZE;
        TASKS[slot].parent_id = CURRENT_TASK.load(Ordering::Relaxed);
        TASKS[slot].exit_code = 0;

        TASKS[slot].context = CpuContext {
            rbx: 0,
            rbp: stack_top,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: initial_rsp,
            rip: task_trampoline as *const () as u64,
            rflags: 0x202,
        };
    }

    TASK_COUNT.fetch_add(1, Ordering::SeqCst);
    unlock_scheduler();

    Some(task_id)
}

fn task_exit_wrapper() {
    exit(0);
}

pub fn exit(code: i32) -> ! {
    lock_scheduler();

    let current = CURRENT_TASK.load(Ordering::Relaxed) as usize;

    unsafe {
        if current < MAX_TASKS {
            TASKS[current].state = TaskState::Terminated;
            TASKS[current].exit_code = code;

            if TASKS[current].stack_base != 0 {
                if let Ok(layout) = Layout::from_size_align(TASK_STACK_SIZE, 16) {
                    alloc::alloc::dealloc(TASKS[current].stack_base as *mut u8, layout);
                }
                TASKS[current].stack_base = 0;
            }

            TASK_COUNT.fetch_sub(1, Ordering::SeqCst);
        }
    }

    unlock_scheduler();

    schedule();

    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

pub fn sleep_ms(ms: u64) {
    let current = CURRENT_TASK.load(Ordering::Relaxed) as usize;

    let tsc_freq = crate::sys::timer::tsc_frequency();
    let tsc_now = crate::sys::timer::rdtsc();
    let sleep_ticks = (tsc_freq * ms) / 1000;
    let wake_time = tsc_now + sleep_ticks;

    lock_scheduler();
    unsafe {
        if current < MAX_TASKS {
            TASKS[current].state = TaskState::Sleeping;
            TASKS[current].sleep_until = wake_time;
        }
    }
    unlock_scheduler();

    schedule();
}
