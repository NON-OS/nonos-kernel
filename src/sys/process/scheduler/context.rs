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
use super::state::{TASKS, CURRENT_TASK, TIME_QUANTUM, CURRENT_SLICE_END, CONTEXT_SWITCHES, unlock_scheduler};
use super::super::{TaskState, CpuContext, MAX_TASKS};

pub(super) fn perform_context_switch(current: usize, next: usize) {
    let now = crate::sys::timer::rdtsc();
    let quantum = TIME_QUANTUM.load(Ordering::Relaxed);

    unsafe {
        if current < MAX_TASKS && TASKS[current].state == TaskState::Running {
            let slice_start = TASKS[current].last_scheduled;
            if slice_start > 0 {
                TASKS[current].run_time += now.saturating_sub(slice_start);
            }
            TASKS[current].state = TaskState::Ready;
        }

        TASKS[next].state = TaskState::Running;
        TASKS[next].last_scheduled = now;
        TASKS[next].switch_count += 1;
        CURRENT_TASK.store(next as u32, Ordering::SeqCst);

        CURRENT_SLICE_END.store(now + quantum, Ordering::Relaxed);
        CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);

        let old_ctx = &mut TASKS[current].context as *mut CpuContext;
        let new_ctx = &TASKS[next].context as *const CpuContext;

        unlock_scheduler();

        context_switch(old_ctx, new_ctx);
    }
}

#[unsafe(naked)]
unsafe extern "C" fn context_switch(_old_ctx: *mut CpuContext, _new_ctx: *const CpuContext) {
    core::arch::naked_asm!(
        "mov [rdi + 0x00], rbx",
        "mov [rdi + 0x08], rbp",
        "mov [rdi + 0x10], r12",
        "mov [rdi + 0x18], r13",
        "mov [rdi + 0x20], r14",
        "mov [rdi + 0x28], r15",
        "mov [rdi + 0x30], rsp",
        "mov rax, [rsp]",
        "mov [rdi + 0x38], rax",
        "pushfq",
        "pop rax",
        "mov [rdi + 0x40], rax",

        "mov rbx, [rsi + 0x00]",
        "mov rbp, [rsi + 0x08]",
        "mov r12, [rsi + 0x10]",
        "mov r13, [rsi + 0x18]",
        "mov r14, [rsi + 0x20]",
        "mov r15, [rsi + 0x28]",
        "mov rsp, [rsi + 0x30]",
        "mov rax, [rsi + 0x40]",
        "push rax",
        "popfq",
        "mov rax, [rsi + 0x38]",
        "jmp rax",
    );
}

#[unsafe(naked)]
pub(super) unsafe extern "C" fn task_trampoline() {
    core::arch::naked_asm!("ret");
}
