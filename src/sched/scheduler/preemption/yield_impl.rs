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
use super::state::{CURRENT_TIME_SLICE, SCHEDULER_STATS};
use super::super::selection::{select_next_process, switch_to_process};

pub fn yield_now() {
    use crate::process::nonos_core::{current_pid, PROCESS_TABLE, ProcessState};
    use crate::arch::x86_64::idt::without_interrupts;

    SCHEDULER_STATS.voluntary_yields.fetch_add(1, Ordering::Relaxed);
    let Some(pid) = current_pid() else { return };

    let mut ctx: crate::sched::Context = unsafe { core::mem::zeroed() };

    let just_restored = without_interrupts(|| {
        crate::sched::Context::clear_restored_flag();
        unsafe { crate::sched::Context::save_to(&mut ctx as *mut crate::sched::Context) };
        crate::sched::Context::was_just_restored()
    });

    if just_restored {
        return;
    }

    crate::process::nonos_core::save_interrupt_context(pid, ctx);
    crate::process::nonos_core::save_fpu_state(pid);

    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        *pcb.state.lock() = ProcessState::Ready;
    }

    crate::sched::add_to_run_queue(pid);
    CURRENT_TIME_SLICE.store(0, Ordering::Relaxed);

    if let Some(next) = select_next_process() {
        if next != pid {
            switch_to_process(next);
        }
    }
}
