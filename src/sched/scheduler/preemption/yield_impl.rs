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
use crate::arch::x86_64::idt::without_interrupts;

pub fn yield_now() {
    use crate::process::nonos_core::{current_pid, PROCESS_TABLE, ProcessState};
    SCHEDULER_STATS.voluntary_yields.fetch_add(1, Ordering::Relaxed);
    let Some(pid) = current_pid() else { return };
    let (ctx, was_restored) = without_interrupts(|| {
        let mut c: crate::sched::Context = unsafe { core::mem::zeroed() };
        unsafe { crate::sched::Context::save_to(&mut c as *mut crate::sched::Context) };
        let restored = crate::sched::Context::was_just_restored();
        (c, restored)
    });
    if was_restored { return; }
    crate::process::nonos_core::save_interrupt_context(pid, ctx);
    crate::process::nonos_core::save_fpu_state(pid);
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        let mut state = pcb.state.lock();
        if *state == ProcessState::Running { *state = ProcessState::Ready; }
    }
    crate::sched::add_to_run_queue(pid);
    CURRENT_TIME_SLICE.store(0, Ordering::Relaxed);
    match select_next_process() {
        Some(next) if next != pid => {
            crate::sys::serial::print(b"[YIELD] ");
            crate::sys::serial::print_dec(pid as u64);
            crate::sys::serial::print(b"->");
            crate::sys::serial::print_dec(next as u64);
            crate::sys::serial::println(b"");
            switch_to_process(next)
        }
        _ => {}
    }
}
