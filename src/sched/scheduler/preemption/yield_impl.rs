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
    use crate::sys::serial;
    SCHEDULER_STATS.voluntary_yields.fetch_add(1, Ordering::Relaxed);
    let curr = current_pid();
    if curr.is_none() {
        serial::println(b"[YIELD] No current pid");
        return;
    }
    let pid = curr.unwrap();
    serial::print(b"[YIELD] pid=");
    serial::print_dec(pid as u64);
    serial::println(b" saving ctx");
    let mut ctx: crate::sched::Context = unsafe { core::mem::zeroed() };
    unsafe { crate::sched::Context::save_to(&mut ctx as *mut crate::sched::Context) };
    if crate::sched::Context::was_just_restored() {
        serial::print(b"[YIELD] pid=");
        serial::print_dec(pid as u64);
        serial::println(b" restored, returning");
        return;
    }
    serial::print(b"[YIELD] pid=");
    serial::print_dec(pid as u64);
    serial::print(b" rip=0x");
    serial::print_hex(ctx.rip);
    serial::print(b" rsp=0x");
    serial::print_hex(ctx.rsp);
    serial::println(b"");
    crate::process::nonos_core::save_interrupt_context(pid, ctx);
    crate::process::nonos_core::save_fpu_state(pid);
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        let mut state = pcb.state.lock();
        if *state == ProcessState::Running { *state = ProcessState::Ready; }
    }
    crate::sched::add_to_run_queue(pid);
    CURRENT_TIME_SLICE.store(0, Ordering::Relaxed);
    let next_opt = select_next_process();
    serial::print(b"[YIELD] selected=");
    if let Some(n) = next_opt { serial::print_dec(n as u64); } else { serial::print(b"None"); }
    serial::println(b"");
    if let Some(next) = next_opt {
        if next != pid {
            serial::print(b"[YIELD] switching ");
            serial::print_dec(pid as u64);
            serial::print(b" -> ");
            serial::print_dec(next as u64);
            serial::println(b"");
            switch_to_process(next);
        }
    }
}
