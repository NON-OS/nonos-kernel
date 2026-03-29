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

use core::sync::atomic::{AtomicU64, Ordering};
use super::state::{CURRENT_TIME_SLICE, SCHEDULER_STATS};
use super::super::selection::{select_next_process, switch_to_process};

pub fn yield_now() {
    use crate::process::nonos_core::{current_pid, PROCESS_TABLE, ProcessState};
    static YIELD_COUNT: AtomicU64 = AtomicU64::new(0);
    let count = YIELD_COUNT.fetch_add(1, Ordering::Relaxed);
    if count < 5 { crate::sys::serial::println(b"[YIELD] yield_now called"); }
    SCHEDULER_STATS.voluntary_yields.fetch_add(1, Ordering::Relaxed);
    if let Some(pid) = current_pid() {
        let ctx = crate::sched::Context::save();
        crate::process::nonos_core::save_interrupt_context(pid, ctx);
        if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
            let mut state = pcb.state.lock();
            if *state == ProcessState::Running { *state = ProcessState::Ready; }
        }
        crate::sched::add_to_run_queue(pid);
    }
    CURRENT_TIME_SLICE.store(0, Ordering::Relaxed);
    if let Some(next) = select_next_process() {
        if count < 5 {
            crate::sys::serial::print(b"[YIELD] Switching to ");
            crate::sys::serial::print_dec(next as u64);
            crate::sys::serial::println(b"");
        }
        switch_to_process(next);
    } else if count < 5 {
        crate::sys::serial::println(b"[YIELD] No process found");
    }
}
