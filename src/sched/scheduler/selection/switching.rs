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
use super::super::preemption::{CURRENT_TIME_SLICE, DEFAULT_TIME_SLICE};

pub fn switch_to_process(pid: u32) {
    use crate::process::nonos_core::{PROCESS_TABLE, ProcessState, CURRENT_PID};
    use crate::memory::paging::manager::api::switch_to_process_address_space;
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        *pcb.state.lock() = ProcessState::Running;
    }
    CURRENT_PID.store(pid, Ordering::SeqCst);
    CURRENT_TIME_SLICE.store(DEFAULT_TIME_SLICE, Ordering::Relaxed);
    let _ = switch_to_process_address_space(pid);
    let ctx_opt = crate::process::nonos_core::INTERRUPT_SAVED_CONTEXTS.write().remove(&pid);
    match ctx_opt {
        Some(ctx) => ctx.restore(),
        None => handle_missing_context(pid),
    }
}

fn handle_missing_context(pid: u32) -> ! {
    crate::sys::serial::print(b"[SCHED] FATAL: No context for PID ");
    crate::sys::serial::print_u64(pid as u64);
    crate::sys::serial::println(b"");
    crate::sys::boot_log::error("SCHED:NO_CTX");
    loop { core::hint::spin_loop(); }
}
