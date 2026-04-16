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
    use crate::process::nonos_core::{restore_fpu_state, has_saved_fpu_state, init_fpu};
    use crate::memory::paging::manager::api::switch_to_process_address_space;
    let ctx_opt = crate::process::nonos_core::INTERRUPT_SAVED_CONTEXTS.write().remove(&pid);
    let Some(ctx) = ctx_opt else {
        if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) { *pcb.state.lock() = ProcessState::Ready; }
        crate::sched::yield_now();
        return;
    };
    let has_own_addr_space = if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        let owns_space = pcb.cr3.load(Ordering::Relaxed) != 0;
        *pcb.state.lock() = ProcessState::Running;
        owns_space
    } else {
        crate::sched::yield_now();
        return;
    };
    CURRENT_PID.store(pid, Ordering::SeqCst);
    CURRENT_TIME_SLICE.store(DEFAULT_TIME_SLICE, Ordering::SeqCst);
    if has_own_addr_space { let _ = switch_to_process_address_space(pid); }
    if !has_saved_fpu_state(pid) { init_fpu(); } else { restore_fpu_state(pid); }
    ctx.restore()
}
