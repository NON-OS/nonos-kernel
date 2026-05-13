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

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::memory::paging::manager::api::switch_to_process_address_space;
use crate::process::core::{ProcessControlBlock, ProcessState, CURRENT_PID};
use crate::process::nonos_core::{
    has_saved_fpu_state, init_fpu, restore_fpu_state, INTERRUPT_SAVED_CONTEXTS,
};
use crate::process::scheduler::preemption::{CURRENT_TIME_SLICE, DEFAULT_TIME_SLICE};

// CPL=0 resume path. Used when the PCB has no pending user-entry and
// no saved user context — typically a kernel thread whose CpuContext
// was parked in INTERRUPT_SAVED_CONTEXTS by the preempt/yield path.
// Returns control to that context via CpuContext::restore.
pub(super) fn resume_kernel_thread(pcb: &Arc<ProcessControlBlock>, pid: u32) {
    let ctx = match INTERRUPT_SAVED_CONTEXTS.write().remove(&pid) {
        Some(c) => c,
        None => {
            *pcb.state.lock() = ProcessState::Ready;
            return;
        }
    };

    let has_own_addr_space = pcb.cr3.load(Ordering::Relaxed) != 0;
    *pcb.state.lock() = ProcessState::Running;
    CURRENT_PID.store(pid, Ordering::SeqCst);
    CURRENT_TIME_SLICE.store(DEFAULT_TIME_SLICE, Ordering::SeqCst);

    if has_own_addr_space {
        let _ = switch_to_process_address_space(pid);
    }

    if has_saved_fpu_state(pid) {
        restore_fpu_state(pid);
    } else {
        init_fpu();
    }

    ctx.restore()
}
