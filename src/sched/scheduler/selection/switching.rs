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
    use crate::process::nonos_core::{PROCESS_TABLE, ProcessState, CURRENT_PID, restore_fpu_state, has_saved_fpu_state, init_fpu};
    use crate::memory::paging::manager::api::switch_to_process_address_space;
    crate::sys::serial::print(b"[SWITCH] to PID ");
    crate::sys::serial::print_dec(pid as u64);
    crate::sys::serial::println(b"");
    let ctx_opt = crate::process::nonos_core::INTERRUPT_SAVED_CONTEXTS.write().remove(&pid);
    if ctx_opt.is_none() {
        crate::sys::serial::println(b"[SWITCH] No context!");
        if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
            *pcb.state.lock() = ProcessState::Ready;
        }
        crate::sched::yield_now();
        return;
    }
    crate::sys::serial::println(b"[SWITCH] Context found");
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        *pcb.state.lock() = ProcessState::Running;
    }
    CURRENT_PID.store(pid, Ordering::SeqCst);
    CURRENT_TIME_SLICE.store(DEFAULT_TIME_SLICE, Ordering::SeqCst);
    if pid > 64 {
        crate::sys::serial::println(b"[SWITCH] Switching address space");
        let _ = switch_to_process_address_space(pid);
    }
    if !has_saved_fpu_state(pid) {
        init_fpu();
    } else {
        restore_fpu_state(pid);
    }
    crate::sys::serial::println(b"[SWITCH] Restoring context");
    if let Some(ctx) = ctx_opt {
        crate::sys::serial::print(b"[SWITCH] rip=0x");
        crate::sys::serial::print_hex(ctx.rip);
        crate::sys::serial::print(b" rsp=0x");
        crate::sys::serial::print_hex(ctx.rsp);
        crate::sys::serial::println(b"");
        ctx.restore();
    }
    loop { core::hint::spin_loop(); }
}
