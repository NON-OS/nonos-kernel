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

use crate::arch::aarch64::context::enter::enter_user;
use crate::arch::aarch64::fpu;
use crate::process::core::{ProcessControlBlock, ProcessState, CURRENT_PID};
use crate::process::scheduler::preemption::{CURRENT_TIME_SLICE, DEFAULT_TIME_SLICE};

use super::address_space::swap_address_space;

// Returns true iff we consumed a pending user-entry record. On success
// the helper does not return; on validation failure we mark the PCB
// terminated and return true so the caller does not try resume too.
pub(super) fn try_first_entry(pcb: &Arc<ProcessControlBlock>, pid: u32) -> bool {
    let mut entry = match pcb.pending_user_entry.lock().take() {
        Some(e) => e,
        None => return false,
    };

    let kstack = pcb.kernel_stack_top.load(Ordering::Acquire);
    if kstack == 0 {
        *pcb.state.lock() = ProcessState::Terminated(-1);
        return true;
    }
    // Mirror PCB's kernel sp top into the entry record so the asm
    // helper sees one source of truth; refuse mismatch as defense.
    if entry.kernel_sp == 0 {
        entry.kernel_sp = kstack;
    } else if entry.kernel_sp != kstack {
        *pcb.state.lock() = ProcessState::Terminated(-1);
        return true;
    }

    if swap_address_space(pcb).is_err() {
        *pcb.state.lock() = ProcessState::Terminated(-1);
        return true;
    }

    *pcb.state.lock() = ProcessState::Running;
    CURRENT_PID.store(pid, Ordering::SeqCst);
    CURRENT_TIME_SLICE.store(DEFAULT_TIME_SLICE, Ordering::SeqCst);

    // FP slot belongs to the incoming task; restore if it has a saved
    // snapshot, otherwise leave FPEN trapping so the first FP op lazy-
    // enables. CURRENT_PID is set above so `fpu::current::slot_mut`
    // resolves to this PCB.
    fpu::prepare_incoming();

    // SAFETY: PCB fields validated above; enter_user diverges on success.
    if unsafe { enter_user(&entry) }.is_err() {
        *pcb.state.lock() = ProcessState::Terminated(-1);
    }
    true
}
