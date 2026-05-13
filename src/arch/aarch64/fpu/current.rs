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

use crate::process::core::{CURRENT_PID, PROCESS_TABLE};

use super::slot::FpSimdSlot;

// Returns the FP slot of the user task currently running on this CPU.
// Path: CURRENT_PID -> PCB::arch_fpu (UnsafeCell<FpSimdSlot>) -> raw
// pointer. The Arc returned by find_by_pid drops at function exit, but
// PROCESS_TABLE retains an Arc to the same PCB, so the slot's address
// remains valid for the trap context that called this. Returns None
// before any user task is scheduled (CURRENT_PID == 0) — keeps the
// lazy-enable path fail-closed at boot.
pub fn slot_mut() -> Option<&'static mut FpSimdSlot> {
    let pid = CURRENT_PID.load(Ordering::Acquire);
    if pid == 0 {
        return None;
    }
    let pcb = PROCESS_TABLE.find_by_pid(pid)?;
    let ptr = pcb.arch_fpu.slot_ptr();
    // SAFETY: PCB is Arc-pinned in PROCESS_TABLE; the slot lives inside
    // a UnsafeCell whose address is stable; the task runs on exactly
    // one CPU at a time and traps are masked here, so this is the only
    // live reference.
    Some(unsafe { &mut *ptr })
}
