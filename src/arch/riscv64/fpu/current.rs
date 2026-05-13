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

use super::slot::FpSlot;

// FP slot of the user task currently running on this hart. Returns
// None at boot (CURRENT_PID == 0) and when no PCB matches CURRENT_PID,
// keeping the lazy-enable path fail-closed in both cases. UnsafeCell
// inside the PCB has stable address as long as PROCESS_TABLE retains
// the Arc; the local Arc returned by find_by_pid drops at return but
// the table's keeps the storage alive for the trap context.
pub fn slot_mut() -> Option<&'static mut FpSlot> {
    let pid = CURRENT_PID.load(Ordering::Acquire);
    if pid == 0 {
        return None;
    }
    let pcb = PROCESS_TABLE.find_by_pid(pid)?;
    let ptr = pcb.arch_fpu.slot_ptr();
    // SAFETY: PCB is Arc-pinned in PROCESS_TABLE; UnsafeCell address
    // is stable; single hart per task + SIE masked here.
    Some(unsafe { &mut *ptr })
}
