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

// Process-subsystem bring-up. Initializes the process table and
// related kernel state only. Userspace `init` is created exactly
// once in `microkernel_main`; creating it here too would be a
// duplicate and would also force address-space allocation before
// the paging manager is wired up.

use super::pcb::ProcessControlBlock;
use super::table::{CURRENT_PID, PROCESS_TABLE};
use core::sync::atomic::Ordering;

pub(crate) fn init_system_processes() {
    // The process table is a static; touching it here makes the
    // subsystem warm and lets us assert basic invariants before
    // any creator runs. CURRENT_PID stays 0 until microkernel_main
    // installs init.
    debug_assert_eq!(CURRENT_PID.load(Ordering::Acquire), 0);
    let _ = PROCESS_TABLE.get_all_processes();
}

pub fn get_init_process() -> Option<alloc::sync::Arc<ProcessControlBlock>> {
    PROCESS_TABLE.find_by_pid(1)
}

pub fn reparent_orphans(dead_pid: u32) {
    for child in PROCESS_TABLE.get_children_of(dead_pid) {
        child.ppid.store(1, Ordering::Release);
    }
}
