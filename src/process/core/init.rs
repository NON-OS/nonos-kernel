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

use super::table::types::{PROCESS_TABLE, CURRENT_PID};
use super::types::{ProcessState, Priority};
use super::table::create_process;
use core::sync::atomic::Ordering;

pub(crate) fn init_system_processes() {
    match create_process("init", ProcessState::Ready, Priority::Normal) {
        Ok(pid) => {
            CURRENT_PID.store(pid, Ordering::SeqCst);
            crate::log::info!("[PROCESS] Init process created with PID {}", pid);
        }
        Err(e) => crate::log::error!("[PROCESS] Failed to create init: {}", e),
    }
    let _ = create_process("kthreadd", ProcessState::Ready, Priority::High);
    let _ = create_process("ksoftirqd", ProcessState::Ready, Priority::High);
}

pub fn get_init_process() -> Option<alloc::sync::Arc<super::pcb::ProcessControlBlock>> {
    PROCESS_TABLE.find_by_pid(1)
}

pub fn reparent_orphans(dead_pid: u32) {
    for child in PROCESS_TABLE.get_children_of(dead_pid) {
        child.ppid.store(1, Ordering::Release);
    }
}
