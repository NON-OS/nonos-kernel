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

use super::table::create_process;
use super::table::{CURRENT_PID, PROCESS_TABLE};
use super::types::{Priority, ProcessState};
use core::sync::atomic::Ordering;

pub(crate) fn init_system_processes() {
    let pid = match create_process("init", ProcessState::Ready, Priority::Normal) {
        Ok(p) => p,
        Err(e) => {
            crate::sys::serial::println(b"[FATAL] Failed to create init process");
            crate::sys::serial::println(e.as_bytes());
            crate::arch::x86_64::boot::cpu_ops::halt_loop()
        }
    };
    CURRENT_PID.store(pid, Ordering::SeqCst);
    crate::log::info!("[PROCESS] Init process created with PID {}", pid);
    if let Err(e) = create_process("kthreadd", ProcessState::Ready, Priority::High) {
        crate::log::warn!("[PROCESS] Failed to create kthreadd: {}", e);
    }
    if let Err(e) = create_process("ksoftirqd", ProcessState::Ready, Priority::High) {
        crate::log::warn!("[PROCESS] Failed to create ksoftirqd: {}", e);
    }
}

pub fn get_init_process() -> Option<alloc::sync::Arc<super::pcb::ProcessControlBlock>> {
    PROCESS_TABLE.find_by_pid(1)
}

pub fn reparent_orphans(dead_pid: u32) {
    for child in PROCESS_TABLE.get_children_of(dead_pid) {
        child.ppid.store(1, Ordering::Release);
    }
}
