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

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use x86_64::VirtAddr;
use super::types::{PROCESS_TABLE, CURRENT_PID, NEXT_PID};
use super::super::types::{Pid, ProcessState, Priority, MemoryState};
use super::super::pcb::ProcessControlBlock;
use crate::process::process_fd_table::ProcessFdTable;

pub fn create_process(name: &str, state: ProcessState, prio: Priority) -> Result<Pid, &'static str> {
    create_process_with_mem(name, state, prio, 0)
}

pub fn create_process_with_mem(name: &str, state: ProcessState, prio: Priority, mem_kb: u64) -> Result<Pid, &'static str> {
    if name.is_empty() { return Err("empty name"); }
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let parent_pid = CURRENT_PID.load(Ordering::Relaxed);
    let pcb = build_pcb(pid, parent_pid, name, state, prio, mem_kb / 4);
    PROCESS_TABLE.add(pcb);
    Ok(pid)
}

fn build_pcb(pid: Pid, parent_pid: Pid, name: &str, state: ProcessState, prio: Priority, pages: u64) -> Arc<ProcessControlBlock> {
    Arc::new(ProcessControlBlock {
        pid, tgid: AtomicU32::new(pid), ppid: AtomicU32::new(parent_pid),
        pgid: AtomicU32::new(pid), sid: AtomicU32::new(pid),
        name: spin::Mutex::new(String::from(name)), state: spin::Mutex::new(state), priority: spin::Mutex::new(prio),
        memory: spin::Mutex::new(MemoryState {
            code_start: VirtAddr::new(0), code_end: VirtAddr::new(0),
            vmas: Vec::new(), resident_pages: AtomicU64::new(pages), next_va: 0x0000_4000_0000,
        }),
        thread_group: None, argv: spin::Mutex::new(Vec::new()), envp: spin::Mutex::new(Vec::new()),
        caps_bits: AtomicU64::new(u64::MAX), exit_code: core::sync::atomic::AtomicI32::new(0),
        zk_proofs_generated: AtomicU64::new(0), zk_proving_time_ms: AtomicU64::new(0),
        zk_proofs_verified: AtomicU64::new(0), zk_verification_time_ms: AtomicU64::new(0),
        zk_circuits_compiled: AtomicU64::new(0), umask: spin::Mutex::new(0o022),
        root_dir: spin::Mutex::new(String::from("/")), clear_child_tid: AtomicU64::new(0), set_child_tid: AtomicU64::new(0),
        alarm_time_ms: AtomicU64::new(0), tls_base: AtomicU64::new(0), stack_base: AtomicU64::new(0), clone_flags: AtomicU64::new(0),
        start_time_ms: AtomicU64::new(crate::time::timestamp_millis()), fd_table: ProcessFdTable::new(),
    })
}
