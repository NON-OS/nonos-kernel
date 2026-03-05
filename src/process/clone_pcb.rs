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

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

use super::core::{ProcessControlBlock, ProcessState, Priority, ThreadGroup, MemoryState};
use super::clone_flags::CLONE_PARENT;

pub(crate) fn create_thread_pcb(
    parent: &Arc<ProcessControlBlock>,
    tid: u32,
    name: &str,
    priority: Priority,
    caps: u64,
    tgid: u32,
    pgid: u32,
    sid: u32,
    flags: u64,
    stack: u64,
    tls: u64,
    child_tid_ptr: u64,
) -> Result<Arc<ProcessControlBlock>, i32> {
    let memory = {
        let parent_mem = parent.memory.lock();
        MemoryState {
            code_start: parent_mem.code_start,
            code_end: parent_mem.code_end,
            vmas: parent_mem.vmas.clone(),
            resident_pages: AtomicU64::new(parent_mem.resident_pages.load(Ordering::Relaxed)),
            next_va: parent_mem.next_va,
        }
    };

    let thread_group = parent.thread_group.clone().unwrap_or_else(|| {
        Arc::new(ThreadGroup::new(tgid))
    });

    let (argv, envp) = {
        let parent_argv = parent.argv.lock();
        let parent_envp = parent.envp.lock();
        (parent_argv.clone(), parent_envp.clone())
    };

    let (umask, root_dir) = {
        let parent_umask = *parent.umask.lock();
        let parent_root = parent.root_dir.lock().clone();
        (parent_umask, parent_root)
    };

    let pcb = Arc::new(ProcessControlBlock {
        pid: tid,
        tgid: AtomicU32::new(tgid),
        ppid: AtomicU32::new(parent.pid),
        pgid: AtomicU32::new(pgid),
        sid: AtomicU32::new(sid),
        name: spin::Mutex::new(String::from(name)),
        state: spin::Mutex::new(ProcessState::Ready),
        priority: spin::Mutex::new(priority),
        memory: spin::Mutex::new(memory),
        thread_group: Some(thread_group),
        argv: spin::Mutex::new(argv),
        envp: spin::Mutex::new(envp),
        caps_bits: AtomicU64::new(caps),
        exit_code: AtomicI32::new(0),
        zk_proofs_generated: AtomicU64::new(0),
        zk_proving_time_ms: AtomicU64::new(0),
        zk_proofs_verified: AtomicU64::new(0),
        zk_verification_time_ms: AtomicU64::new(0),
        zk_circuits_compiled: AtomicU64::new(0),
        umask: spin::Mutex::new(umask),
        root_dir: spin::Mutex::new(root_dir),
        clear_child_tid: AtomicU64::new(0),
        set_child_tid: AtomicU64::new(child_tid_ptr),
        alarm_time_ms: AtomicU64::new(0),
        tls_base: AtomicU64::new(tls),
        stack_base: AtomicU64::new(stack),
        clone_flags: AtomicU64::new(flags),
        start_time_ms: AtomicU64::new(crate::time::timestamp_millis()),
    });

    Ok(pcb)
}

pub(crate) fn create_process_pcb(
    parent: &Arc<ProcessControlBlock>,
    pid: u32,
    name: &str,
    priority: Priority,
    caps: u64,
    pgid: u32,
    sid: u32,
    flags: u64,
) -> Result<Arc<ProcessControlBlock>, i32> {
    let memory = {
        let parent_mem = parent.memory.lock();
        MemoryState {
            code_start: parent_mem.code_start,
            code_end: parent_mem.code_end,
            vmas: parent_mem.vmas.clone(),
            resident_pages: AtomicU64::new(parent_mem.resident_pages.load(Ordering::Relaxed)),
            next_va: parent_mem.next_va,
        }
    };

    let (argv, envp) = {
        let parent_argv = parent.argv.lock();
        let parent_envp = parent.envp.lock();
        (parent_argv.clone(), parent_envp.clone())
    };

    let (umask, root_dir) = {
        let parent_umask = *parent.umask.lock();
        let parent_root = parent.root_dir.lock().clone();
        (parent_umask, parent_root)
    };

    let pcb = Arc::new(ProcessControlBlock {
        pid,
        tgid: AtomicU32::new(pid),
        ppid: AtomicU32::new(parent.pid),
        pgid: AtomicU32::new(if (flags & CLONE_PARENT) != 0 { pgid } else { pid }),
        sid: AtomicU32::new(sid),
        name: spin::Mutex::new(String::from(name)),
        state: spin::Mutex::new(ProcessState::Ready),
        priority: spin::Mutex::new(priority),
        memory: spin::Mutex::new(memory),
        thread_group: None,
        argv: spin::Mutex::new(argv),
        envp: spin::Mutex::new(envp),
        caps_bits: AtomicU64::new(caps),
        exit_code: AtomicI32::new(0),
        zk_proofs_generated: AtomicU64::new(0),
        zk_proving_time_ms: AtomicU64::new(0),
        zk_proofs_verified: AtomicU64::new(0),
        zk_verification_time_ms: AtomicU64::new(0),
        zk_circuits_compiled: AtomicU64::new(0),
        umask: spin::Mutex::new(umask),
        root_dir: spin::Mutex::new(root_dir),
        clear_child_tid: AtomicU64::new(0),
        set_child_tid: AtomicU64::new(0),
        alarm_time_ms: AtomicU64::new(0),
        tls_base: AtomicU64::new(0),
        stack_base: AtomicU64::new(0),
        clone_flags: AtomicU64::new(flags),
        start_time_ms: AtomicU64::new(crate::time::timestamp_millis()),
    });

    Ok(pcb)
}
